// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

import { createHash } from "node:crypto";
import { pinnedRosterFor } from "./gateway-client.js";
import { printable } from "./printable.js";
import { chainIdFor, verifyMlDsa65, ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES } from "./pq-schemes.js";

export const ATTEST_CONTEXT = "QORUS-ATTEST-CERT";
export const COMMITTEE_BUDGET = 500n;
export const MIN_SELF_STAKE = 2000n;
export const MAX_ACTIVE_VALIDATORS = 100;
export const DRAW_FULL = 2;

const U64_MAX = (1n << 64n) - 1n;
const MAX_SLOTS = 1n << 16n;
const STAGE_ONE = 1;
const MAX_ATTESTATIONS = 4096n;
const MAX_REVEALS = 4096n;
const MAX_SIBLINGS = 64n;
const MAX_ROSTER = 4096;
const MAX_PROPOSER = 128;
const MAX_EXTRA = 32;
const DIGEST = 32;

const COMMITTEE_DOMAIN = Buffer.from("QORUS-ATTEST-COMMITTEE");
const DRAW_DOMAIN = Buffer.from("QORUS-ATTEST-DRAW");
const ROTATION_DOMAIN = Buffer.from("QORUS/leader/rotation/v1");
const FULL_BEACON_DOMAIN = Buffer.from("QORUS/beacon/full-committee/v1");
const LEAF_DOMAIN = Buffer.from("QORUS/onetime/leaf");
const NODE_DOMAIN = Buffer.from("QORUS/onetime/node");
const ROOT_DOMAIN = Buffer.from("QORUS/onetime/root");

export function sha3(bytes) {
  return createHash("sha3-256").update(bytes).digest();
}

export function shake256(bytes, length = DIGEST) {
  return createHash("shake256", { outputLength: length }).update(bytes).digest();
}

export function u64le(value) {
  const out = Buffer.alloc(8);
  out.writeBigUInt64LE(BigInt(value));
  return out;
}

export function hexBytes(text, what, length) {
  if (typeof text !== "string" || !/^([0-9a-f]{2})*$/.test(text)) throw new Error(`${what} is not lowercase hex`);
  const bytes = Buffer.from(text, "hex");
  if (length !== undefined && bytes.length !== length) throw new Error(`${what} is ${bytes.length} bytes, not ${length}`);
  return bytes;
}

function wholeNumber(raw, what, max = U64_MAX) {
  let n = null;
  if (typeof raw === "number" && Number.isSafeInteger(raw) && raw >= 0) n = BigInt(raw);
  else if (typeof raw === "string" && raw.length <= 20 && /^(0|[1-9]\d*)$/.test(raw)) n = BigInt(raw);
  if (n === null || n > max) throw new Error(`${what} ${printable(JSON.stringify(raw), 40)} is not a whole number in range`);
  return n;
}

class Reader {
  constructor(bytes, what) {
    this.bytes = bytes;
    this.at = 0;
    this.what = what;
  }

  take(n) {
    if (n > this.bytes.length - this.at) throw new Error(`the ${this.what} ends early`);
    const out = this.bytes.subarray(this.at, this.at + n);
    this.at += n;
    return out;
  }

  u8() {
    return this.take(1)[0];
  }

  u64() {
    return this.take(8).readBigUInt64LE(0);
  }

  bytesField(max) {
    const n = this.u64();
    if (n > BigInt(this.bytes.length - this.at) || (max !== undefined && n > BigInt(max))) {
      throw new Error(`a field of the ${this.what} has a length out of bounds`);
    }
    return this.take(Number(n));
  }

  fixed(n) {
    const out = this.bytesField(n);
    if (out.length !== n) throw new Error(`a field of the ${this.what} is ${out.length} bytes, not ${n}`);
    return out;
  }

  finish() {
    if (this.at !== this.bytes.length) throw new Error(`the ${this.what} carries ${this.bytes.length - this.at} bytes after its last field`);
  }
}

export function decodeHeader(bytes) {
  const r = new Reader(bytes, "header");
  const height = r.u64();
  const parentHash = Buffer.from(r.take(DIGEST));
  const qRoot = Buffer.from(r.take(DIGEST));
  const transactionRoot = Buffer.from(r.take(DIGEST));
  const eventRoot = Buffer.from(r.take(DIGEST));
  const beaconSeed = Buffer.from(r.take(DIGEST));
  const proposerBytes = r.bytesField(MAX_PROPOSER);
  let proposer;
  try {
    proposer = new TextDecoder("utf-8", { fatal: true }).decode(proposerBytes);
  } catch {
    throw new Error("the header proposer is not valid text");
  }
  const time = r.u64();
  const extraData = Buffer.from(r.bytesField(MAX_EXTRA));
  r.finish();
  return { height, parentHash, qRoot, transactionRoot, eventRoot, beaconSeed, proposer, time, extraData, hash: sha3(bytes) };
}

function decodeBlock(r) {
  const start = r.at;
  const height = r.u64();
  const val = Buffer.from(r.take(DIGEST));
  const parentTag = r.u8();
  const parent = Buffer.from(r.take(DIGEST));
  if (parentTag === 0 && !parent.equals(Buffer.alloc(DIGEST))) throw new Error("a genesis parent carries a value");
  if (parentTag !== 0 && parentTag !== 1) throw new Error(`a block names parent tag ${parentTag}`);
  const cost = r.u64();
  return { height, val, parentTag, parent, cost, bytes: Buffer.from(r.bytes.subarray(start, r.at)) };
}

function decodeCredential(r) {
  const position = r.u64();
  const preimage = Buffer.from(r.fixed(DIGEST));
  const count = r.u64();
  if (count > MAX_SIBLINGS) throw new Error("a membership path is longer than 64 steps");
  const siblings = [];
  for (let i = 0n; i < count; i += 1n) siblings.push(Buffer.from(r.fixed(DIGEST)));
  return { position, preimage, siblings };
}

function decodeAttestation(r) {
  const from = r.u64();
  const height = r.u64();
  const slot = r.u64();
  const view = r.u64();
  const committee = Buffer.from(r.fixed(DIGEST));
  const block = decodeBlock(r);
  const membership = decodeCredential(r);
  const sig = Buffer.from(r.fixed(ML_DSA_65_SIGNATURE_BYTES));
  return { from, height, slot, view, committee, block, membership, sig };
}

export function decodeCertificate(bytes) {
  const r = new Reader(bytes, "certificate");
  const envelope = { height: r.u64(), slot: r.u64(), block: decodeBlock(r), committee: Buffer.from(r.fixed(DIGEST)) };
  const stage = r.u8();
  if (stage !== STAGE_ONE) throw new Error(`the certificate names stage ${stage}, not ${STAGE_ONE}`);
  const count = r.u64();
  if (count > MAX_ATTESTATIONS) throw new Error("the certificate carries too many attestations");
  const attestations = [];
  for (let i = 0n; i < count; i += 1n) attestations.push(decodeAttestation(r));
  const revealCount = r.u64();
  if (revealCount > MAX_REVEALS) throw new Error("the certificate carries too many committee reveals");
  const reveals = [];
  for (let i = 0n; i < revealCount; i += 1n) reveals.push({ id: r.u64(), credential: decodeCredential(r) });
  r.finish();
  return { envelope, attestations, reveals };
}

export function parseRoster(members, where = "the pinned roster") {
  if (!Array.isArray(members) || members.length === 0 || members.length > MAX_ROSTER) {
    throw new Error(`${where} carries no validators or too many`);
  }
  const seen = new Set();
  const roster = members.map((m) => {
    const id = wholeNumber(m?.id, `a validator id in ${where}`);
    if (seen.has(id)) throw new Error(`${where} names validator ${id} twice`);
    seen.add(id);
    const slots = wholeNumber(m?.root_slots, `the root slot count of validator ${id} in ${where}`, MAX_SLOTS);
    if (slots === 0n) throw new Error(`validator ${id} in ${where} commits to no slots`);
    return {
      id,
      stake: wholeNumber(m?.stake, `the stake of validator ${id} in ${where}`),
      bondAddress: typeof m?.bond_address === "string" ? m.bond_address : "",
      attestPk: hexBytes(typeof m?.attest_pk === "string" ? m.attest_pk.toLowerCase() : m?.attest_pk, `the attest key of validator ${id} in ${where}`, ML_DSA_65_PUBLIC_KEY_BYTES),
      root: hexBytes(typeof m?.root === "string" ? m.root.toLowerCase() : m?.root, `the sortition root of validator ${id} in ${where}`, DIGEST),
      slots,
    };
  });
  return roster.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

export function sameRoster(pinned, served) {
  if (pinned.length !== served.length) return `the pinned roster names ${pinned.length} validators and the gateway serves ${served.length}`;
  for (let i = 0; i < pinned.length; i += 1) {
    const a = pinned[i];
    const b = served[i];
    if (a.id !== b.id) return `the pinned roster names validator ${a.id} where the gateway serves validator ${b.id}`;
    if (a.stake !== b.stake) return `validator ${a.id} is pinned with stake ${a.stake} and served with stake ${b.stake}`;
    if (!a.attestPk.equals(b.attestPk)) return `validator ${a.id} is served with an attestation key other than the pinned one`;
    if (!a.root.equals(b.root) || a.slots !== b.slots) return `validator ${a.id} is served with a sortition root other than the pinned one`;
    if (a.bondAddress && a.bondAddress !== b.bondAddress) return `validator ${a.id} is pinned with bond address ${printable(a.bondAddress)} and served with ${printable(b.bondAddress)}`;
  }
  return null;
}

export function activeSet(roster) {
  let chosen = roster.filter((m) => m.stake >= MIN_SELF_STAKE);
  if (chosen.length > MAX_ACTIVE_VALIDATORS) {
    chosen = [...chosen]
      .sort((a, b) => (a.stake !== b.stake ? (b.stake > a.stake ? 1 : -1) : a.id < b.id ? -1 : 1))
      .slice(0, MAX_ACTIVE_VALIDATORS);
  }
  return chosen.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

function saturatingTotal(members) {
  const total = members.reduce((acc, m) => acc + m.stake, 0n);
  return total > U64_MAX ? U64_MAX : total;
}

export function committeeDigest(slot, active) {
  const parts = [COMMITTEE_DOMAIN, u64le(slot), u64le(COMMITTEE_BUDGET), u64le(saturatingTotal(active)), u64le(active.length)];
  for (const m of active) {
    parts.push(u64le(m.id), u64le(m.stake), u64le(m.stake), m.root, u64le(m.slots), m.attestPk);
  }
  parts.push(DRAW_DOMAIN, Buffer.from([DRAW_FULL]));
  return shake256(Buffer.concat(parts));
}

export function rotationLeader(epoch, slot, active) {
  const total = active.reduce((acc, m) => acc + m.stake, 0n);
  if (total === 0n) return null;
  const out = shake256(Buffer.concat([ROTATION_DOMAIN, u64le(epoch), u64le(slot)]), 16);
  let position = (out.readBigUInt64LE(8) << 64n) + out.readBigUInt64LE(0);
  position %= total;
  for (const m of active) {
    if (position < m.stake) return m;
    position -= m.stake;
  }
  return null;
}

export function leaderForView(active, leader, view) {
  const base = Math.max(0, active.findIndex((m) => m.id === leader.id));
  const offset = Number(BigInt(view) % BigInt(active.length));
  return active[(base + offset) % active.length];
}

export function nextBeacon(seed, slot) {
  return shake256(Buffer.concat([seed, FULL_BEACON_DOMAIN, u64le(slot)]));
}

function treeDepth(slots) {
  let padded = 1n;
  let depth = 0;
  while (padded < slots) {
    padded <<= 1n;
    depth += 1;
  }
  return depth;
}

export function opensAt(member, slot, credential) {
  if (credential.position !== slot || slot >= member.slots) return false;
  if (credential.siblings.length !== treeDepth(member.slots)) return false;
  let node = sha3(Buffer.concat([LEAF_DOMAIN, u64le(credential.position), credential.preimage]));
  let position = credential.position;
  for (const sibling of credential.siblings) {
    node = (position & 1n) === 0n ? sha3(Buffer.concat([NODE_DOMAIN, node, sibling])) : sha3(Buffer.concat([NODE_DOMAIN, sibling, node]));
    position >>= 1n;
  }
  const bound = sha3(Buffer.concat([ROOT_DOMAIN, u64le(member.id), u64le(member.slots), node]));
  return bound.equals(member.root);
}

export function attestationMessage(chainId, genesis, attestation) {
  return Buffer.concat([
    u64le(chainId),
    genesis,
    u64le(attestation.height),
    u64le(attestation.slot),
    u64le(attestation.view),
    attestation.committee,
    attestation.block.bytes,
  ]);
}

export function verifyFinality({ chainId, genesis, finality, roster: pinnedMembers }) {
  if (typeof chainId !== "bigint") throw new Error("no numeric chain id was given");
  if (!Buffer.isBuffer(genesis) || genesis.length !== DIGEST) throw new Error("no 32 byte genesis hash was given");
  if (!finality || typeof finality !== "object") throw new Error("get_finality returned nothing");
  if (String(finality.chain_id) !== String(chainId)) throw new Error(`the finality proof is for chain id ${printable(finality.chain_id)}, not ${chainId}`);

  const headerBytes = hexBytes(finality.header_bytes, "the header bytes");
  const header = decodeHeader(headerBytes);
  const height = wholeNumber(finality.height, "the finality height");
  if (header.height !== height) throw new Error(`the header is for height ${header.height}, not ${height}`);
  if (finality.header_hash !== undefined && finality.header_hash !== header.hash.toString("hex")) {
    throw new Error("the header hash the gateway reports is not the SHA3 256 of the header bytes");
  }

  const epoch = wholeNumber(finality.epoch, "the finality epoch");
  const roster = parseRoster(pinnedMembers);
  const slotCounts = new Set(roster.map((m) => m.slots));
  if (slotCounts.size !== 1) throw new Error("the validators of one epoch commit to different slot counts");
  const epochLength = roster[0].slots;
  if (height / epochLength !== epoch) throw new Error(`height ${height} is not in epoch ${epoch} of ${epochLength} heights`);
  const slot = height % epochLength;

  const cert = decodeCertificate(hexBytes(finality.certificate, "the certificate"));
  const env = cert.envelope;
  if (env.height !== height || env.block.height !== height) throw new Error("the certificate is for another height");
  if (env.slot !== slot) throw new Error(`the certificate names slot ${env.slot}, height ${height} is slot ${slot}`);
  if (!env.block.val.equals(header.hash)) throw new Error("the certificate does not name this header");
  if (env.block.cost !== 1n) throw new Error(`the certified block carries cost ${env.block.cost}, a proposal carries 1`);
  const genesisParent = header.parentHash.equals(Buffer.alloc(DIGEST));
  if (genesisParent ? env.block.parentTag !== 0 : env.block.parentTag !== 1 || !env.block.parent.equals(header.parentHash)) {
    throw new Error("the certificate names a parent other than the parent of this header");
  }

  const active = activeSet(roster);
  if (active.length === 0) throw new Error("no validator holds the minimum self stake");
  const digest = committeeDigest(slot, active);
  if (!env.committee.equals(digest)) throw new Error(`the certificate names a committee other than the ${active.length} active validators for slot ${slot}`);
  const byId = new Map(active.map((m) => [m.id, m]));

  const revealed = new Set();
  for (const reveal of cert.reveals) {
    if (revealed.has(reveal.id)) throw new Error(`validator ${reveal.id} is revealed twice`);
    revealed.add(reveal.id);
    const member = byId.get(reveal.id);
    if (!member) throw new Error(`a committee reveal comes from validator ${reveal.id}, who is not active`);
    if (!opensAt(member, slot, reveal.credential)) throw new Error(`the committee reveal of validator ${reveal.id} does not open its sortition root at slot ${slot}`);
  }

  if (cert.attestations.length === 0) throw new Error("the certificate carries no attestations");
  if (cert.attestations.length > active.length) throw new Error("the certificate carries more attestations than the committee has members");
  const view = cert.attestations[0].view;
  const signers = new Set();
  let signed = 0n;
  for (const att of cert.attestations) {
    if (att.view !== view) throw new Error("the attestations name different views");
    if (att.height !== env.height || att.slot !== env.slot || !att.block.bytes.equals(env.block.bytes)) {
      throw new Error(`the attestation of validator ${att.from} is for another block`);
    }
    if (!att.committee.equals(digest)) throw new Error(`the attestation of validator ${att.from} names another committee`);
    const member = byId.get(att.from);
    if (!member) throw new Error(`validator ${att.from} attests but is not on the committee`);
    if (!verifyMlDsa65(member.attestPk, attestationMessage(chainId, genesis, att), att.sig, ATTEST_CONTEXT)) {
      throw new Error(`the ML-DSA-65 attestation of validator ${att.from} does not verify for chain id ${chainId} and the pinned genesis`);
    }
    if (signers.has(att.from)) continue;
    if (member.stake === 0n || !opensAt(member, slot, att.membership)) {
      throw new Error(`the attestation of validator ${att.from} does not prove committee membership at slot ${slot}`);
    }
    signers.add(att.from);
    signed += member.stake;
  }
  const committeeStake = active.reduce((acc, m) => acc + m.stake, 0n);
  if (committeeStake === 0n || signed * 3n < committeeStake * 2n) {
    throw new Error(`the attesting validators hold ${signed} of ${committeeStake} committee stake, less than two thirds`);
  }

  return { height, epoch, slot, epochLength, header, view, active, signers, signed, committeeStake, reveals: cert.reveals.length };
}

export function proposerCandidates(verified) {
  const leader = rotationLeader(verified.epoch, verified.slot, verified.active);
  if (!leader) return [];
  const views = verified.view < BigInt(verified.active.length) ? Number(verified.view) : verified.active.length - 1;
  const out = [];
  for (let v = 0; v <= views; v += 1) out.push(leaderForView(verified.active, leader, v));
  return out;
}

export async function fetchVerifiedFinality(g, height) {
  const pin = await g.finalityPin();
  const chainId = chainIdFor(pin.chainName);
  const finality = await g.getFinality(String(height));
  const epoch = wholeNumber(finality?.epoch, "the finality epoch");
  const members = pinnedRosterFor(pin, epoch);
  const verified = verifyFinality({ chainId, genesis: Buffer.from(pin.genesisHash, "hex"), finality, roster: members });
  const { status, payload } = await g.raw("get_validator_set", { epoch: Number(epoch) });
  if (status === 200 && payload && !payload.error) {
    if (String(payload.chain_id) !== String(chainId) || String(payload.epoch) !== String(epoch)) {
      throw new Error(`the gateway serves a validator set for chain id ${printable(payload.chain_id)} epoch ${printable(payload.epoch)} when asked for chain id ${chainId} epoch ${epoch}`);
    }
    const differs = sameRoster(parseRoster(members), parseRoster(payload.members, "the served validator set"));
    if (differs) throw new Error(`the validator set the gateway serves for epoch ${epoch} is not the pinned roster, ${differs}`);
    verified.servedMatches = true;
  }
  return verified;
}

export async function fetchVerifiedFinalizedHead(g) {
  return fetchVerifiedFinality(g, await g.finalizedHeight());
}

export default {
  fetchVerifiedFinality,
  fetchVerifiedFinalizedHead,
  verifyFinality,
  proposerCandidates,
  sameRoster,
  decodeHeader,
  decodeCertificate,
  parseRoster,
  activeSet,
  committeeDigest,
  rotationLeader,
  leaderForView,
  nextBeacon,
  opensAt,
  attestationMessage,
};
