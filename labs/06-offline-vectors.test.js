// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, rmSync, statSync, symlinkSync, writeFileSync, readFileSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { decodeBech32m, encodeBech32m } from "../lib/bech32m.js";
import { LIVE_NETWORK, MAX_HEIGHT, parseHeight, readPinFile } from "../lib/gateway-client.js";
import { activeSet, committeeDigest, fetchVerifiedFinality, parseRoster, rotationLeader, sha3, shake256, u64le, verifyFinality } from "../lib/qorus.js";
import { chainIdFor, nativeMlDsaAvailable, verifyKeyRegistration } from "../lib/pq-schemes.js";

const VECTORS = JSON.parse(readFileSync(new URL("./vectors/offline-vectors.json", import.meta.url), "utf8"));
const GENESIS = Buffer.from(VECTORS.genesis_hash, "hex");
const CHAIN_ID = BigInt(VECTORS.chain_id);
const LAB_05 = fileURLToPath(new URL("./05-deterministic-finality.test.js", import.meta.url));

function certificateOf(entry) {
  if (entry.certificate) return entry.certificate;
  const base = Buffer.from(VECTORS.certificates.find((c) => c.roster === entry.base && c.certificate).certificate, "hex");
  return Buffer.concat([base.subarray(0, entry.at), Buffer.from(entry.insert, "hex"), base.subarray(entry.at + entry.remove)]).toString("hex");
}

function finalityOf(entry) {
  return { chain_id: VECTORS.chain_id, height: VECTORS.height, epoch: VECTORS.epoch, header_bytes: entry.header, certificate: certificateOf(entry) };
}

function verdictOf(entry, roster = VECTORS.rosters[entry.roster]) {
  try {
    verifyFinality({ chainId: CHAIN_ID, genesis: GENESIS, finality: finalityOf(entry), roster });
    return "accepted";
  } catch (err) {
    return `refused, ${err.message}`;
  }
}

test("the vectors are for the live network chain id, offline", () => {
  assert.equal(chainIdFor(LIVE_NETWORK), CHAIN_ID);
});

for (const entry of VECTORS.certificates) {
  test(`finality certificate vector "${entry.name}" is ${entry.accept ? "accepted" : "refused"} (${entry.verdict}), offline`, () => {
    assert.ok(nativeMlDsaAvailable(), "this Node build has no native ML-DSA-65, run the labs on Node 24 or later");
    const verdict = verdictOf(entry);
    if (entry.accept) assert.equal(verdict, "accepted");
    else assert.match(verdict, /^refused/, `this certificate must be refused, the lab accepted it`);
  });
}

test("a valid certificate is refused under another chain id, another genesis or another roster, offline", () => {
  const valid = VECTORS.certificates.find((c) => c.name === "valid");
  const finality = finalityOf(valid);
  const roster = VECTORS.rosters.four;
  assert.throws(() => verifyFinality({ chainId: CHAIN_ID + 1n, genesis: GENESIS, finality: { ...finality, chain_id: String(CHAIN_ID + 1n) }, roster }));
  assert.throws(() => verifyFinality({ chainId: CHAIN_ID, genesis: Buffer.alloc(32, 0x11), finality, roster }));
  assert.throws(() => verifyFinality({ chainId: CHAIN_ID, genesis: GENESIS, finality, roster: VECTORS.rosters.uneven }));
  assert.throws(() => verifyFinality({ chainId: CHAIN_ID, genesis: GENESIS, finality: { ...finality, epoch: VECTORS.epoch + 1 }, roster }));
  assert.throws(() => verifyFinality({ chainId: CHAIN_ID, genesis: GENESIS, finality: { ...finality, height: VECTORS.height + 1 }, roster }));
});

function committeeRoster() {
  return VECTORS.committee_roster.map((m) => ({
    id: m.id,
    stake: m.stake,
    attest_pk: shake256(Buffer.concat([Buffer.from("vector key"), u64le(m.id)]), 1952).toString("hex"),
    root: shake256(Buffer.concat([Buffer.from("vector root"), u64le(m.id)]), 32).toString("hex"),
    root_slots: "16",
  }));
}

test("the active set, its committee digest and the rotation leader match the consensus code for a roster above the active set cap, offline", () => {
  const active = activeSet(parseRoster(committeeRoster()));
  assert.equal(active.length, 100, "a roster with more eligible validators than the cap commits to the 100 with the most stake");
  for (const c of VECTORS.committees) {
    assert.equal(committeeDigest(BigInt(c.slot), active).toString("hex"), c.digest, `committee digest for slot ${c.slot}`);
    const leader = rotationLeader(BigInt(c.epoch), BigInt(c.slot), active);
    assert.equal(Number(leader.id), c.leader, `rotation leader for epoch ${c.epoch} slot ${c.slot}`);
  }
});

function stubGateway(entry, served) {
  return {
    finalityPin: async () => ({ file: "vectors", chainName: LIVE_NETWORK, genesisHash: VECTORS.genesis_hash, roster: VECTORS.rosters[entry.roster], epochs: new Map() }),
    getFinality: async (h) => ({ ...finalityOf(entry), height: Number(h) }),
    raw: async (method, body) => {
      assert.equal(method, "get_validator_set");
      return { status: 200, payload: { chain_id: VECTORS.chain_id, epoch: body.epoch, members: served } };
    },
  };
}

test("a served validator set that differs from the pin is refused, offline", async () => {
  const valid = VECTORS.certificates.find((c) => c.name === "valid");
  const pinned = VECTORS.rosters.four;
  const same = await fetchVerifiedFinality(stubGateway(valid, pinned), VECTORS.height);
  assert.equal(same.servedMatches, true);
  const changed = pinned.map((m, i) => (i === 0 ? { ...m, stake: String(BigInt(m.stake) + 1n) } : m));
  await assert.rejects(fetchVerifiedFinality(stubGateway(valid, changed), VECTORS.height), /is not the pinned roster/);
  await assert.rejects(fetchVerifiedFinality(stubGateway(valid, pinned.slice(1)), VECTORS.height), /is not the pinned roster/);
});

test("a pin file is read only when it is a regular file owned by this user and closed to writes by others, offline", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "pin-modes-"));
  try {
    const good = path.join(dir, "pin.json");
    writeFileSync(good, "{}", { mode: 0o600 });
    assert.equal(readPinFile(good), "{}");
    const loose = path.join(dir, "loose.json");
    writeFileSync(loose, "{}");
    chmodSync(loose, 0o666);
    assert.throws(() => readPinFile(loose), /writable by other users/);
    const group = path.join(dir, "group.json");
    writeFileSync(group, "{}");
    chmodSync(group, 0o620);
    assert.throws(() => readPinFile(group), /writable by other users/);
    const link = path.join(dir, "link.json");
    symlinkSync(good, link);
    assert.throws(() => readPinFile(link), /not a link/);
    const fifo = path.join(dir, "pin.fifo");
    execFileSync("mkfifo", ["-m", "600", fifo]);
    assert.throws(() => readPinFile(fifo), /not a regular file/);
    assert.throws(() => readPinFile(dir), /not a regular file/);
    const foreign = ["/etc/hosts", "/etc/passwd"].find((f) => existsSync(f) && statSync(f).uid !== process.getuid() && (statSync(f).mode & 0o022) === 0);
    if (foreign) assert.throws(() => readPinFile(foreign), /belongs to another user/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an SLH-DSA key registration signed by the chain cryptography verifies, and a changed byte does not, offline", () => {
  for (const { tx } of VECTORS.registrations) {
    const verdict = verifyKeyRegistration(tx, CHAIN_ID, GENESIS);
    assert.ok(verdict.ok, verdict.reason);
    assert.equal(verdict.scheme, 2);
    const flipped = tx.raw.slice(0, 200) + (tx.raw[200] === "0" ? "1" : "0") + tx.raw.slice(201);
    assert.equal(verifyKeyRegistration({ ...tx, raw: flipped }, CHAIN_ID, GENESIS).ok, false);
    assert.equal(verifyKeyRegistration(tx, CHAIN_ID, Buffer.alloc(32, 0x11)).ok, false);
  }
});

function serve(blocks) {
  const byHeight = new Map(blocks.map((b) => [b.height, b]));
  const top = Math.max(...blocks.map((b) => b.height));
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      let body = {};
      try {
        body = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
      } catch {
        body = {};
      }
      const send = (status, value) => {
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify(value));
      };
      const method = req.url.replace(/^\/v1\//, "");
      const block = byHeight.get(Number(body.height));
      switch (method) {
        case "node_info":
          return send(200, { chain_id: LIVE_NETWORK, genesis_hash: VECTORS.genesis_hash, head_height: top + 2 });
        case "head":
          return send(200, { height: top + 2 });
        case "finalized_head":
          return send(200, { head: top });
        case "get_finality":
          if (body.height === undefined) return send(400, { error: "bad_request", message: "get_finality needs a height" });
          if (!block) return send(404, { error: "not_found", message: "no finalized block" });
          return send(200, { height: block.height, epoch: block.epoch, chain_id: VECTORS.chain_id, header_bytes: block.header, header_hash: sha3(Buffer.from(block.header, "hex")).toString("hex"), certificate: block.certificate });
        case "get_block":
          if (!block) return send(404, { error: "not_found", message: "no block" });
          return send(200, { height: block.height, block: encodeBech32m("QBK", sha3(Buffer.from(block.header, "hex"))), proposer: block.proposer, tx_ids: [] });
        case "get_validator_set":
          return send(404, { error: "not_found", message: "only the current epoch" });
        default:
          return send(404, { error: "unknown_method", message: "unknown method" });
      }
    });
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

async function runLab05(blocks) {
  const dir = mkdtempSync(path.join(tmpdir(), "lab05-"));
  const pin = path.join(dir, "pin.json");
  writeFileSync(pin, JSON.stringify({ chain_id: LIVE_NETWORK, genesis_hash: VECTORS.genesis_hash, roster: VECTORS.rosters.four }), { mode: 0o600 });
  const server = await serve(blocks);
  try {
    const env = { PATH: process.env.PATH, HOME: process.env.HOME, QUANTOVA_GATEWAY_URL: `http://127.0.0.1:${server.address().port}`, QUANTOVA_FINALITY_FILE: pin, QUANTOVA_OFFLINE: "0" };
    const child = spawn(process.execPath, ["--test", "--test-reporter=tap", LAB_05], { env, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    child.stdout.on("data", (d) => {
      out += d;
    });
    child.stderr.on("data", (d) => {
      out += d;
    });
    await new Promise((resolve) => child.on("exit", resolve));
    const status = (name) => {
      const line = out.split("\n").find((l) => /^(not )?ok \d+ - /.test(l) && l.includes(name));
      return line ? (line.startsWith("ok") ? "ok" : "not ok") : "missing";
    };
    return { certified: status("carries a certificate"), linked: status("link by parent hash and beacon"), lag: status("finality lag stays bounded"), out };
  } finally {
    server.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

const chainBlock = (role) => VECTORS.chain.find((b) => b.role === role);

test("lab 05 passes against an honest recorded chain, offline", async () => {
  const r = await runLab05([chainBlock("parent"), chainBlock("child")]);
  assert.deepEqual([r.certified, r.linked, r.lag], ["ok", "ok", "ok"], r.out.slice(-1500));
});

test("lab 05 refuses a certified child whose beacon does not follow its parent, offline", async () => {
  const r = await runLab05([chainBlock("parent"), chainBlock("child with a broken beacon")]);
  assert.equal(r.linked, "not ok", r.out.slice(-1500));
});

test("lab 05 checks the certificate of every finalized height it samples for the lag, offline", async () => {
  const forged = VECTORS.certificates.find((c) => c.name === "another genesis");
  const r = await runLab05([chainBlock("parent"), { height: VECTORS.height, epoch: VECTORS.epoch, header: forged.header, certificate: certificateOf(forged), proposer: chainBlock("child").proposer }]);
  assert.equal(r.lag, "not ok", r.out.slice(-1500));
});

test("bech32m addresses decode only in their canonical form, offline", () => {
  for (const v of VECTORS.addresses) {
    const decoded = decodeBech32m(v.text, { hrp: "Q", length: 32 });
    assert.equal(Boolean(decoded), v.accept, `${v.text.slice(0, 24)} should ${v.accept ? "" : "not "}decode`);
  }
});

test("heights are whole numbers from 0 to 2^40 and nothing else, offline", () => {
  const accepted = [[0, 0], ["0", 0], [58, 58], ["58", 58], [MAX_HEIGHT, MAX_HEIGHT], [String(MAX_HEIGHT), MAX_HEIGHT]];
  for (const [raw, want] of accepted) assert.equal(parseHeight(raw), want);
  const refused = ["12abc", "012", "1e3", "-1", 1.5, -1, " 12", "12 ", "+12", "0x10", "\u{661}\u{662}", 2 ** 53 + 2, MAX_HEIGHT + 1, String(MAX_HEIGHT + 1), "00", true, null, [], {}, "9".repeat(17)];
  for (const raw of refused) assert.throws(() => parseHeight(raw), undefined, `height ${JSON.stringify(raw)} must be refused`);
});
