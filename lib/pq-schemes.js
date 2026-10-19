// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

import { createHash, createPublicKey, generateKeyPairSync, verify as verifySignature } from "node:crypto";
import { decodeBech32m } from "./bech32m.js";
import { printable } from "./printable.js";

export const PQ_SIGNATURE_SIZES = {
  "ML-DSA-44": 2420,
  "ML-DSA-65": 3309,
  "ML-DSA-87": 4627,
  "SLH-DSA-128s": 7856,
  "SLH-DSA-128f": 17088,
  "SLH-DSA-192s": 16224,
  "SLH-DSA-256s": 29792,
};

export const CLASSICAL_SIGNATURE_SIZES = {
  "ECDSA-secp256k1": 65,
  Ed25519: 64,
};

export const CLASSICAL_MAX_BYTES = 80;

export const PQ_MIN_BYTES = 2000;

export function byteLength(hex) {
  if (typeof hex !== "string") return 0;
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  return Math.floor(h.length / 2);
}

export function classifySignature(sigHex) {
  const bytes = byteLength(sigHex);
  const classical = bytes > 0 && bytes <= CLASSICAL_MAX_BYTES;
  const postQuantum = bytes >= PQ_MIN_BYTES;
  let nearest = null;
  let best = Infinity;
  for (const [name, size] of Object.entries(PQ_SIGNATURE_SIZES)) {
    const d = Math.abs(size - bytes);
    if (d < best) {
      best = d;
      nearest = name;
    }
  }
  return { bytes, classical, postQuantum, nearest };
}

export const SCHEME_ML_DSA_65 = 1;
export const SCHEME_SLH_DSA = 2;
export const ML_DSA_65_PUBLIC_KEY_BYTES = 1952;
export const ML_DSA_65_SIGNATURE_BYTES = 3309;
export const SLH_DSA_SIGNATURE_BYTES = 16224;
export const SLH_DSA_PUBLIC_KEY_BYTES = 48;
export const REGISTERED_KEY_BYTES = Object.freeze({ [SCHEME_ML_DSA_65]: ML_DSA_65_PUBLIC_KEY_BYTES, [SCHEME_SLH_DSA]: SLH_DSA_PUBLIC_KEY_BYTES });
export const CHAIN_SIGNATURE_BYTES = Object.freeze({ [SCHEME_ML_DSA_65]: ML_DSA_65_SIGNATURE_BYTES, [SCHEME_SLH_DSA]: SLH_DSA_SIGNATURE_BYTES });
export const KIND_TRANSFER = 0;
export const KEY_REGISTER_TARGET = createHash("sha3-256").update("qtv/key/register").digest();
export const TRANSACTION_CONTEXT = "quantova.transaction.v1";
const ML_DSA_65_SPKI_PREFIX = Buffer.from("308207b2300b0609608648016503040312038207a100", "hex");
const SLH_DSA_SPKI_PREFIX = Buffer.from("3040300b060960864801650304031c033100", "hex");

export function nativeMlDsaAvailable() {
  try {
    generateKeyPairSync("ml-dsa-65");
    return true;
  } catch {
    return false;
  }
}

function sha3(bytes) {
  return createHash("sha3-256").update(bytes).digest();
}

function u64le(n) {
  const out = Buffer.alloc(8);
  out.writeBigUInt64LE(BigInt(n));
  return out;
}

function fromHex(hex) {
  if (typeof hex !== "string" || !/^([0-9a-f]{2})*$/.test(hex)) return null;
  return Buffer.from(hex, "hex");
}

export function verifyMlDsa65(publicKey, message, signature, context) {
  const key = createPublicKey({
    key: Buffer.concat([ML_DSA_65_SPKI_PREFIX, publicKey]),
    format: "der",
    type: "spki",
  });
  return verifySignature(null, message, { key, context: Buffer.from(context) }, signature);
}

export function verifySlhDsa(publicKey, message, signature, context) {
  const key = createPublicKey({
    key: Buffer.concat([SLH_DSA_SPKI_PREFIX, publicKey]),
    format: "der",
    type: "spki",
  });
  return verifySignature(null, message, { key, context: Buffer.from(context) }, signature);
}

export function chainIdFor(name) {
  return sha3(Buffer.from(String(name), "utf8")).readBigUInt64BE(0);
}

export function parseTransactionBody(body) {
  let at = 0;
  const take = (n) => {
    if (n < 0 || at + n > body.length) throw new RangeError("short body");
    const out = body.subarray(at, at + n);
    at += n;
    return out;
  };
  const u64 = () => take(8).readBigUInt64LE(0);
  const bytes = () => {
    const n = u64();
    if (n > BigInt(body.length)) throw new RangeError("length beyond body");
    return take(Number(n));
  };
  try {
    const sender = bytes();
    const nonce = u64();
    const meterLimit = u64();
    const feeBytes = take(16);
    const fee = feeBytes.readBigUInt64LE(0) + (feeBytes.readBigUInt64LE(8) << 64n);
    const target = bytes();
    const args = bytes();
    const value = u64();
    const chainId = u64();
    const inAsset = bytes();
    const validUntil = u64();
    const kind = take(1)[0];
    if (at !== body.length || (inAsset.length !== 0 && inAsset.length !== 32)) return null;
    return { sender, nonce, meterLimit, fee, target, args, value, chainId, inAsset, validUntil, kind };
  } catch {
    return null;
  }
}

export function transactionChainId(tx) {
  const raw = fromHex(tx?.raw);
  const signature = fromHex(tx?.signature);
  if (!raw || !signature) return null;
  const trailer = 1 + 8 + signature.length;
  if (raw.length <= trailer) return null;
  const parsed = parseTransactionBody(raw.subarray(0, raw.length - trailer));
  return parsed ? parsed.chainId : null;
}

export function verifyKeyRegistration(tx, expectedChainId, genesis = null) {
  const fail = (reason) => ({ ok: false, reason });
  if (typeof expectedChainId !== "bigint") return fail("no expected chain id was given");
  if (genesis !== null && !(Buffer.isBuffer(genesis) && genesis.length === 32)) return fail("the genesis hash is not 32 bytes");
  const scheme = tx?.scheme;
  if (scheme !== SCHEME_ML_DSA_65 && scheme !== SCHEME_SLH_DSA) return fail(`scheme ${printable(scheme)} is neither ML-DSA-65 nor SLH-DSA`);
  const name = scheme === SCHEME_ML_DSA_65 ? "ML-DSA-65" : "SLH-DSA";
  const raw = fromHex(tx.raw);
  const signature = fromHex(tx.signature);
  if (!raw || !signature) return fail("the transaction bytes or signature are not hex");
  if (signature.length !== CHAIN_SIGNATURE_BYTES[scheme]) {
    return fail(`the signature is ${signature.length} bytes, not ${CHAIN_SIGNATURE_BYTES[scheme]}`);
  }
  const id = decodeBech32m(tx.tx_id, { hrp: "QTX", length: 32 });
  if (!id || !sha3(raw).equals(Buffer.from(id.bytes))) {
    return fail("the transaction id is not the SHA3 256 of the recorded bytes");
  }
  const trailer = 1 + 8 + signature.length;
  if (
    raw.length <= trailer ||
    !raw.subarray(raw.length - signature.length).equals(signature) ||
    !raw.subarray(raw.length - signature.length - 8, raw.length - signature.length).equals(u64le(signature.length)) ||
    raw[raw.length - trailer] !== scheme
  ) {
    return fail("the signature does not close the recorded transaction bytes");
  }
  const body = raw.subarray(0, raw.length - trailer);
  const parsed = parseTransactionBody(body);
  if (!parsed) return fail("the transaction body does not parse");
  const sender = decodeBech32m(tx.from, { hrp: "Q", length: 32 });
  if (!sender) return fail("the sender is not a Q1 address");
  if (!parsed.sender.equals(Buffer.from(sender.bytes))) return fail("the signed body names another sender");
  if (!parsed.target.equals(KEY_REGISTER_TARGET)) return fail("the signed body is not sent to the key registration system address");
  if (parsed.kind !== KIND_TRANSFER) return fail(`the signed body is of kind ${parsed.kind}, a key registration is of kind ${KIND_TRANSFER}`);
  const publicKey = parsed.args;
  if (publicKey.length !== REGISTERED_KEY_BYTES[scheme]) return fail(`the registered key is ${publicKey.length} bytes, not ${REGISTERED_KEY_BYTES[scheme]}`);
  if (!sha3(Buffer.concat([Buffer.from([scheme]), publicKey])).equals(Buffer.from(sender.bytes))) {
    return fail("the registered public key does not hash to the sender address");
  }
  const signed = sha3(genesis ? Buffer.concat([genesis, body]) : body);
  const verified = scheme === SCHEME_ML_DSA_65
    ? verifyMlDsa65(publicKey, signed, signature, TRANSACTION_CONTEXT)
    : verifySlhDsa(publicKey, signed, signature, TRANSACTION_CONTEXT);
  if (!verified) {
    return fail(genesis ? `the ${name} signature does not verify under the registered key over the pinned genesis` : `the ${name} signature does not verify under the registered key`);
  }
  if (parsed.chainId !== expectedChainId) {
    return fail(`the transaction is bound to chain id ${parsed.chainId}, not ${expectedChainId}`);
  }
  return { ok: true, publicKey, chainId: parsed.chainId, scheme };
}

export default {
  PQ_SIGNATURE_SIZES,
  CLASSICAL_SIGNATURE_SIZES,
  CLASSICAL_MAX_BYTES,
  PQ_MIN_BYTES,
  byteLength,
  classifySignature,
  nativeMlDsaAvailable,
  verifyMlDsa65,
  verifySlhDsa,
  chainIdFor,
  parseTransactionBody,
  transactionChainId,
  verifyKeyRegistration,
  CHAIN_SIGNATURE_BYTES,
  KEY_REGISTER_TARGET,
};
