// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

import { createHash, createPublicKey, generateKeyPairSync, verify as verifySignature } from "node:crypto";
import { decodeBech32m } from "./bech32m.js";

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
export const ML_DSA_65_PUBLIC_KEY_BYTES = 1952;
export const ML_DSA_65_SIGNATURE_BYTES = 3309;
export const TRANSACTION_CONTEXT = "quantova.transaction.v1";
const ML_DSA_65_SPKI_PREFIX = Buffer.from("308207b2300b0609608648016503040312038207a100", "hex");

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

export function verifyKeyRegistration(tx) {
  const fail = (reason) => ({ ok: false, reason });
  if (tx?.scheme !== SCHEME_ML_DSA_65) return fail(`scheme ${tx?.scheme} is not ML-DSA-65`);
  const raw = fromHex(tx.raw);
  const signature = fromHex(tx.signature);
  if (!raw || !signature) return fail("the transaction bytes or signature are not hex");
  if (signature.length !== ML_DSA_65_SIGNATURE_BYTES) {
    return fail(`the signature is ${signature.length} bytes, not ${ML_DSA_65_SIGNATURE_BYTES}`);
  }
  const id = decodeBech32m(tx.tx_id);
  if (!id || id.hrp !== "QTX" || !sha3(raw).equals(Buffer.from(id.bytes))) {
    return fail("the transaction id is not the SHA3 256 of the recorded bytes");
  }
  const trailer = 1 + 8 + signature.length;
  if (
    raw.length <= trailer ||
    !raw.subarray(raw.length - signature.length).equals(signature) ||
    !raw.subarray(raw.length - signature.length - 8, raw.length - signature.length).equals(u64le(signature.length)) ||
    raw[raw.length - trailer] !== SCHEME_ML_DSA_65
  ) {
    return fail("the signature does not close the recorded transaction bytes");
  }
  const body = raw.subarray(0, raw.length - trailer);
  const sender = decodeBech32m(tx.from);
  if (!sender || sender.hrp !== "Q" || sender.bytes.length !== 32) return fail("the sender is not a Q1 address");
  const prefix = u64le(ML_DSA_65_PUBLIC_KEY_BYTES);
  let publicKey = null;
  for (let at = body.indexOf(prefix); at >= 0; at = body.indexOf(prefix, at + 1)) {
    const candidate = body.subarray(at + 8, at + 8 + ML_DSA_65_PUBLIC_KEY_BYTES);
    if (candidate.length !== ML_DSA_65_PUBLIC_KEY_BYTES) break;
    const bound = sha3(Buffer.concat([Buffer.from([SCHEME_ML_DSA_65]), candidate]));
    if (bound.equals(Buffer.from(sender.bytes))) {
      publicKey = candidate;
      break;
    }
  }
  if (!publicKey) return fail("no registered public key in the body hashes to the sender address");
  if (!verifyMlDsa65(publicKey, sha3(body), signature, TRANSACTION_CONTEXT)) {
    return fail("the ML-DSA-65 signature does not verify under the registered key");
  }
  return { ok: true, publicKey };
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
  verifyKeyRegistration,
};
