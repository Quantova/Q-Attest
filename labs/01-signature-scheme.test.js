// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

/**
 * Lab 01 Signature Scheme
 *
 * Verifies that signatures on the chain are post quantum by size band, not
 * classical. Quantova signs with ML-DSA-65 (FIPS 204), which is 3309 bytes.
 * Classical signatures such as ECDSA and Ed25519 are about 64 bytes, so a
 * signature in the classical band is a red flag.
 *
 * What this proves is that the inspected signature uses a post quantum scheme by
 * size. What it does NOT prove is correct implementation, parameter choice, or the
 * absence of a classical path elsewhere. See docs/what-the-labs-prove.md.
 *
 * Run  QUANTOVA_GATEWAY_URL=https://rpc-testnet.quantova.org npm run lab:signature
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { HAS_ENDPOINT, QuantovaGateway } from "../lib/gateway-client.js";
import { classifySignature, PQ_MIN_BYTES, CLASSICAL_MAX_BYTES } from "../lib/pq-schemes.js";

const skip = !HAS_ENDPOINT;

/**
 * Pull a signature to inspect from a recent block.
 * ADAPT, confirm where the node exposes the signature. It may be the block
 * finality signature, the proposer signature, or a transaction signature.
 * Adjust the extraction below to the get_block response shape.
 */
async function fetchSignedTransaction(g) {
  const height = await g.headHeight();
  for (let h = height - 1; h > Math.max(0, height - 200); h -= 1) {
    const block = await g.getBlock(h);
    const id = block?.tx_ids?.[0];
    if (id) return g.getTransaction(id);
  }
  throw new Error("no transaction was found in the last 200 blocks");
}

test("a chain signature is in the post quantum size band", { skip }, async () => {
  const g = new QuantovaGateway();
  const tx = await fetchSignedTransaction(g);
  const sigHex = tx.signature;
  assert.ok(typeof sigHex === "string" && /^[0-9a-f]+$/.test(sigHex), "the transaction carries no hex signature");
  assert.equal(tx.scheme, 1, `the transaction names signature scheme ${tx.scheme}, not 1 for ML-DSA-65`);
  assert.ok(typeof tx.raw === "string" && tx.raw.includes(sigHex), "the signature is not part of the transaction bytes the chain recorded");
  const { bytes, classical, postQuantum, nearest } = classifySignature(sigHex);
  assert.equal(bytes, 3309, `the signature is ${bytes} bytes, an ML-DSA-65 signature is exactly 3309 bytes`);

  console.log(`signature length ${bytes} bytes, nearest post quantum parameter set ${nearest}`);

  assert.ok(
    !classical,
    `signature is ${bytes} bytes, within the classical band at or below ${CLASSICAL_MAX_BYTES}. ` +
      "A post quantum chain must not authenticate with 64 byte ECDSA or Ed25519 signatures."
  );
  assert.ok(
    postQuantum,
    `signature is ${bytes} bytes, below the post quantum minimum of ${PQ_MIN_BYTES}. ` +
      "Quantova signs with ML-DSA-65 at 3309 bytes."
  );
});
