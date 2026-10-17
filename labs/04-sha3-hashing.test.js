// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

/**
 * Lab 04 SHA3 Hashing
 *
 * Verifies the chain hashes with SHA-3. Quantova uses SHA-3 and SHAKE from
 * FIPS 202 across the stack. This lab runs self verifying known answer tests
 * offline, which confirm the lab's own SHA3 256 is correct, and a live check
 * that block hashes are 32 byte values.
 *
 * The known answer tests always run, so part of this lab passes with no node
 * and demonstrates the harness is sound. The live check needs a gateway.
 *
 * Run  npm run lab:sha3                                  (offline, KATs only)
 *       QUANTOVA_GATEWAY_URL=... npm run lab:sha3         (KATs and live width check)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { decodeBech32m } from "../lib/bech32m.js";
import { HAS_ENDPOINT, QuantovaGateway } from "../lib/gateway-client.js";
import { byteLength } from "../lib/pq-schemes.js";

// Self verifying known answer tests. These always run, no node needed.

const SHA3_256_KATS = [
  { input: "", expected: "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a" },
  { input: "abc", expected: "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532" },
];

test("SHA3 256 known answer tests, self check, offline", () => {
  for (const { input, expected } of SHA3_256_KATS) {
    const got = crypto.createHash("sha3-256").update(input).digest("hex");
    assert.equal(got, expected, `SHA3 256 of "${input}" did not match`);
  }
});

test("SHA3 256 produces a 32 byte digest", () => {
  const digest = crypto.createHash("sha3-256").update("quantova").digest();
  assert.equal(digest.length, 32, "SHA3 256 digest must be 32 bytes");
});

// Live check that block hashes are 256 bit values.

const skip = !HAS_ENDPOINT;

test("live, a block hash is a 32 byte value", { skip }, async () => {
  const g = new QuantovaGateway();
  const height = await g.headHeight();
  const block = await g.getBlock(Math.max(0, height - 1));

  const id = decodeBech32m(block?.block);
  assert.ok(id && id.hrp === "QBK", `the block identifier ${block?.block} is not a QBK bech32m string`);
  assert.equal(id.bytes.length, 32, `the block hash is ${id.bytes.length} bytes, SHA3 256 hashes are 32 bytes`);
  for (const field of ["transaction_root", "event_root"]) {
    assert.ok(/^[0-9a-f]{64}$/.test(block?.[field] || ""), `${field} is not a 32 byte hash`);
  }
  console.log("block hash width confirmed, 32 bytes");
});
