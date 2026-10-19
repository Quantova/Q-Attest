// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

import { test } from "node:test";
import assert from "node:assert/strict";
import { setTimeout as sleep } from "node:timers/promises";
import { decodeBech32m } from "../lib/bech32m.js";
import { printable } from "../lib/printable.js";
import { FIELD_TABLE, HAS_ENDPOINT, QuantovaGateway } from "../lib/gateway-client.js";
import { fetchVerifiedFinality, fetchVerifiedFinalizedHead, nextBeacon } from "../lib/qorus.js";

const skip = !HAS_ENDPOINT;
const SAMPLES = 5;
const SAMPLE_GAP_MS = 250;
const MAX_LAG = 256;

async function requireFinality(g) {
  for (const method of ["finalized_head", "get_finality"]) {
    assert.ok(!(await g.methodAbsent(method)), `the gateway does not serve ${method}, so finality cannot be confirmed`);
  }
}

test("the finalized block carries a certificate signed by two thirds of the pinned committee stake", { skip }, async () => {
  const g = new QuantovaGateway();
  await requireFinality(g);
  const verified = await fetchVerifiedFinalizedHead(g);
  const head = await g.headHeight();
  assert.ok(Number(verified.height) <= head, `finalized height ${verified.height} is ahead of head ${head}`);

  const block = await g.getBlock(Number(verified.height));
  const id = decodeBech32m(block?.block, { hrp: "QBK", length: 32 });
  assert.ok(id, `could not read a QBK block identifier at finalized height ${verified.height}, ${FIELD_TABLE}`);
  assert.ok(Buffer.from(id.bytes).equals(verified.header.hash), `get_block names block ${printable(block.block)} at height ${verified.height}, not the SHA3 256 of the certified header`);

  const again = await fetchVerifiedFinality(g, verified.height);
  assert.ok(again.header.hash.equals(verified.header.hash), `finalized block ${verified.height} returned two different headers`);
  console.log(
    `block ${verified.height} certified by ${verified.signers.size} of ${verified.active.length} pinned validators holding ${verified.signed} of ${verified.committeeStake} stake, view ${verified.view}, ` +
      (verified.servedMatches ? "the served validator set matches the pin" : "no served validator set to compare")
  );
});

test("consecutive finalized blocks link by parent hash and beacon", { skip }, async () => {
  const g = new QuantovaGateway();
  await requireFinality(g);
  let child = await fetchVerifiedFinalizedHead(g);
  for (let i = 0; i < 4 && child.slot === 0n; i += 1) {
    await sleep(1000);
    child = await fetchVerifiedFinalizedHead(g);
  }
  assert.ok(child.slot > 0n, `finalized height ${child.height} stayed at the first slot of its epoch`);
  const parent = await fetchVerifiedFinality(g, child.height - 1n);
  assert.ok(child.header.parentHash.equals(parent.header.hash), `block ${child.height} does not name block ${parent.height} as its parent`);
  assert.ok(
    child.header.beaconSeed.equals(nextBeacon(parent.header.beaconSeed, parent.slot)),
    `the beacon of block ${child.height} is not the full committee step of the beacon of block ${parent.height}`
  );
  console.log(`blocks ${parent.height} and ${child.height} are both certified and linked by parent hash and beacon`);
});

test("finality lag stays bounded and the finalized height never moves back", { skip }, async () => {
  const g = new QuantovaGateway();
  await requireFinality(g);
  let worst = 0;
  let last = 0;

  for (let i = 0; i < SAMPLES; i += 1) {
    if (i > 0) await sleep(SAMPLE_GAP_MS);
    const fin = await g.finalizedHeight();
    const verified = await fetchVerifiedFinality(g, fin);
    assert.equal(verified.height, BigInt(fin), `the certificate the gateway serves for finalized height ${fin} is for height ${verified.height}`);
    const head = await g.headHeight();
    assert.ok(fin >= last, `the finalized height moved back from ${last} to ${fin}`);
    assert.ok(fin <= head, `finalized height ${fin} is ahead of head ${head}`);
    worst = Math.max(worst, head - fin);
    last = fin;
  }

  assert.ok(worst <= MAX_LAG, `finality lag reached ${worst}, above the ceiling of ${MAX_LAG}`);
  console.log(`finality lag stayed within ${worst} over ${SAMPLES} samples, each finalized height certified by the pinned roster, finalized height ${last}`);
});
