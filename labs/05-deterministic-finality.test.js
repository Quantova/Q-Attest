// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

import { test } from "node:test";
import assert from "node:assert/strict";
import { HAS_ENDPOINT, QuantovaGateway } from "../lib/gateway-client.js";

const skip = !HAS_ENDPOINT;

async function finalizedHeight(g) {
  const h = await g.head();
  const raw = h?.finalized_height ?? h?.height;
  if (raw === undefined || raw === null) {
    throw new Error(
      "head did not report a finalized height, set the correct field per the ADAPT note"
    );
  }
  return typeof raw === "string" ? parseInt(raw, 10) : raw;
}

function blockHash(block) {
  return block?.block;
}

test("a finalized block is stable on re read", { skip }, async () => {
  const g = new QuantovaGateway();
  const fin = await finalizedHeight(g);
  const target = Math.max(0, fin - 2);

  const first = blockHash(await g.getBlock(target));
  const second = blockHash(await g.getBlock(target));
  assert.ok(first && second, "could not read a block hash, see the ADAPT note");
  assert.equal(first, second, `finalized block ${target} returned two different hashes`);
  console.log(`finalized block ${target} is stable across re read`);
});

test("finality lag stays bounded over a short window", { skip }, async () => {
  const g = new QuantovaGateway();
  const SAMPLES = 5;
  const MAX_LAG = 256;
  let worst = 0;

  for (let i = 0; i < SAMPLES; i++) {
    const h = await g.head();
    const head = Number(h?.height);
    const fin = Number(h?.finalized_height ?? h?.height);
    const lag = head - fin;
    worst = Math.max(worst, lag);
    assert.ok(lag >= 0, `finalized height ${fin} is ahead of head ${head}`);
  }

  assert.ok(worst <= MAX_LAG, `finality lag reached ${worst}, above the ceiling of ${MAX_LAG}`);
  console.log(`finality lag stayed within ${worst} over ${SAMPLES} samples`);
});
