// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

import { test } from "node:test";
import assert from "node:assert/strict";
import { setTimeout as sleep } from "node:timers/promises";
import { HAS_ENDPOINT, QuantovaGateway } from "../lib/gateway-client.js";
import { printable } from "../lib/printable.js";

const skip = !HAS_ENDPOINT;
const POLL_MS = 500;
const POLLS = 20;

test("the gateway reports a node identity and chain params", { skip }, async () => {
  const g = new QuantovaGateway();
  const info = await g.nodeInfo();
  const params = await g.chainParams();

  assert.ok(info, "node_info returned nothing");
  assert.ok(params, "chain_params returned nothing");
  console.log(`node_info ${printable(JSON.stringify(info), 4000)}`);
  console.log(`chain_params ${printable(JSON.stringify(params), 4000)}`);
});

test("the head advances", { skip }, async () => {
  const g = new QuantovaGateway();
  const first = await g.headHeight();
  let later = first;
  for (let i = 0; i < POLLS && later <= first; i += 1) {
    await sleep(POLL_MS);
    later = await g.headHeight();
  }
  assert.ok(later > first, `the head stayed at height ${first} for ${(POLLS * POLL_MS) / 1000} seconds`);
  console.log(`head height advanced from ${first} to ${later}`);
});
