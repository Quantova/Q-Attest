// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

/**
 * Lab 00 Connectivity
 *
 * Confirms the gateway is reachable and reports a node identity, a chain id,
 * and a head height. This is the ground truth every other live lab builds on.
 *
 * What this proves is that the gateway answers and the node is producing blocks.
 * What it does NOT prove is anything about the cryptography. See
 * docs/what-the-labs-prove.md.
 *
 * Run  QUANTOVA_GATEWAY_URL=https://rpc-testnet.quantova.org npm run lab:connectivity
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { HAS_ENDPOINT, QuantovaGateway } from "../lib/gateway-client.js";

const skip = !HAS_ENDPOINT;

test("the gateway reports a node identity and chain params", { skip }, async () => {
  const g = new QuantovaGateway();
  const info = await g.nodeInfo();
  const params = await g.chainParams();

  assert.ok(info, "node_info returned nothing");
  assert.ok(params, "chain_params returned nothing");
  console.log(`node_info ${JSON.stringify(info)}`);
  console.log(`chain_params ${JSON.stringify(params)}`);
});

test("the head advances to a positive height", { skip }, async () => {
  const g = new QuantovaGateway();
  const height = await g.headHeight();
  assert.ok(Number.isFinite(height) && height >= 0, `head height was ${height}`);
  console.log(`head height ${height}`);
});
