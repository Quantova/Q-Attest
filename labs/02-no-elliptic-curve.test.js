// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

import { test } from "node:test";
import assert from "node:assert/strict";
import { HAS_ENDPOINT, QuantovaGateway } from "../lib/gateway-client.js";

const skip = !HAS_ENDPOINT;

async function fetchAddress(g) {
  const height = await g.headHeight();
  const block = await g.getBlock(Math.max(0, height - 1));
  const candidate =
    block?.proposer ||
    block?.transactions?.[0]?.from ||
    block?.transactions?.[0]?.sender;
  if (candidate) return candidate;

  const set = await g.validators();
  const list = Array.isArray(set) ? set : set?.validators;
  const first = Array.isArray(list) ? list[0] : null;
  return typeof first === "string" ? first : first?.address;
}

test("addresses are Q1 bech32m, not 20 byte hex", { skip }, async () => {
  const g = new QuantovaGateway();
  const address = await fetchAddress(g);
  assert.ok(address, "could not find an address to inspect, see the ADAPT note in this file");

  const isHex20 = /^0x[0-9a-fA-F]{40}$/.test(address);
  assert.ok(!isHex20, `address ${address} is 20 byte hex, which is a classical account format`);
  assert.ok(
    /^Q1[02-9AC-HJ-NP-Z]+$/.test(address),
    `address ${address} is not a Q1 bech32m string. Quantova addresses start with a capital Q.`
  );
  console.log(`address confirmed as Q1 bech32m ${address}`);
});

test("the gateway exposes no elliptic curve recovery method", { skip }, async () => {
  const g = new QuantovaGateway();
  const probes = ["ecrecover", "ec_recover", "recover_pubkey"];
  for (const method of probes) {
    const absent = await g.methodAbsent(method);
    assert.ok(absent, `the gateway did not answer /v1/${method} with unknown_method, so it either exposes the method or could not be reached`);
  }
  console.log("no elliptic curve recovery method is exposed");
});
