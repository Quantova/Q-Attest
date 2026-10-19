// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

import { test } from "node:test";
import assert from "node:assert/strict";
import { decodeBech32m } from "../lib/bech32m.js";
import { printable } from "../lib/printable.js";
import { FIELD_TABLE, HAS_ENDPOINT, QuantovaGateway } from "../lib/gateway-client.js";

const skip = !HAS_ENDPOINT;
const PROBES = ["ecrecover", "ec_recover", "recover_pubkey"];

async function fetchAddress(g) {
  const height = await g.headHeight();
  const block = await g.getBlock(Math.max(0, height - 1));
  if (typeof block?.proposer === "string") return block.proposer;

  const set = await g.validators();
  const list = Array.isArray(set) ? set : set?.validators;
  const first = Array.isArray(list) ? list[0] : null;
  return typeof first === "string" ? first : first?.address;
}

test("addresses are Q1 bech32m with a 32 byte payload, not 20 byte hex", { skip }, async () => {
  const g = new QuantovaGateway();
  const address = await fetchAddress(g);
  assert.ok(typeof address === "string" && address, `could not find an address to inspect, ${FIELD_TABLE}`);

  const isHex20 = /^0x[0-9a-fA-F]{40}$/.test(address);
  assert.ok(!isHex20, `address ${printable(address)} is 20 byte hex, which is a classical account format`);
  const decoded = decodeBech32m(address, { hrp: "Q", length: 32 });
  assert.ok(
    decoded,
    `address ${printable(address)} is not a valid Q1 bech32m string with a 32 byte payload. Quantova addresses start with a capital Q.`
  );
  console.log(`address confirmed as Q1 bech32m with a 32 byte payload ${printable(address)}`);
});

test(`the gateway exposes no methods named ${PROBES.join(", ")}`, { skip }, async () => {
  const g = new QuantovaGateway();
  for (const method of PROBES) {
    const absent = await g.methodAbsent(method);
    assert.ok(absent, `the gateway did not answer /v1/${method} with unknown_method, so it either exposes the method or could not be reached`);
  }
  console.log(`no method named ${PROBES.join(", ")} is exposed`);
});
