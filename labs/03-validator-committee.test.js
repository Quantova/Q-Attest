// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

import { test } from "node:test";
import assert from "node:assert/strict";
import { decodeBech32m } from "../lib/bech32m.js";
import { printable } from "../lib/printable.js";
import { FIELD_TABLE, HAS_ENDPOINT, QuantovaGateway } from "../lib/gateway-client.js";
import {
  COMMITTEE_BUDGET,
  MAX_ACTIVE_VALIDATORS,
  MIN_SELF_STAKE,
  fetchVerifiedFinality,
  fetchVerifiedFinalizedHead,
  proposerCandidates,
} from "../lib/qorus.js";

const skip = !HAS_ENDPOINT;
const SAMPLE = 12;

function addressOf(v) {
  return typeof v === "string" ? v : v?.address;
}

test("the validators endpoint returns a well formed validator registry", { skip }, async () => {
  const g = new QuantovaGateway();
  const set = await g.validators();
  const list = Array.isArray(set) ? set : set?.validators;
  assert.ok(Array.isArray(list) && list.length > 0, `could not read the validator registry from the validators endpoint, ${FIELD_TABLE}`);
  const addresses = list.map(addressOf);
  for (const address of addresses) {
    assert.ok(decodeBech32m(address, { hrp: "Q", length: 32 }), `registry entry ${printable(address)} is not a Q1 bech32m address`);
  }
  assert.equal(new Set(addresses).size, addresses.length, "the validator registry lists an address twice");
  console.log(`validator registry of ${addresses.length} entries`);
});

test("the committee of a finalized slot is the pinned active validator set and every reveal opens its sortition root", { skip }, async () => {
  const g = new QuantovaGateway();
  const verified = await fetchVerifiedFinalizedHead(g);
  const eligible = verified.active.every((m) => m.stake >= MIN_SELF_STAKE);
  assert.ok(eligible, `a committee member holds less than the minimum self stake of ${MIN_SELF_STAKE}`);
  assert.ok(verified.active.length <= MAX_ACTIVE_VALIDATORS, `the committee has ${verified.active.length} members, above the active set of ${MAX_ACTIVE_VALIDATORS}`);
  for (const m of verified.active) {
    assert.ok(decodeBech32m(m.bondAddress, { hrp: "Q", length: 32 }), `validator ${m.id} bonds from ${printable(m.bondAddress)}, not a Q1 address`);
  }
  console.log(
    `slot ${verified.slot} of epoch ${verified.epoch} committed to ${verified.active.length} pinned active validators under budget ${COMMITTEE_BUDGET}, ` +
      `${verified.reveals} reveals and ${verified.signers.size} attestations opened their sortition roots`
  );
});

test("recent finalized blocks were proposed by the pinned stake weighted rotation leader of their slot", { skip }, async () => {
  const g = new QuantovaGateway();
  const top = await fetchVerifiedFinalizedHead(g);
  let checked = 0;
  const leaders = new Set();
  for (let i = 0n; i < BigInt(SAMPLE) && i <= top.slot; i += 1n) {
    const verified = i === 0n ? top : await fetchVerifiedFinality(g, top.height - i);
    const candidates = proposerCandidates(verified);
    assert.ok(candidates.length > 0, `no rotation leader could be drawn for block ${verified.height}`);
    const proposer = verified.header.proposer;
    assert.ok(candidates.every((m) => m.bondAddress), `the pinned roster names no bond address for a validator, so the proposer of block ${verified.height} cannot be checked`);
    assert.ok(
      candidates.some((m) => m.bondAddress === proposer),
      `block ${verified.height} was proposed by ${printable(proposer)}, but the rotation leader for slot ${verified.slot} up to view ${verified.view} is ${printable(candidates.map((m) => m.bondAddress).join(" or "), 600)}`
    );
    const block = await g.getBlock(Number(verified.height));
    assert.ok(block?.proposer === proposer, `get_block names proposer ${printable(block?.proposer)} for block ${verified.height}, the certified header names ${printable(proposer)}`);
    leaders.add(proposer);
    checked += 1;
  }
  assert.ok(checked > 0, "no finalized block could be checked");
  console.log(`${checked} finalized blocks, each proposed by its rotation leader, ${leaders.size} distinct proposers`);
});
