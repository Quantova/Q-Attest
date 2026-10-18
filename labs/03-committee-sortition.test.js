// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

import { test } from "node:test";
import assert from "node:assert/strict";
import { HAS_ENDPOINT, QuantovaGateway } from "../lib/gateway-client.js";

const skip = !HAS_ENDPOINT;

async function fetchCommittee(g) {
  const set = await g.validators();
  const list = Array.isArray(set) ? set : set?.committee ?? set?.validators;
  if (!Array.isArray(list) || list.length === 0) {
    throw new Error(
      "Could not read the active committee from the validators endpoint. Set the correct " +
        "field, marked with an ADAPT note in this file, per docs/how-the-labs-work.md."
    );
  }
  return list.map((v) => (typeof v === "string" ? v : v?.address || v?.id));
}

async function fetchCommitteeBudget(g) {
  const params = await g.chainParams();
  return params?.committee_budget ?? params?.max_committee_size ?? params?.committee_size;
}

function blockAuthor(block) {
  const raw = block?.proposer ?? block?.author ?? block?.header?.proposer;
  return typeof raw === "string" ? raw : raw?.address || raw?.id;
}

test("the validators endpoint returns an active committee within budget", { skip }, async () => {
  const g = new QuantovaGateway();
  const committee = await fetchCommittee(g);
  assert.ok(committee.length > 0, "committee is empty");

  const budget = await fetchCommitteeBudget(g);
  if (budget !== undefined && budget !== null) {
    assert.ok(
      committee.length <= budget,
      `committee has ${committee.length} members, above the reported budget of ${budget}`
    );
    console.log(`committee size ${committee.length} within budget ${budget}`);
  } else {
    console.warn("chain_params did not report a committee budget, see the ADAPT note");
    console.log(`committee size ${committee.length}`);
  }
});

test("recent block authors are drawn from the validator registry", { skip }, async () => {
  const g = new QuantovaGateway();
  const committee = new Set(await fetchCommittee(g));

  const head = await g.headHeight();
  const SAMPLE = 12;
  const authors = new Set();
  let checked = 0;

  for (let h = Math.max(0, head - SAMPLE); h < head; h++) {
    const block = await g.getBlock(h);
    const author = blockAuthor(block);
    if (!author) continue;
    checked++;
    authors.add(author);
    assert.ok(
      committee.has(author),
      `block ${h} author ${author} is not in the active committee`
    );
  }

  assert.ok(checked > 0, "no blocks could be inspected, check the ADAPT fields");
  console.log(
    `inspected ${checked} blocks, ${authors.size} distinct authors, all within the committee`
  );
});
