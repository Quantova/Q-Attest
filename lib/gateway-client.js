// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { printable } from "./printable.js";

export const LIVE_NETWORK = "Q-test-net-01";
export const OFFICIAL_GATEWAY = "https://rpc-testnet.quantova.org";
export const EXPECTED_CHAIN_ID = process.env.QUANTOVA_CHAIN_ID || LIVE_NETWORK;
export const FINALITY_FILE = process.env.QUANTOVA_FINALITY_FILE || null;
const DEFAULT_PIN = fileURLToPath(new URL("../finality-pin.json", import.meta.url));
const NO_PIN =
  `no finality pin is set for ${EXPECTED_CHAIN_ID}. The ${LIVE_NETWORK} genesis hash and validator roster are pinned in finality-pin.json after the relaunch, ` +
  "until then set QUANTOVA_FINALITY_FILE to a pin you trust";
export const MAX_HEIGHT = 2 ** 40;
export const FIELD_TABLE = "see the field table in docs/how-the-labs-work.md";
const TIMEOUT_MS = 15000;
const RESPONSE_MAX = 8 * 1024 * 1024;

function rosterOf(list, where) {
  if (!Array.isArray(list)) throw new Error(`the finality pin ${where} is not a list of validators`);
  for (const m of list) {
    if (!m || typeof m !== "object" || Array.isArray(m)) throw new Error(`the finality pin ${where} holds an entry that is not a validator`);
  }
  return list;
}

const PIN_FILE_MAX = 4 * 1024 * 1024;
const OPEN_FLAGS = constants.O_RDONLY | (constants.O_NOFOLLOW || 0) | (constants.O_NONBLOCK || 0);

export function readPinFile(file) {
  let fd;
  try {
    fd = openSync(file, OPEN_FLAGS);
  } catch (err) {
    if (err && err.code === "ENOENT") throw err;
    throw new Error(`the finality pin ${printable(file)} must be a regular file, not a link, writable only by its owner`);
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new Error(`the finality pin ${printable(file)} is not a regular file`);
    if ((st.mode & 0o022) !== 0) throw new Error(`the finality pin ${printable(file)} is writable by other users, run chmod go-w on it`);
    if (typeof process.getuid === "function" && st.uid !== process.getuid()) throw new Error(`the finality pin ${printable(file)} belongs to another user, it must be owned by the user running the labs`);
    const buffer = Buffer.alloc(PIN_FILE_MAX + 1);
    let length = 0;
    for (;;) {
      const n = readSync(fd, buffer, length, buffer.length - length, length);
      if (n === 0) break;
      length += n;
      if (length === buffer.length) break;
    }
    if (length > PIN_FILE_MAX) throw new Error(`the finality pin ${printable(file)} is too large`);
    return buffer.subarray(0, length).toString("utf8");
  } finally {
    closeSync(fd);
  }
}

let loadedPin;

export function loadFinalityPin() {
  if (loadedPin !== undefined) return loadedPin;
  const file = FINALITY_FILE || DEFAULT_PIN;
  let text;
  try {
    text = readPinFile(file);
  } catch (err) {
    if (err && err.code === "ENOENT") {
      if (!FINALITY_FILE) return (loadedPin = null);
      throw new Error(`the finality pin ${printable(file)} does not exist`);
    }
    throw err;
  }
  let pin;
  try {
    pin = JSON.parse(text);
  } catch {
    throw new Error(`the finality pin ${printable(file)} could not be read as JSON`);
  }
  if (!pin || typeof pin !== "object" || Array.isArray(pin)) throw new Error(`the finality pin ${printable(file)} is not a JSON object`);
  if (pin.chain_id !== EXPECTED_CHAIN_ID) {
    if (FINALITY_FILE) throw new Error(`the finality pin ${printable(file)} is for chain ${printable(pin.chain_id, 40)}, not ${printable(EXPECTED_CHAIN_ID)}`);
    return (loadedPin = null);
  }
  const roster = rosterOf(pin.roster ?? [], "roster");
  const epochs = new Map();
  for (const entry of rosterOf(pin.epochs ?? [], "epochs")) {
    const epoch = parseHeight(entry.epoch, "pinned epoch");
    if (epochs.has(epoch)) throw new Error(`the finality pin ${printable(file)} names epoch ${epoch} twice`);
    const members = rosterOf(entry.roster, `roster of epoch ${epoch}`);
    if (members.length === 0) throw new Error(`the finality pin ${printable(file)} gives epoch ${epoch} an empty roster`);
    epochs.set(epoch, members);
  }
  if (!pin.genesis_hash && roster.length === 0 && epochs.size === 0) {
    if (FINALITY_FILE) throw new Error(`the finality pin ${printable(file)} names no genesis hash and no validator roster`);
    return (loadedPin = null);
  }
  if (typeof pin.genesis_hash !== "string" || !/^[0-9a-f]{64}$/i.test(pin.genesis_hash)) {
    throw new Error(`the finality pin ${printable(file)} needs a genesis hash of 64 hex characters`);
  }
  if (roster.length === 0 && epochs.size === 0) throw new Error(`the finality pin ${printable(file)} needs a non empty validator roster`);
  return (loadedPin = { file, chainName: pin.chain_id, genesisHash: pin.genesis_hash.toLowerCase(), roster, epochs });
}

export function pinnedRosterFor(pin, epoch) {
  const members = pin.epochs.get(Number(epoch)) ?? (pin.roster.length > 0 ? pin.roster : null);
  if (!members) throw new Error(`the finality pin ${printable(pin.file)} holds no validator roster for epoch ${printable(epoch)}`);
  return members;
}

export function expectedGenesis() {
  const named = process.env.QUANTOVA_GENESIS_HASH || null;
  const pinned = loadFinalityPin()?.genesisHash ?? null;
  if (named && pinned && named.toLowerCase() !== pinned) {
    throw new Error(`QUANTOVA_GENESIS_HASH names genesis ${printable(named)} but the finality pin names ${pinned}`);
  }
  return named || pinned;
}

export function parseHeight(raw, what = "height") {
  let n = null;
  if (typeof raw === "number" && Number.isSafeInteger(raw)) n = raw;
  else if (typeof raw === "string" && raw.length <= 16 && /^(0|[1-9]\d*)$/.test(raw)) n = Number(raw);
  if (n === null || n < 0 || n > MAX_HEIGHT) {
    const shown = printable(JSON.stringify(raw), 40);
    throw new Error(`the ${what} ${shown} is not a whole number from 0 to 2^40`);
  }
  return n;
}

async function readBounded(res, method) {
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > RESPONSE_MAX) {
      await reader.cancel();
      throw new Error(`gateway response on /v1/${method} is too large`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

export class QuantovaGateway {
  constructor(baseUrl = process.env.QUANTOVA_GATEWAY_URL || OFFICIAL_GATEWAY) {
    const url = new URL(baseUrl);
    const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    if (url.protocol !== "https:" && !(url.protocol === "http:" && local)) {
      throw new Error("the gateway must be reached over https, plain http is allowed only to this machine");
    }
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.pinned = null;
  }

  async raw(method, body = {}) {
    if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0") {
      throw new Error("refusing to run with NODE_TLS_REJECT_UNAUTHORIZED=0, the gateway certificate must be checked");
    }
    const res = await fetch(`${this.baseUrl}/v1/${method}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(TIMEOUT_MS),
      redirect: "error",
    });
    const text = await readBounded(res, method);
    let payload = null;
    try {
      payload = JSON.parse(text);
    } catch {
      payload = null;
    }
    if (payload === null || typeof payload !== "object" || Array.isArray(payload)) payload = null;
    return { status: res.status, payload };
  }

  async pin() {
    if (!this.pinned) {
      this.pinned = (async () => {
        const genesis = expectedGenesis();
        if (!genesis) {
          throw new Error(
            `no genesis hash is pinned for ${EXPECTED_CHAIN_ID}. The ${LIVE_NETWORK} genesis hash is pinned in finality-pin.json after the relaunch, ` +
              "until then set QUANTOVA_FINALITY_FILE or QUANTOVA_GENESIS_HASH to the genesis you trust"
          );
        }
        if (!/^[0-9a-f]{64}$/.test(genesis)) {
          throw new Error("QUANTOVA_GENESIS_HASH must be 64 lowercase hex characters");
        }
        const { status, payload } = await this.raw("node_info");
        if (status !== 200 || !payload) throw new Error(`gateway HTTP ${status} on /v1/node_info`);
        if (payload.chain_id !== EXPECTED_CHAIN_ID || payload.genesis_hash !== genesis) {
          throw new Error(`the gateway serves chain ${printable(payload.chain_id)} with genesis ${printable(payload.genesis_hash)}, not ${printable(EXPECTED_CHAIN_ID)} with genesis ${genesis}`);
        }
        return payload;
      })();
    }
    return this.pinned;
  }

  async call(method, body = {}) {
    const info = await this.pin();
    if (method === "node_info") return info;
    const { status, payload } = await this.raw(method, body);
    if (status !== 200 || !payload) throw new Error(`gateway HTTP ${status} on /v1/${method}`);
    if (payload.error) throw new Error(`gateway error on /v1/${method} ${printable(payload.error)}`);
    return payload;
  }

  async methodAbsent(method) {
    await this.pin();
    const { status, payload } = await this.raw(method, {});
    return status === 404 && payload && payload.error === "unknown_method";
  }

  nodeInfo() {
    return this.call("node_info");
  }

  chainParams() {
    return this.call("chain_params");
  }

  head() {
    return this.call("head");
  }

  finalizedHead() {
    return this.call("finalized_head");
  }

  validators() {
    return this.call("validators");
  }

  supply() {
    return this.call("supply");
  }

  getBlock(height) {
    return this.call("get_block", { height: parseHeight(height, "block height") });
  }

  getTransaction(txId) {
    return this.call("get_transaction", { tx_id: txId });
  }

  getAccount(address) {
    return this.call("get_account", { address });
  }

  getContainer(address) {
    return this.call("get_container", { address });
  }

  getEvents(height) {
    return this.call("get_events", { height: parseHeight(height, "event height") });
  }

  getFinality(height) {
    return this.call("get_finality", { height: parseHeight(height, "finality height") });
  }

  getValidatorSet(epoch) {
    return this.call("get_validator_set", { epoch: parseHeight(epoch, "epoch") });
  }

  async binding() {
    await this.pin();
    return { chainName: EXPECTED_CHAIN_ID, genesis: Buffer.from(expectedGenesis(), "hex") };
  }

  async finalityPin() {
    const pin = loadFinalityPin();
    if (!pin) throw new Error(NO_PIN);
    await this.pin();
    return pin;
  }

  async headHeight() {
    const h = await this.head();
    if (h?.height === undefined || h?.height === null) {
      throw new Error(`the head response did not carry a height, ${FIELD_TABLE}`);
    }
    return parseHeight(h.height, "head height");
  }

  async finalizedHeight() {
    const f = await this.finalizedHead();
    if (f?.head === undefined || f?.head === null) {
      throw new Error(`the finalized_head response did not carry a head height, ${FIELD_TABLE}`);
    }
    return parseHeight(f.head, "finalized height");
  }
}

export const HAS_ENDPOINT = process.env.QUANTOVA_OFFLINE !== "1";

export default QuantovaGateway;
