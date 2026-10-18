// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

/**
 * Minimal Quantova gateway client for the QORUS verification labs.
 *
 * The Quantova gateway is a plain HTTP surface. Every call is an HTTP POST to
 * <base>/v1/<method> with a flat JSON body. Addresses are Q1 bech32m strings
 * written with a capital Q. Heights and amounts are plain JSON numbers or
 * decimal strings, not hex quantities.
 *
 * The gateway methods used by the labs are node_info, head, validators,
 * chain_params, get_account, get_transaction, submit_transaction, get_block,
 * supply, get_container, get_storage, and get_events.
 */

export const OFFICIAL_GATEWAY = "https://rpc-testnet.quantova.org";
export const EXPECTED_CHAIN_ID = process.env.QUANTOVA_CHAIN_ID || "Q-test-net-01";
export const EXPECTED_GENESIS =
  process.env.QUANTOVA_GENESIS_HASH || "ca91e093bb8de33e90db52d7c89876597d14760703793ea7211929e73e613062";
const TIMEOUT_MS = 15000;
const RESPONSE_MAX = 8 * 1024 * 1024;

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
        const { status, payload } = await this.raw("node_info");
        if (status !== 200 || !payload) throw new Error(`gateway HTTP ${status} on /v1/node_info`);
        if (payload.chain_id !== EXPECTED_CHAIN_ID || payload.genesis_hash !== EXPECTED_GENESIS) {
          throw new Error(`the gateway serves chain ${payload.chain_id} with genesis ${payload.genesis_hash}, not ${EXPECTED_CHAIN_ID} with genesis ${EXPECTED_GENESIS}`);
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
    if (payload.error) throw new Error(`gateway error on /v1/${method} ${payload.error}`);
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

  validators() {
    return this.call("validators");
  }

  supply() {
    return this.call("supply");
  }

  getBlock(height) {
    return this.call("get_block", { height });
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
    return this.call("get_events", { height });
  }

  /** Read the current head height as a number, tolerating a few field shapes. */
  async headHeight() {
    const h = await this.head();
    const raw = h?.height ?? h?.head?.height ?? h?.number;
    if (raw === undefined || raw === null) {
      throw new Error("head response did not carry a height (see the ADAPT note in the lab)");
    }
    return typeof raw === "string" ? parseInt(raw, 10) : raw;
  }
}

export const HAS_ENDPOINT = process.env.QUANTOVA_OFFLINE !== "1";

export default QuantovaGateway;
