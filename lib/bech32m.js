// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
export const BECH32M_MAX_LENGTH = 90;

function polymod(values) {
  const G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const b = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((b >>> i) & 1) chk ^= G[i];
  }
  return chk;
}

export function decodeBech32m(text, expected = {}) {
  if (typeof text !== "string" || text.length > BECH32M_MAX_LENGTH || text !== text.toUpperCase()) return null;
  const s = text.toLowerCase();
  const sep = s.lastIndexOf("1");
  if (sep < 1 || sep + 7 > s.length) return null;
  const hrp = s.slice(0, sep);
  for (const c of hrp) {
    const code = c.charCodeAt(0);
    if (code < 33 || code > 126) return null;
  }
  const data = [];
  for (const c of s.slice(sep + 1)) {
    const v = CHARSET.indexOf(c);
    if (v < 0) return null;
    data.push(v);
  }
  const expanded = [...hrp].map((c) => c.charCodeAt(0) >> 5).concat([0], [...hrp].map((c) => c.charCodeAt(0) & 31));
  if (polymod(expanded.concat(data)) !== 0x2bc830a3) return null;
  const out = [];
  let acc = 0;
  let bits = 0;
  for (const v of data.slice(0, -6)) {
    acc = ((acc << 5) | v) & 0xfff;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >>> bits) & 255);
    }
  }
  if (bits >= 5 || (acc & ((1 << bits) - 1)) !== 0) return null;
  const result = { hrp: hrp.toUpperCase(), bytes: Uint8Array.from(out) };
  if (expected.hrp !== undefined && result.hrp !== expected.hrp) return null;
  if (expected.length !== undefined && result.bytes.length !== expected.length) return null;
  return result;
}

export function encodeBech32m(hrp, bytes) {
  const lower = String(hrp).toLowerCase();
  const data = [];
  let acc = 0;
  let bits = 0;
  for (const byte of bytes) {
    acc = ((acc << 8) | byte) & 0xfff;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      data.push((acc >>> bits) & 31);
    }
  }
  if (bits > 0) data.push((acc << (5 - bits)) & 31);
  const expanded = [...lower].map((c) => c.charCodeAt(0) >> 5).concat([0], [...lower].map((c) => c.charCodeAt(0) & 31));
  const mod = polymod(expanded.concat(data, [0, 0, 0, 0, 0, 0])) ^ 0x2bc830a3;
  const checksum = [0, 1, 2, 3, 4, 5].map((i) => (mod >>> (5 * (5 - i))) & 31);
  return `${lower}1${data.concat(checksum).map((v) => CHARSET[v]).join("")}`.toUpperCase();
}
