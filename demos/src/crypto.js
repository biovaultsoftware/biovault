import { createPublicKey, verify as nodeVerify } from "node:crypto";

export function b64ToU8(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function u8(s) {
  return new TextEncoder().encode(s);
}

export function importJwkPublicKey(jwkJsonString) {
  const jwk = JSON.parse(jwkJsonString);
  return createPublicKey({ key: jwk, format: "jwk" });
}

export function verifyEd25519(pubKeyObj, messageBytes, sigBytes) {
  // Ed25519 uses null digest in node:crypto
  return nodeVerify(null, messageBytes, pubKeyObj, sigBytes);
}

// Canonical messages (DO NOT change order/separators)
export function msgReclaimV1({ chainId, account_id, new_device_pubkey_jwk_hash, reclaim_nonce, last_utc_ms, counter }) {
  return [
    "BALANCECHAIN_RECLAIM_V1",
    `chain=${chainId}`,
    `acct=${account_id}`,
    `newdev=${new_device_pubkey_jwk_hash}`,
    `nonce=${reclaim_nonce}`,
    `utc=${last_utc_ms}`,
    `ctr=${counter}`,
  ].join("|");
}

export function msgSegmentUpdateV1({ chainId, origin_account_id, segment_no, previous_account_id, current_account_id, last_utc_ms, counter }) {
  return [
    "BALANCECHAIN_SEGMENT_UPDATE_V1",
    `chain=${chainId}`,
    `origin=${origin_account_id}`,
    `no=${segment_no}`,
    `prev=${previous_account_id}`,
    `curr=${current_account_id}`,
    `utc=${last_utc_ms}`,
    `ctr=${counter}`,
  ].join("|");
}

// v1: stable string form; wallet should compute the same string before signing
export function stableHashJwk(jwkObj) {
  return JSON.stringify(jwkObj);
}
