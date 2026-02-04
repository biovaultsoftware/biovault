import {
  importJwkPublicKey,
  verifyEd25519,
  b64ToU8,
  u8,
  msgReclaimV1,
  msgSegmentUpdateV1,
  stableHashJwk,
} from "./crypto.js";

import { asInt, enforceUtcCounterMatch, enforceNotFuture } from "./validate.js";

import {
  getAccount,
  createAccountIfMissing,
  updateReclaim,
  getSegment,
  upsertSegment,
  conditionalAdvanceSegment,
  listSegmentsByCurrentOwner,
  listSegmentsByOrigin,
  upsertOriginMax,
  getOriginStats,
  countAccounts,
  countSegments,
  listAccounts,
} from "./db.js";

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET,POST,OPTIONS",
      "access-control-allow-headers": "content-type",
    },
  });
}

function bad(msg, status = 400) {
  return json({ ok: false, error: msg }, status);
}

const YEAR_SEC = 365 * 24 * 3600;
function allowedToDate(now_ms, genesis_ms, join_delta_sec, initial_unlocked, yearly_cap) {
  const join_ms = genesis_ms + join_delta_sec * 1000;
  const elapsed_sec = Math.max(0, Math.floor((now_ms - join_ms) / 1000));
  const full_years = Math.floor(elapsed_sec / YEAR_SEC);
  const rem_sec = elapsed_sec - full_years * YEAR_SEC;
  const partial = Math.floor((rem_sec / YEAR_SEC) * yearly_cap);
  return initial_unlocked + full_years * yearly_cap + partial;
}

export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return json({ ok: true });

    const url = new URL(req.url);
    const path = url.pathname;

    const CHAIN_ID = env.CHAIN_ID || "balancechain";
    const GENESIS_UTC_MS = asInt(env.GENESIS_UTC_MS, "GENESIS_UTC_MS");
    const MAX_FUTURE_SKEW_MS = asInt(env.MAX_FUTURE_SKEW_MS || "120000", "MAX_FUTURE_SKEW_MS");
    const MAX_BATCH = asInt(env.MAX_BATCH || "500", "MAX_BATCH");

    // Explorer caps (used only for display)
    const INITIAL_UNLOCKED = asInt(env.INITIAL_UNLOCKED || "1200", "INITIAL_UNLOCKED");
    const YEARLY_CAP = asInt(env.YEARLY_CAP || "120000", "YEARLY_CAP");

    // ---- Node info ----
    if (req.method === "GET" && path === "/v1/node/info") {
      return json({
        ok: true,
        chain_id: CHAIN_ID,
        genesis_utc_ms: GENESIS_UTC_MS,
        max_future_skew_ms: MAX_FUTURE_SKEW_MS,
        version: "balancechain-node-v2",
      });
    }

    // =========================
    // Explorer endpoints
    // =========================

    if (req.method === "GET" && path === "/v1/explorer/stats") {
      const now = Date.now();
      const total_accounts = await countAccounts(env.DB);
      const total_segments = await countSegments(env.DB);
      return json({
        ok: true,
        chain_id: CHAIN_ID,
        genesis_utc_ms: GENESIS_UTC_MS,
        now_ms: now,
        total_accounts,
        total_segments,
        initial_unlocked: INITIAL_UNLOCKED,
        yearly_cap: YEARLY_CAP,
      });
    }

    if (req.method === "GET" && path === "/v1/explorer/accounts") {
      const now = Date.now();
      const limit = Math.min(Number(url.searchParams.get("limit") || "100"), 500);
      const cursor = Math.max(Number(url.searchParams.get("cursor") || "0"), 0);

      const accounts = await listAccounts(env.DB, limit, cursor);
      const enriched = [];

      for (const a of accounts) {
        const s = await getOriginStats(env.DB, a.account_id);
        const unlocked_segments_count = s ? (s.max_segment_no + 1) : 0;
        const expected_allowed_to_date = allowedToDate(now, GENESIS_UTC_MS, a.join_delta_sec, INITIAL_UNLOCKED, YEARLY_CAP);
        const remaining = Math.max(0, expected_allowed_to_date - unlocked_segments_count);

        enriched.push({
          account_id: a.account_id,
          reclaim_nonce: a.reclaim_nonce,
          last_reclaim_utc_ms: a.last_reclaim_utc_ms,
          unlocked_segments_count,
          expected_allowed_to_date,
          remaining,
          active_device_pubkey_jwk: a.active_device_pubkey_jwk,
        });
      }

      return json({ ok: true, cursor, limit, accounts: enriched });
    }

    const acctSum = path.match(/^\/v1\/explorer\/accounts\/([^/]+)\/summary$/);
    if (req.method === "GET" && acctSum) {
      const now = Date.now();
      const accountId = decodeURIComponent(acctSum[1]);
      const a = await getAccount(env.DB, accountId);
      if (!a) return bad("Account not found", 404);

      const s = await getOriginStats(env.DB, accountId);
      const unlocked_segments_count = s ? (s.max_segment_no + 1) : 0;
      const expected_allowed_to_date = allowedToDate(now, GENESIS_UTC_MS, a.join_delta_sec, INITIAL_UNLOCKED, YEARLY_CAP);
      const remaining = Math.max(0, expected_allowed_to_date - unlocked_segments_count);

      return json({
        ok: true,
        account_id: accountId,
        reclaim_nonce: a.reclaim_nonce,
        last_reclaim_utc_ms: a.last_reclaim_utc_ms,
        unlocked_segments_count,
        expected_allowed_to_date,
        remaining,
      });
    }

    if (req.method === "GET" && path === "/v1/explorer/serial") {
      const origin = url.searchParams.get("origin");
      const no = url.searchParams.get("no");
      if (!origin || no === null) return bad("origin and no are required");
      let segment_no;
      try { segment_no = asInt(no, "no"); } catch (e) { return bad(e.message); }
      const seg = await getSegment(env.DB, origin, segment_no);
      return json({ ok: true, segment: seg || null });
    }

    // =========================
    // Wallet endpoints (minimal)
    // =========================

    const acctMatch = path.match(/^\/v1\/accounts\/([^/]+)$/);
    if (req.method === "GET" && acctMatch) {
      const accountId = decodeURIComponent(acctMatch[1]);
      const a = await getAccount(env.DB, accountId);
      return json({ ok: true, account: a || null });
    }

    const segListMatch = path.match(/^\/v1\/accounts\/([^/]+)\/segments$/);
    if (req.method === "GET" && segListMatch) {
      const accountId = decodeURIComponent(segListMatch[1]);
      const role = url.searchParams.get("role") || "current"; // current|origin
      const limit = Math.min(Number(url.searchParams.get("limit") || "500"), 2000);
      const cursor = Math.max(Number(url.searchParams.get("cursor") || "0"), 0);

      const rows = role === "origin"
        ? await listSegmentsByOrigin(env.DB, accountId, limit, cursor)
        : await listSegmentsByCurrentOwner(env.DB, accountId, limit, cursor);

      return json({ ok: true, role, cursor, limit, segments: rows });
    }

    // ---- RECLAIM: rotate device key using recovery key; old device frozen forever ----
    if (req.method === "POST" && path === "/v1/accounts/reclaim") {
      let body;
      try { body = await req.json(); } catch { return bad("Invalid JSON"); }

      const now = Date.now();

      const account_id = String(body.account_id || "");
      const recovery_pubkey_jwk = body.recovery_pubkey_jwk;
      const new_device_pubkey_jwk = body.new_device_pubkey_jwk;
      const join_delta_sec = asInt(body.join_delta_sec, "join_delta_sec");
      const reclaim_nonce = asInt(body.reclaim_nonce, "reclaim_nonce");
      const last_utc_ms = asInt(body.last_utc_ms, "last_utc_ms");
      const counter = asInt(body.counter, "counter");
      const sig_b64 = String(body.sig_b64 || "");

      if (!account_id || !recovery_pubkey_jwk || !new_device_pubkey_jwk || !sig_b64) {
        return bad("Missing required reclaim fields");
      }

      try {
        enforceNotFuture(last_utc_ms, now, MAX_FUTURE_SKEW_MS);
        enforceUtcCounterMatch(last_utc_ms, counter, GENESIS_UTC_MS);
      } catch (e) {
        return bad(e.message);
      }

      const existing = await getAccount(env.DB, account_id);

      if (!existing) {
        if (reclaim_nonce !== 1) return bad("First reclaim must use reclaim_nonce=1");

        await createAccountIfMissing(env.DB, {
          account_id,
          recovery_pubkey_jwk: JSON.stringify(recovery_pubkey_jwk),
          active_device_pubkey_jwk: JSON.stringify(new_device_pubkey_jwk),
          join_delta_sec,
          reclaim_nonce: 0,
          last_reclaim_utc_ms: 0,
          updated_at_ms: now,
          created_at_ms: now,
        });
      } else {
        const locked = existing.recovery_pubkey_jwk;
        const provided = JSON.stringify(recovery_pubkey_jwk);
        if (locked !== provided) return bad("recovery_pubkey_jwk mismatch (locked)");
      }

      const acc = await getAccount(env.DB, account_id);
      const recPub = importJwkPublicKey(acc.recovery_pubkey_jwk);

      const newDevHash = stableHashJwk(new_device_pubkey_jwk);
      const msg = msgReclaimV1({
        chainId: CHAIN_ID,
        account_id,
        new_device_pubkey_jwk_hash: newDevHash,
        reclaim_nonce,
        last_utc_ms,
        counter,
      });

      const okSig = verifyEd25519(recPub, u8(msg), b64ToU8(sig_b64));
      if (!okSig) return bad("Invalid reclaim signature");

      const changed = await updateReclaim(env.DB, {
        account_id,
        new_device_pubkey_jwk: JSON.stringify(new_device_pubkey_jwk),
        reclaim_nonce,
        last_reclaim_utc_ms: last_utc_ms,
        now_ms: now,
      });

      if (changed !== 1) return bad("Reclaim rejected (nonce mismatch or already applied)", 409);

      return json({ ok: true, account_id, reclaim_nonce, frozen_old_device: true });
    }

    // ---- Apply segment updates (state-only) ----
    if (req.method === "POST" && path === "/v1/segments/apply") {
      let body;
      try { body = await req.json(); } catch { return bad("Invalid JSON"); }

      const now = Date.now();
      const updates = Array.isArray(body.updates) ? body.updates : null;
      if (!updates || updates.length === 0) return bad("updates[] required");
      if (updates.length > MAX_BATCH) return bad(`Too many updates (max ${MAX_BATCH})`);

      for (const seg of updates) {
        const required = [
          "origin_account_id",
          "segment_no",
          "previous_account_id",
          "current_account_id",
          "last_utc_ms",
          "counter",
          "sig_b64",
        ];
        for (const k of required) {
          if (seg[k] === undefined || seg[k] === null) return bad(`Missing ${k}`);
        }

        seg.origin_account_id = String(seg.origin_account_id);
        seg.previous_account_id = String(seg.previous_account_id);
        seg.current_account_id = String(seg.current_account_id);
        seg.segment_no = asInt(seg.segment_no, "segment_no");
        seg.last_utc_ms = asInt(seg.last_utc_ms, "last_utc_ms");
        seg.counter = asInt(seg.counter, "counter");
        seg.sig_b64 = String(seg.sig_b64);

        try {
          enforceNotFuture(seg.last_utc_ms, now, MAX_FUTURE_SKEW_MS);
          enforceUtcCounterMatch(seg.last_utc_ms, seg.counter, GENESIS_UTC_MS);
        } catch (e) {
          return bad(e.message);
        }

        // previous owner must exist and have an active device key
        const prevAccount = await getAccount(env.DB, seg.previous_account_id);
        if (!prevAccount) return bad(`Unknown previous_account_id: ${seg.previous_account_id}`);

        const devPub = importJwkPublicKey(prevAccount.active_device_pubkey_jwk);
        const msg = msgSegmentUpdateV1({
          chainId: CHAIN_ID,
          origin_account_id: seg.origin_account_id,
          segment_no: seg.segment_no,
          previous_account_id: seg.previous_account_id,
          current_account_id: seg.current_account_id,
          last_utc_ms: seg.last_utc_ms,
          counter: seg.counter,
        });

        const okSig = verifyEd25519(devPub, u8(msg), b64ToU8(seg.sig_b64));
        if (!okSig) return bad("Invalid segment signature");

        const existing = await getSegment(env.DB, seg.origin_account_id, seg.segment_no);

        if (existing) {
          const advanced = await conditionalAdvanceSegment(env.DB, seg, now);
          if (advanced !== 1) return bad("Segment continuity failed (double-spend or stale)", 409);
        } else {
          if (seg.previous_account_id !== seg.origin_account_id) {
            return bad("First state of a segment must originate from origin_account_id", 409);
          }
          await upsertSegment(env.DB, seg, now);
        }

        // Explorer stat: track how many serials origin has activated
        await upsertOriginMax(env.DB, seg.origin_account_id, seg.segment_no, now);
      }

      return json({ ok: true, applied: updates.length });
    }

    return bad("Not found", 404);
  },
};
