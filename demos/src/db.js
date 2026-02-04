export async function getAccount(DB, accountId) {
  return await DB.prepare(
    `SELECT account_id, recovery_pubkey_jwk, active_device_pubkey_jwk, join_delta_sec, reclaim_nonce, last_reclaim_utc_ms
       FROM accounts
      WHERE account_id = ?`
  ).bind(accountId).first();
}

export async function createAccountIfMissing(DB, row) {
  await DB.prepare(
    `INSERT INTO accounts
      (account_id, recovery_pubkey_jwk, active_device_pubkey_jwk, join_delta_sec, reclaim_nonce, last_reclaim_utc_ms, updated_at_ms, created_at_ms)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(account_id) DO NOTHING`
  ).bind(
    row.account_id,
    row.recovery_pubkey_jwk,
    row.active_device_pubkey_jwk,
    row.join_delta_sec,
    row.reclaim_nonce,
    row.last_reclaim_utc_ms,
    row.updated_at_ms,
    row.created_at_ms
  ).run();
}

export async function updateReclaim(DB, { account_id, new_device_pubkey_jwk, reclaim_nonce, last_reclaim_utc_ms, now_ms }) {
  const res = await DB.prepare(
    `UPDATE accounts
        SET active_device_pubkey_jwk = ?,
            reclaim_nonce = ?,
            last_reclaim_utc_ms = ?,
            updated_at_ms = ?
      WHERE account_id = ?
        AND reclaim_nonce = ?`
  ).bind(
    new_device_pubkey_jwk,
    reclaim_nonce,
    last_reclaim_utc_ms,
    now_ms,
    account_id,
    reclaim_nonce - 1
  ).run();

  return res.meta.changes || 0;
}

export async function getSegment(DB, origin, no) {
  return await DB.prepare(
    `SELECT origin_account_id, segment_no, previous_account_id, current_account_id, last_utc_ms, counter, sig_b64
       FROM segments
      WHERE origin_account_id = ? AND segment_no = ?`
  ).bind(origin, no).first();
}

export async function upsertSegment(DB, seg, now_ms) {
  await DB.prepare(
    `INSERT INTO segments
      (origin_account_id, segment_no, previous_account_id, current_account_id, last_utc_ms, counter, sig_b64, updated_at_ms)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(origin_account_id, segment_no) DO UPDATE SET
       previous_account_id = excluded.previous_account_id,
       current_account_id  = excluded.current_account_id,
       last_utc_ms         = excluded.last_utc_ms,
       counter             = excluded.counter,
       sig_b64             = excluded.sig_b64,
       updated_at_ms       = excluded.updated_at_ms`
  ).bind(
    seg.origin_account_id, seg.segment_no,
    seg.previous_account_id, seg.current_account_id,
    seg.last_utc_ms, seg.counter,
    seg.sig_b64, now_ms
  ).run();
}

export async function conditionalAdvanceSegment(DB, seg, now_ms) {
  const res = await DB.prepare(
    `UPDATE segments
        SET previous_account_id = ?,
            current_account_id  = ?,
            last_utc_ms         = ?,
            counter             = ?,
            sig_b64             = ?,
            updated_at_ms       = ?
      WHERE origin_account_id = ?
        AND segment_no = ?
        AND current_account_id = ?
        AND counter < ?
        AND last_utc_ms < ?`
  ).bind(
    seg.previous_account_id,
    seg.current_account_id,
    seg.last_utc_ms,
    seg.counter,
    seg.sig_b64,
    now_ms,
    seg.origin_account_id,
    seg.segment_no,
    seg.previous_account_id,
    seg.counter,
    seg.last_utc_ms
  ).run();

  return res.meta.changes || 0;
}

export async function listSegmentsByCurrentOwner(DB, accountId, limit, cursor) {
  const r = await DB.prepare(
    `SELECT origin_account_id, segment_no, previous_account_id, current_account_id, last_utc_ms, counter, sig_b64
       FROM segments
      WHERE current_account_id = ?
      ORDER BY origin_account_id, segment_no
      LIMIT ? OFFSET ?`
  ).bind(accountId, limit, cursor).all();
  return r.results || [];
}

export async function listSegmentsByOrigin(DB, originId, limit, cursor) {
  const r = await DB.prepare(
    `SELECT origin_account_id, segment_no, previous_account_id, current_account_id, last_utc_ms, counter, sig_b64
       FROM segments
      WHERE origin_account_id = ?
      ORDER BY segment_no
      LIMIT ? OFFSET ?`
  ).bind(originId, limit, cursor).all();
  return r.results || [];
}

// Explorer helpers
export async function upsertOriginMax(DB, originId, segmentNo, now_ms) {
  await DB.prepare(
    `INSERT INTO origin_stats (origin_account_id, max_segment_no, updated_at_ms)
     VALUES (?, ?, ?)
     ON CONFLICT(origin_account_id) DO UPDATE SET
       max_segment_no = CASE
         WHEN excluded.max_segment_no > origin_stats.max_segment_no THEN excluded.max_segment_no
         ELSE origin_stats.max_segment_no
       END,
       updated_at_ms = excluded.updated_at_ms`
  ).bind(originId, segmentNo, now_ms).run();
}

export async function getOriginStats(DB, originId) {
  return await DB.prepare(
    `SELECT origin_account_id, max_segment_no, updated_at_ms
       FROM origin_stats
      WHERE origin_account_id = ?`
  ).bind(originId).first();
}

export async function countAccounts(DB) {
  const r = await DB.prepare(`SELECT COUNT(*) as n FROM accounts`).first();
  return r?.n || 0;
}

export async function countSegments(DB) {
  const r = await DB.prepare(`SELECT COUNT(*) as n FROM segments`).first();
  return r?.n || 0;
}

export async function listAccounts(DB, limit, cursor) {
  const r = await DB.prepare(
    `SELECT account_id, join_delta_sec, reclaim_nonce, last_reclaim_utc_ms, active_device_pubkey_jwk
       FROM accounts
      ORDER BY account_id
      LIMIT ? OFFSET ?`
  ).bind(limit, cursor).all();
  return r.results || [];
}
