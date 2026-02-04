-- Account registry: recoverable identity + currently active device liveness key
CREATE TABLE IF NOT EXISTS accounts (
  account_id TEXT PRIMARY KEY,
  recovery_pubkey_jwk TEXT NOT NULL,
  active_device_pubkey_jwk TEXT NOT NULL,
  join_delta_sec INTEGER NOT NULL,
  reclaim_nonce INTEGER NOT NULL,
  last_reclaim_utc_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  created_at_ms INTEGER NOT NULL
);

-- Segment state only (no history)
CREATE TABLE IF NOT EXISTS segments (
  origin_account_id TEXT NOT NULL,
  segment_no INTEGER NOT NULL,

  previous_account_id TEXT NOT NULL,
  current_account_id TEXT NOT NULL,

  last_utc_ms INTEGER NOT NULL,
  counter INTEGER NOT NULL,

  sig_b64 TEXT NOT NULL,
  updated_at_ms INTEGER NOT NULL,

  PRIMARY KEY(origin_account_id, segment_no)
);

CREATE INDEX IF NOT EXISTS idx_segments_by_current_owner
  ON segments(current_account_id);

CREATE INDEX IF NOT EXISTS idx_segments_by_origin
  ON segments(origin_account_id);

-- Explorer helper: "how many serials has this origin activated?"
CREATE TABLE IF NOT EXISTS origin_stats (
  origin_account_id TEXT PRIMARY KEY,
  max_segment_no INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL
);
