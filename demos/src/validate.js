export function asInt(v, name) {
  const n = Number(v);
  if (!Number.isFinite(n)) throw new Error(`Invalid ${name}`);
  return n;
}

export function expectedCounterFromUtc(lastUtcMs, genesisUtcMs) {
  return Math.floor((lastUtcMs - genesisUtcMs) / 1000);
}

export function enforceUtcCounterMatch(lastUtcMs, counter, genesisUtcMs) {
  const exp = expectedCounterFromUtc(lastUtcMs, genesisUtcMs);
  if (counter !== exp) {
    throw new Error(`counter/utc mismatch expected=${exp} got=${counter}`);
  }
}

export function enforceNotFuture(lastUtcMs, nowMs, maxSkewMs) {
  if (lastUtcMs > nowMs + maxSkewMs) {
    throw new Error("last_utc_ms too far in future");
  }
}
