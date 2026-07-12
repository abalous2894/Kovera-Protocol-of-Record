/**
 * Narrow unknown JSON values to plain objects (excludes null and arrays).
 * Canonical owner — re-exported from @aevesa/shared (Phase 7).
 */
export function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}
