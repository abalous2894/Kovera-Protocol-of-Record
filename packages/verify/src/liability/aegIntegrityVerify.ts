import {
  AEG_INTEGRITY_SCHEMA,
  AEG_INTEGRITY_CHECKS,
  AEG_CHECK_RESULTS,
  AEG_STRUCTURAL_SOURCES,
  computeAegIntegrityDigest,
  type AegIntegrityCheckEvaluated,
  type AegStructuralSource,
} from '../core/aegIntegrity.js';

export const AEG_INTEGRITY_SKU = 'aevesa-aeg-integrity-v1' as const;

export interface AegIntegrityDocument {
  schema?: string;
  session_id?: string;
  decision_id?: string;
  edge?: number;
  checks_evaluated?: AegIntegrityCheckEvaluated[];
  environmental_digest?: string;
  delegated_digest?: string;
  aeg_integrity_digest?: string;
}

export interface AegIntegrityVerifyOptions {
  requireFailureAttribution?: boolean;
}

export interface AegIntegrityVerifyChecks {
  schemaValid: boolean;
  sessionIdPresent: boolean;
  edgeValid: boolean;
  checksPresent: boolean;
  checksValid: boolean;
  digestMatches: boolean;
  failureSourceAttributed: boolean;
  profileComplete: boolean;
}

export interface AegIntegrityVerifyResult {
  schema: typeof AEG_INTEGRITY_SCHEMA;
  sku: typeof AEG_INTEGRITY_SKU;
  ok: boolean;
  checks: AegIntegrityVerifyChecks;
  gtmLine: string;
  note: string | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function parseChecks(raw: unknown): AegIntegrityCheckEvaluated[] {
  if (!Array.isArray(raw)) return [];
  const out: AegIntegrityCheckEvaluated[] = [];
  for (const item of raw) {
    const rec = asRecord(item);
    if (!rec) continue;
    const check = String(rec.check || '').trim();
    const result = String(rec.result || '').trim();
    if (!AEG_INTEGRITY_CHECKS.includes(check as AegIntegrityCheckEvaluated['check'])) continue;
    if (!AEG_CHECK_RESULTS.includes(result as AegIntegrityCheckEvaluated['result'])) continue;
    const sourceRaw = rec.source != null ? String(rec.source).trim() : null;
    const source =
      sourceRaw && AEG_STRUCTURAL_SOURCES.includes(sourceRaw as AegStructuralSource)
        ? (sourceRaw as AegStructuralSource)
        : undefined;
    out.push({
      check: check as AegIntegrityCheckEvaluated['check'],
      result: result as AegIntegrityCheckEvaluated['result'],
      ...(source ? { source } : {}),
      ...(rec.detail ? { detail: String(rec.detail).slice(0, 256) } : {}),
    });
  }
  return out;
}

/**
 * Verify AEG source-attributed integrity manifest — post-incident root-cause attribution.
 */
export function verifyAegIntegrityBundle(
  input: unknown,
  options: AegIntegrityVerifyOptions = {},
): AegIntegrityVerifyResult {
  const doc = asRecord(input) as AegIntegrityDocument | null;
  const schemaValid = doc?.schema === AEG_INTEGRITY_SCHEMA;
  const session_id = String(doc?.session_id || '').trim();
  const sessionIdPresent = session_id.length > 0;
  const edge = Number(doc?.edge);
  const edgeValid = edge >= 2 && edge <= 5;

  const checks_evaluated = parseChecks(doc?.checks_evaluated);
  const checksPresent = checks_evaluated.length > 0;
  const checksValid = checks_evaluated.every((c) => {
    if (c.result === 'FAIL' && options.requireFailureAttribution === true) {
      return Boolean(c.source);
    }
    return true;
  });

  let digestMatches = false;
  if (sessionIdPresent && checksPresent && edgeValid) {
    const expected = computeAegIntegrityDigest({
      session_id,
      decision_id: doc?.decision_id,
      edge,
      checks_evaluated,
      environmental_digest: doc?.environmental_digest,
      delegated_digest: doc?.delegated_digest,
    });
    digestMatches = Boolean(doc?.aeg_integrity_digest) && doc!.aeg_integrity_digest === expected;
  }

  const hasFailure = checks_evaluated.some((c) => c.result === 'FAIL');
  const failureSourceAttributed =
    !hasFailure || checks_evaluated.some((c) => c.result === 'FAIL' && c.source);

  const profileComplete =
    schemaValid &&
    sessionIdPresent &&
    edgeValid &&
    checksPresent &&
    checksValid &&
    digestMatches &&
    failureSourceAttributed;

  let note: string | null = null;
  if (profileComplete) {
    note = 'AEG integrity verified — structural source attribution bound at decision edge';
  } else if (!digestMatches) {
    note = 'aeg_integrity_digest does not match canonical checks preimage';
  } else if (hasFailure && !failureSourceAttributed) {
    note = 'FAIL checks require aeg structural source (A, B, or C) attribution';
  } else {
    note = 'AEG integrity profile verification failed';
  }

  return {
    schema: AEG_INTEGRITY_SCHEMA,
    sku: AEG_INTEGRITY_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      sessionIdPresent,
      edgeValid,
      checksPresent,
      checksValid,
      digestMatches,
      failureSourceAttributed,
      profileComplete,
    },
    gtmLine:
      'Same failure, three sources. Aevesa AEG integrity attributes channel corruption vs delegation vs composition — offline.',
    note,
  };
}
