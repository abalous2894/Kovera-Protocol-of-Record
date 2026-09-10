import { sha256HexUtf8 } from '../core/sha256.js';
import { CONFORMITY_CLOSURE_SCHEMA, buildConformityClosurePreimage, evaluateConformityClosureSignals } from '../core/conformityClosure.js';
import { stableStringify } from '../core/stableStringify.js';

export const CONFORMITY_CLOSURE_SKU = 'aevesa-conformity-closure-v1' as const;

export interface ConformityClosureDocument {
  schema?: string;
  obligation_id?: string;
  organization_id?: string;
  live_signal_count?: number;
  signal_threshold?: number;
  lookback_days?: number;
  closure_test_id?: string;
  gap_score_before?: number;
  gap_score_after?: number;
  closed_at?: string;
  closure_entry_hash?: string | null;
  closure_digest?: string;
  export_pack?: { type?: string; path?: string; label?: string } | null;
  contributing_entry_hashes?: string[];
}

export interface ConformityClosureVerifyOptions {
  requireClosureEntryHash?: boolean;
}

export interface ConformityClosureVerifyResult {
  schema: typeof CONFORMITY_CLOSURE_SCHEMA;
  sku: typeof CONFORMITY_CLOSURE_SKU;
  ok: boolean;
  checks: {
    schemaValid: boolean;
    organizationIdPresent: boolean;
    obligationIdPresent: boolean;
    signalsMeetThreshold: boolean;
    gapScoreAfterZero: boolean;
    closureDigestMatches: boolean;
    closureEntryHashPresent: boolean;
    profileComplete: boolean;
  };
  gtmLine: string;
  note: string | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

export function verifyConformityClosureBundle(
  input: unknown,
  options: ConformityClosureVerifyOptions = {},
): ConformityClosureVerifyResult {
  const doc = asRecord(input) as ConformityClosureDocument | null;
  const schemaValid = doc?.schema === CONFORMITY_CLOSURE_SCHEMA;
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;
  const obligationIdPresent = String(doc?.obligation_id || '').trim().length > 0;

  const live = Number(doc?.live_signal_count) || 0;
  const threshold = Math.max(1, Number(doc?.signal_threshold) || 1);
  const signalEval = evaluateConformityClosureSignals({
    live_signal_count: live,
    signal_threshold: threshold,
  });
  const signalsMeetThreshold = signalEval.canClose;

  const gapScoreAfterZero = Number(doc?.gap_score_after) === 0;

  let closureDigestMatches = false;
  if (organizationIdPresent && obligationIdPresent && doc?.closed_at) {
    const expected = sha256HexUtf8(
      stableStringify(
        buildConformityClosurePreimage({
          obligation_id: String(doc.obligation_id),
          organization_id: String(doc.organization_id),
          live_signal_count: live,
          signal_threshold: threshold,
          lookback_days: Number(doc.lookback_days) || 90,
          closure_test_id: String(doc.closure_test_id || ''),
          gap_score_before: Number(doc.gap_score_before) || 0,
          closed_at: String(doc.closed_at),
          export_pack: doc.export_pack ?? null,
          contributing_entry_hashes: Array.isArray(doc.contributing_entry_hashes)
            ? doc.contributing_entry_hashes.map(String)
            : [],
        }),
      ),
    );
    closureDigestMatches = Boolean(doc.closure_digest) && doc!.closure_digest === expected;
  }

  const closureEntryHashPresent =
    options.requireClosureEntryHash !== true ||
    (typeof doc?.closure_entry_hash === 'string' && /^[a-f0-9]{64}$/.test(doc.closure_entry_hash));

  const profileComplete =
    schemaValid &&
    organizationIdPresent &&
    obligationIdPresent &&
    signalsMeetThreshold &&
    gapScoreAfterZero &&
    closureDigestMatches &&
    closureEntryHashPresent;

  let note: string | null = null;
  if (profileComplete) {
    note = 'Conformity closure verified — obligation met live signal threshold offline';
  } else if (!signalsMeetThreshold) {
    note = `live_signal_count ${live} below signal_threshold ${threshold}`;
  } else if (!closureDigestMatches) {
    note = 'closure_digest does not match closure preimage';
  } else if (!gapScoreAfterZero) {
    note = 'gap_score_after must be 0 on successful closure';
  } else {
    note = 'Conformity closure verification failed';
  }

  return {
    schema: CONFORMITY_CLOSURE_SCHEMA,
    sku: CONFORMITY_CLOSURE_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      organizationIdPresent,
      obligationIdPresent,
      signalsMeetThreshold,
      gapScoreAfterZero,
      closureDigestMatches,
      closureEntryHashPresent,
      profileComplete,
    },
    gtmLine:
      'Live gap score → automated evidence pack. EU AI Act as a product loop, not a consulting project.',
    note,
  };
}
