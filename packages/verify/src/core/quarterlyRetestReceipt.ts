import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';

/** Wave 13 Track C — AIUC-1 quarterly technical re-test receipt. */

export const QUARTERLY_RETEST_RECEIPT_SCHEMA = 'aevesa.quarterly-retest-receipt/v1' as const;

/** AIUC-1 quarterly re-test cadence — 92 days (~13 weeks). */
export const MAX_QUARTERLY_RETEST_CADENCE_DAYS = 92;

export type RetestReadiness = 'cert_maintenance_ready' | 'partial' | 'stale';

export interface TestRunInput {
  suite_id: string;
  run_digest: string;
  ran_at: string;
  checks_passed: number;
  checks_total: number;
}

export interface CadenceAssertionsInput {
  previous_run_at: string | null;
  all_suites_green: boolean;
  third_party_verifiable: boolean;
}

export interface RetestSessionBinding {
  period_label: string;
  previous_run_digest: string | null;
  latest_run_digest: string;
  normalization_bound: boolean;
}

export interface QuarterlyRetestReceiptInput {
  organization_id: string;
  period_label: string;
  generated_at?: string;
  test_runs: TestRunInput[];
  cadence_assertions: CadenceAssertionsInput;
  retest_session_binding: RetestSessionBinding;
  disclaimer?: string;
}



export function computeDaysSincePrevious(
  previousRunAt: string | null | undefined,
  latestRunAt: string,
): number | null {
  if (!previousRunAt?.trim() || !latestRunAt?.trim()) return null;
  const prev = Date.parse(previousRunAt);
  const latest = Date.parse(latestRunAt);
  if (!Number.isFinite(prev) || !Number.isFinite(latest)) return null;
  const diffMs = latest - prev;
  if (diffMs < 0) return null;
  return Math.floor(diffMs / (24 * 60 * 60 * 1000));
}

export function deriveRetestReadiness(
  cadenceWithinQuarter: boolean,
  allSuitesGreen: boolean,
  runsPresent: boolean,
  thirdPartyVerifiable: boolean,
): RetestReadiness {
  if (!cadenceWithinQuarter) return 'stale';
  if (runsPresent && allSuitesGreen && thirdPartyVerifiable) return 'cert_maintenance_ready';
  if (runsPresent && (allSuitesGreen || cadenceWithinQuarter)) return 'partial';
  return 'stale';
}

export function evaluateTestRunsAllGreen(runs: TestRunInput[]): boolean {
  if (!runs.length) return false;
  return runs.every(
    (r) =>
      Number(r.checks_total) > 0 &&
      Number(r.checks_passed) === Number(r.checks_total),
  );
}

export function buildCadenceAssertionsBlock(
  input: CadenceAssertionsInput,
  runs: TestRunInput[],
) {
  const ordered = [...runs].sort(
    (a, b) => Date.parse(String(a.ran_at)) - Date.parse(String(b.ran_at)),
  );
  const latestRun = ordered[ordered.length - 1];
  const days_since_previous = computeDaysSincePrevious(
    input.previous_run_at,
    latestRun ? String(latestRun.ran_at) : '',
  );
  const cadence_within_quarter =
    days_since_previous != null && days_since_previous <= MAX_QUARTERLY_RETEST_CADENCE_DAYS;
  const computedAllGreen = evaluateTestRunsAllGreen(runs);
  const all_suites_green = computedAllGreen && input.all_suites_green !== false;

  const retest_readiness = deriveRetestReadiness(
    cadence_within_quarter,
    all_suites_green,
    runs.length > 0,
    input.third_party_verifiable === true,
  );

  return {
    days_since_previous,
    cadence_within_quarter,
    all_suites_green,
    third_party_verifiable: input.third_party_verifiable === true,
    retest_readiness,
    max_cadence_days: MAX_QUARTERLY_RETEST_CADENCE_DAYS,
    suite_count: runs.length,
  };
}

export function buildQuarterlyRetestReceiptPreimage(
  input: Omit<QuarterlyRetestReceiptInput, 'disclaimer' | 'cadence_assertions'> & {
    generated_at: string;
    cadence_assertions: ReturnType<typeof buildCadenceAssertionsBlock>;
    test_runs: TestRunInput[];
  },
): Record<string, unknown> {
  const runs = [...input.test_runs]
    .map((r) => ({
      suite_id: String(r.suite_id || '').trim(),
      run_digest: String(r.run_digest || '').trim().toLowerCase(),
      ran_at: String(r.ran_at || '').trim(),
      checks_passed: Number(r.checks_passed) || 0,
      checks_total: Number(r.checks_total) || 0,
    }))
    .sort((a, b) => a.suite_id.localeCompare(b.suite_id));

  const binding = input.retest_session_binding;

  return {
    schema: QUARTERLY_RETEST_RECEIPT_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    period_label: String(input.period_label || '').trim(),
    generated_at: input.generated_at,
    test_runs: runs,
    cadence_assertions: input.cadence_assertions,
    retest_session_binding: {
      period_label: String(binding.period_label || '').trim(),
      previous_run_digest: binding.previous_run_digest
        ? String(binding.previous_run_digest).trim().toLowerCase()
        : null,
      latest_run_digest: String(binding.latest_run_digest || '').trim().toLowerCase(),
      normalization_bound: binding.normalization_bound === true,
    },
  };
}

export interface QuarterlyRetestReceiptDocument {
  schema: typeof QUARTERLY_RETEST_RECEIPT_SCHEMA;
  organization_id: string;
  period_label: string;
  generated_at: string;
  test_runs: TestRunInput[];
  cadence_assertions: ReturnType<typeof buildCadenceAssertionsBlock>;
  retest_session_binding: RetestSessionBinding;
  disclaimer: string;
  pack_digest: string;
}

export function buildQuarterlyRetestReceiptDocument(
  input: QuarterlyRetestReceiptInput,
): QuarterlyRetestReceiptDocument {
  const generated_at = input.generated_at || new Date().toISOString();
  const cadence_assertions = buildCadenceAssertionsBlock(
    input.cadence_assertions,
    input.test_runs,
  );
  const preimage = buildQuarterlyRetestReceiptPreimage({
    ...input,
    generated_at,
    cadence_assertions,
    test_runs: input.test_runs,
  });
  const pack_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...(preimage as Omit<QuarterlyRetestReceiptDocument, 'pack_digest' | 'disclaimer'>),
    pack_digest,
    disclaimer:
      input.disclaimer ??
      'Quarterly re-test receipt for AIUC-1 cert maintenance — not legal advice or certification.',
  };
}

export default {
  QUARTERLY_RETEST_RECEIPT_SCHEMA,
  MAX_QUARTERLY_RETEST_CADENCE_DAYS,
  buildQuarterlyRetestReceiptDocument,
  buildCadenceAssertionsBlock,
  computeDaysSincePrevious,
  deriveRetestReadiness,
  evaluateTestRunsAllGreen,
};
