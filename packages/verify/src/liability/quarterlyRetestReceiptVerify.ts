import { sha256HexUtf8 } from '../core/sha256.js';
import { buildQuarterlyRetestReceiptPreimage, evaluateTestRunsAllGreen, MAX_QUARTERLY_RETEST_CADENCE_DAYS, QUARTERLY_RETEST_RECEIPT_SCHEMA, type RetestReadiness } from '../core/quarterlyRetestReceipt.js';
import { stableStringify } from '../core/stableStringify.js';

export const QUARTERLY_RETEST_RECEIPT_SKU = 'aevesa-quarterly-retest-receipt-v1' as const;

const HEX64 = /^[a-f0-9]{64}$/;
const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|ssn|phone|address|pan|cvv)$/i;

export interface QuarterlyRetestReceiptVerifyResult {
  schema: typeof QUARTERLY_RETEST_RECEIPT_SCHEMA;
  sku: typeof QUARTERLY_RETEST_RECEIPT_SKU;
  ok: boolean;
  checks: Record<string, boolean>;
  retest_readiness: RetestReadiness | null;
  gtmLine: string;
  note: string | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function hasForbiddenKeys(value: unknown, depth = 0): boolean {
  if (depth > 8 || value == null) return false;
  if (Array.isArray(value)) return value.some((v) => hasForbiddenKeys(v, depth + 1));
  if (typeof value !== 'object') return false;
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (FORBIDDEN_KEYS.test(key)) return true;
    if (hasForbiddenKeys(child, depth + 1)) return true;
  }
  return false;
}

export function verifyQuarterlyRetestReceipt(
  docInput: unknown,
): QuarterlyRetestReceiptVerifyResult {
  const doc = asRecord(docInput);
  const schemaValid = doc?.schema === QUARTERLY_RETEST_RECEIPT_SCHEMA;
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;
  const periodLabelPresent = String(doc?.period_label || '').trim().length > 0;

  const runs = Array.isArray(doc?.test_runs) ? doc.test_runs : [];
  const runsPresent = runs.length >= 1;
  const runDigestsValid =
    runs.length === 0 ||
    runs.every((r) => HEX64.test(String(r?.run_digest || '').toLowerCase()));

  const orderedRuns = [...runs].sort(
    (a, b) => Date.parse(String(a?.ran_at)) - Date.parse(String(b?.ran_at)),
  );
  const latestRun = orderedRuns[orderedRuns.length - 1];
  const latestRunDigest = latestRun
    ? String(latestRun.run_digest || '').toLowerCase()
    : '';

  const binding = asRecord(doc?.retest_session_binding) || {};
  const normalizationBound = binding.normalization_bound === true;
  const bindingDigestsValid =
    (binding.previous_run_digest == null ||
      HEX64.test(String(binding.previous_run_digest || '').toLowerCase())) &&
    HEX64.test(String(binding.latest_run_digest || '').toLowerCase());

  const bindingMatchesRuns =
    String(binding.period_label || '') === String(doc?.period_label || '') &&
    String(binding.latest_run_digest || '').toLowerCase() === latestRunDigest;

  const assertions = asRecord(doc?.cadence_assertions) || {};
  const derivedReadiness = String(assertions.retest_readiness || '') as RetestReadiness;

  const computedAllGreen = evaluateTestRunsAllGreen(
    runs.map((r) => ({
      suite_id: String(r?.suite_id || ''),
      run_digest: String(r?.run_digest || ''),
      ran_at: String(r?.ran_at || ''),
      checks_passed: Number(r?.checks_passed) || 0,
      checks_total: Number(r?.checks_total) || 0,
    })),
  );

  const daysSincePrevious = Number(assertions.days_since_previous);
  const cadenceWithinQuarter =
    Number.isFinite(daysSincePrevious) &&
    daysSincePrevious <= MAX_QUARTERLY_RETEST_CADENCE_DAYS;

  let cadenceAssertionsConsistent =
    assertions.third_party_verifiable === true && periodLabelPresent;

  if (derivedReadiness === 'cert_maintenance_ready') {
    cadenceAssertionsConsistent =
      cadenceAssertionsConsistent &&
      assertions.cadence_within_quarter === true &&
      assertions.all_suites_green === true &&
      cadenceWithinQuarter &&
      computedAllGreen &&
      bindingMatchesRuns &&
      normalizationBound;
  } else if (derivedReadiness === 'partial') {
    cadenceAssertionsConsistent =
      cadenceAssertionsConsistent &&
      cadenceWithinQuarter &&
      bindingMatchesRuns;
  } else if (derivedReadiness === 'stale') {
    cadenceAssertionsConsistent =
      cadenceAssertionsConsistent &&
      (assertions.cadence_within_quarter === false || !cadenceWithinQuarter);
  }

  const readinessConsistent = assertions.retest_readiness === derivedReadiness;

  let packDigestMatches = false;
  if (schemaValid && doc && bindingDigestsValid && bindingMatchesRuns && runsPresent) {
    const preimage = buildQuarterlyRetestReceiptPreimage({
      organization_id: String(doc.organization_id),
      period_label: String(doc.period_label),
      generated_at: String(doc.generated_at || ''),
      test_runs: runs.map((r) => ({
        suite_id: String(r?.suite_id || ''),
        run_digest: String(r?.run_digest || ''),
        ran_at: String(r?.ran_at || ''),
        checks_passed: Number(r?.checks_passed) || 0,
        checks_total: Number(r?.checks_total) || 0,
      })),
      cadence_assertions: {
        days_since_previous: assertions.days_since_previous as number | null,
        cadence_within_quarter: assertions.cadence_within_quarter === true,
        all_suites_green: assertions.all_suites_green === true,
        third_party_verifiable: assertions.third_party_verifiable === true,
        retest_readiness: derivedReadiness,
        max_cadence_days: Number(assertions.max_cadence_days) || MAX_QUARTERLY_RETEST_CADENCE_DAYS,
        suite_count: Number(assertions.suite_count) || runs.length,
      },
      retest_session_binding: {
        period_label: String(binding.period_label || ''),
        previous_run_digest: binding.previous_run_digest
          ? String(binding.previous_run_digest).toLowerCase()
          : null,
        latest_run_digest: String(binding.latest_run_digest || ''),
        normalization_bound: normalizationBound,
      },
    });
    const expected = sha256HexUtf8(stableStringify(preimage));
    packDigestMatches = String(doc.pack_digest || '').toLowerCase() === expected;
  }

  const hashOnlySurface = !hasForbiddenKeys(doc);

  const profileComplete =
    schemaValid &&
    organizationIdPresent &&
    periodLabelPresent &&
    runsPresent &&
    runDigestsValid &&
    computedAllGreen === (assertions.all_suites_green === true) &&
    cadenceWithinQuarter === (assertions.cadence_within_quarter === true) &&
    bindingMatchesRuns &&
    bindingDigestsValid &&
    cadenceAssertionsConsistent &&
    packDigestMatches &&
    hashOnlySurface &&
    readinessConsistent &&
    derivedReadiness === 'cert_maintenance_ready';

  let note: string | null = null;
  if (!schemaValid) note = `schema must be ${QUARTERLY_RETEST_RECEIPT_SCHEMA}`;
  else if (!cadenceWithinQuarter && derivedReadiness !== 'stale')
    note = `cadence exceeds ${MAX_QUARTERLY_RETEST_CADENCE_DAYS}-day quarterly window`;
  else if (!computedAllGreen) note = 'not all test suites green — checks_passed must equal checks_total';
  else if (!bindingMatchesRuns) note = 'retest_session_binding must match latest test run digest';
  else if (!packDigestMatches) note = 'pack_digest does not match canonical preimage';
  else if (!cadenceAssertionsConsistent) note = 'cadence_assertions inconsistent with test runs or binding';

  return {
    schema: QUARTERLY_RETEST_RECEIPT_SCHEMA,
    sku: QUARTERLY_RETEST_RECEIPT_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      organizationIdPresent,
      periodLabelPresent,
      runsPresent,
      runDigestsValid,
      computedAllGreen,
      cadenceWithinQuarter,
      bindingMatchesRuns,
      bindingDigestsValid,
      cadenceAssertionsConsistent,
      packDigestMatches,
      hashOnlySurface,
      readinessConsistent,
      profileComplete,
    },
    retest_readiness: derivedReadiness || null,
    gtmLine:
      'AIUC-1 re-tests your agent every quarter. Aevesa turns each run into a cryptographic receipt an auditor verifies offline.',
    note,
  };
}

export default { verifyQuarterlyRetestReceipt, QUARTERLY_RETEST_RECEIPT_SKU };
