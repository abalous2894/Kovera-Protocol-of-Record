import { sha256HexUtf8 } from '../core/sha256.js';
import { CARRIER_UNDERWRITING_EVIDENCE_PACK_SCHEMA, buildAccountableExecutiveAttestationDigest, CARRIER_SIX_CONTROL_IDS } from '../core/carrierUnderwritingEvidencePack.js';
import { stableStringify } from '../core/stableStringify.js';
import type { SixControlStatus } from '../core/carrierUnderwritingEvidencePack.js';

export const CARRIER_UNDERWRITING_EVIDENCE_PACK_SKU =
  'aevesa-carrier-underwriting-evidence-pack-v1' as const;

const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|ssn|phone|address)$/i;
const HEX64 = /^[a-f0-9]{64}$/;

export interface CarrierUnderwritingEvidencePackDocument {
  schema?: string;
  organization_id?: string;
  generated_at?: string;
  period_start?: string;
  period_end?: string;
  lookback_days?: number;
  six_control_evaluation?: Array<{
    control_id?: string;
    label?: string;
    status?: SixControlStatus;
    evidence_refs?: string[];
    notes?: string | null;
  }>;
  accountable_executive_attestation?: {
    required?: boolean;
    executive_id?: string | null;
    executive_display_name?: string | null;
    role_title?: string | null;
    attested_at?: string | null;
    attestation_statement?: string;
    attestation_digest?: string;
  };
  composed_evidence?: Record<string, unknown>;
  overall_readiness?: 'ready' | 'partial' | 'insufficient';
  pack_digest?: string;
}

export interface CarrierUnderwritingEvidencePackVerifyChecks {
  schemaValid: boolean;
  organizationIdPresent: boolean;
  periodValid: boolean;
  lookbackDaysValid: boolean;
  sixControlsComplete: boolean;
  executiveAttestationPresent: boolean;
  executiveAttestationDigestValid: boolean;
  packDigestMatches: boolean;
  hashOnlySurface: boolean;
  readinessConsistent: boolean;
  profileComplete: boolean;
}

export interface CarrierUnderwritingEvidencePackVerifyResult {
  schema: typeof CARRIER_UNDERWRITING_EVIDENCE_PACK_SCHEMA;
  sku: typeof CARRIER_UNDERWRITING_EVIDENCE_PACK_SKU;
  ok: boolean;
  checks: CarrierUnderwritingEvidencePackVerifyChecks;
  controls_pass_count: number;
  controls_fail_count: number;
  overall_readiness: string | null;
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
  if (Array.isArray(value)) {
    return value.some((v) => hasForbiddenKeys(v, depth + 1));
  }
  if (typeof value !== 'object') return false;
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (FORBIDDEN_KEYS.test(key)) return true;
    if (hasForbiddenKeys(child, depth + 1)) return true;
  }
  return false;
}

function countStatus(
  rows: CarrierUnderwritingEvidencePackDocument['six_control_evaluation'],
  status: SixControlStatus,
): number {
  return (rows || []).filter((r) => r?.status === status).length;
}

export function verifyCarrierUnderwritingEvidencePack(
  docInput: unknown,
): CarrierUnderwritingEvidencePackVerifyResult {
  const doc = asRecord(docInput) as CarrierUnderwritingEvidencePackDocument | null;
  const schemaValid = doc?.schema === CARRIER_UNDERWRITING_EVIDENCE_PACK_SCHEMA;
  const organizationIdPresent = Boolean(String(doc?.organization_id || '').trim());
  const periodValid =
    Boolean(String(doc?.period_start || '').trim()) && Boolean(String(doc?.period_end || '').trim());
  const lookbackDays = Number(doc?.lookback_days);
  const lookbackDaysValid = Number.isFinite(lookbackDays) && lookbackDays >= 7 && lookbackDays <= 365;

  const evals = doc?.six_control_evaluation || [];
  const ids = new Set(evals.map((e) => e?.control_id).filter(Boolean));
  const sixControlsComplete =
    evals.length === 6 && CARRIER_SIX_CONTROL_IDS.every((id) => ids.has(id));

  const att = doc?.accountable_executive_attestation;
  const executiveAttestationPresent =
    att?.required === true &&
    Boolean(String(att?.attestation_statement || '').trim()) &&
    typeof att?.attestation_digest === 'string' &&
    HEX64.test(att.attestation_digest);

  let executiveAttestationDigestValid = false;
  if (executiveAttestationPresent && doc?.organization_id) {
    const expected = buildAccountableExecutiveAttestationDigest({
      organization_id: String(doc.organization_id),
      executive_id: att?.executive_id ?? null,
      executive_display_name: att?.executive_display_name ?? null,
      role_title: att?.role_title ?? null,
      attested_at: att?.attested_at ?? null,
      attestation_statement: String(att?.attestation_statement || ''),
    });
    executiveAttestationDigestValid = expected === att?.attestation_digest;
  }

  let packDigestMatches = false;
  if (doc && typeof doc.pack_digest === 'string' && HEX64.test(doc.pack_digest)) {
    const { pack_digest, disclaimer: _d, ...rest } = doc as Record<string, unknown>;
    const recomputed = sha256HexUtf8(stableStringify(rest));
    packDigestMatches = recomputed === pack_digest;
  }

  const hashOnlySurface = !hasForbiddenKeys(docInput);
  const passCount = countStatus(evals, 'pass');
  const failCount = countStatus(evals, 'fail');
  const readiness = doc?.overall_readiness ?? null;
  const readinessConsistent =
    readiness === 'ready'
      ? failCount === 0 && passCount >= 5
      : readiness === 'insufficient'
        ? failCount >= 3
        : readiness === 'partial'
          ? failCount < 3
          : false;

  const profileComplete =
    schemaValid &&
    organizationIdPresent &&
    periodValid &&
    lookbackDaysValid &&
    sixControlsComplete &&
    executiveAttestationPresent &&
    executiveAttestationDigestValid &&
    packDigestMatches &&
    hashOnlySurface &&
    readinessConsistent;

  return {
    schema: CARRIER_UNDERWRITING_EVIDENCE_PACK_SCHEMA,
    sku: CARRIER_UNDERWRITING_EVIDENCE_PACK_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      organizationIdPresent,
      periodValid,
      lookbackDaysValid,
      sixControlsComplete,
      executiveAttestationPresent,
      executiveAttestationDigestValid,
      packDigestMatches,
      hashOnlySurface,
      readinessConsistent,
      profileComplete,
    },
    controls_pass_count: passCount,
    controls_fail_count: failCount,
    overall_readiness: readiness,
    gtmLine:
      'Silent AI coverage ended Jan 2026. Aevesa ships the six-control evidence pack carriers ask for - offline-verifiable, not a posture dashboard.',
    note: profileComplete
      ? 'Carrier underwriting evidence pack verified offline.'
      : 'Carrier underwriting pack incomplete — see checks.',
  };
}

export default verifyCarrierUnderwritingEvidencePack;
