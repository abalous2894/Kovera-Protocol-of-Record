import { sha256HexUtf8 } from '../core/sha256.js';
import { ANCHOR_COVERAGE_FORENSIC_PACK_SCHEMA, ATTRIBUTION_ANCHOR_IDS } from '../core/anchorCoverageForensicPack.js';
import { stableStringify } from '../core/stableStringify.js';
import type {
  AnchorCoverageStatus,
  AttributionReadiness,
} from '../core/anchorCoverageForensicPack.js';

export const ANCHOR_COVERAGE_FORENSIC_PACK_SKU =
  'aevesa-anchor-coverage-forensic-pack-v1' as const;

const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|ssn|phone|address)$/i;
const HEX64 = /^[a-f0-9]{64}$/;

export interface AnchorCoverageForensicPackDocument {
  schema?: string;
  organization_id?: string;
  session_id?: string;
  generated_at?: string;
  incident_ref?: string | null;
  formal_attribution_ref?: string;
  anchor_coverage_evaluation?: Array<{
    anchor_id?: string;
    label?: string;
    status?: AnchorCoverageStatus;
    evidence_refs?: string[];
    member_digest?: string | null;
    notes?: string | null;
  }>;
  composed_anchor_evidence?: Record<string, unknown>;
  composed_members?: Array<Record<string, unknown>>;
  attribution_readiness?: AttributionReadiness;
  pack_digest?: string;
}

export interface AnchorCoverageForensicPackVerifyChecks {
  schemaValid: boolean;
  organizationIdPresent: boolean;
  sessionIdPresent: boolean;
  fiveAnchorsComplete: boolean;
  composedEvidencePresent: boolean;
  packDigestMatches: boolean;
  hashOnlySurface: boolean;
  readinessConsistent: boolean;
  profileComplete: boolean;
}

export interface AnchorCoverageForensicPackVerifyResult {
  schema: typeof ANCHOR_COVERAGE_FORENSIC_PACK_SCHEMA;
  sku: typeof ANCHOR_COVERAGE_FORENSIC_PACK_SKU;
  ok: boolean;
  checks: AnchorCoverageForensicPackVerifyChecks;
  anchors_pass_count: number;
  anchors_fail_count: number;
  attribution_readiness: AttributionReadiness | null;
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
  rows: AnchorCoverageForensicPackDocument['anchor_coverage_evaluation'],
  status: AnchorCoverageStatus,
): number {
  return (rows || []).filter((r) => r?.status === status).length;
}

export function verifyAnchorCoverageForensicPack(
  docInput: unknown,
): AnchorCoverageForensicPackVerifyResult {
  const doc = asRecord(docInput) as AnchorCoverageForensicPackDocument | null;
  const schemaValid = doc?.schema === ANCHOR_COVERAGE_FORENSIC_PACK_SCHEMA;
  const organizationIdPresent = Boolean(String(doc?.organization_id || '').trim());
  const sessionIdPresent = Boolean(String(doc?.session_id || '').trim());

  const evals = doc?.anchor_coverage_evaluation || [];
  const ids = new Set(evals.map((e) => e?.anchor_id).filter(Boolean));
  const fiveAnchorsComplete =
    evals.length === 5 && ATTRIBUTION_ANCHOR_IDS.every((id) => ids.has(id));

  const composed = asRecord(doc?.composed_anchor_evidence);
  const composedEvidencePresent =
    composed != null &&
    (typeof composed.delegation_chain_digest === 'string' ||
      typeof composed.memory_commitment_digest === 'string' ||
      typeof composed.tool_manifest_fingerprint_digest === 'string');

  let packDigestMatches = false;
  if (doc && typeof doc.pack_digest === 'string' && HEX64.test(doc.pack_digest)) {
    const { pack_digest, disclaimer: _d, member_documents: _md, ...rest } = doc as Record<string, unknown>;
    const recomputed = sha256HexUtf8(stableStringify(rest));
    packDigestMatches = recomputed === pack_digest;
  }

  const hashOnlyInput = asRecord(docInput);
  const { member_documents: _hashMemberDocs, ...hashOnlyDoc } = hashOnlyInput || {};
  const hashOnlySurface = !hasForbiddenKeys(hashOnlyDoc);
  const passCount = countStatus(evals, 'pass');
  const failCount = countStatus(evals, 'fail');
  const readiness = doc?.attribution_readiness ?? null;
  const readinessConsistent =
    readiness === 'attribution_ready'
      ? failCount === 0 && passCount >= 4
      : readiness === 'insufficient'
        ? failCount >= 3
        : readiness === 'partial'
          ? failCount < 3
          : false;

  const profileComplete =
    schemaValid &&
    organizationIdPresent &&
    sessionIdPresent &&
    fiveAnchorsComplete &&
    composedEvidencePresent &&
    packDigestMatches &&
    hashOnlySurface &&
    readinessConsistent;

  return {
    schema: ANCHOR_COVERAGE_FORENSIC_PACK_SCHEMA,
    sku: ANCHOR_COVERAGE_FORENSIC_PACK_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      organizationIdPresent,
      sessionIdPresent,
      fiveAnchorsComplete,
      composedEvidencePresent,
      packDigestMatches,
      hashOnlySurface,
      readinessConsistent,
      profileComplete,
    },
    anchors_pass_count: passCount,
    anchors_fail_count: failCount,
    attribution_readiness: readiness,
    gtmLine:
      'Tamper-evident is not trustworthy. Aevesa binds the exogenous anchors attribution actually requires.',
    note: profileComplete
      ? 'Anchor coverage forensic pack verified offline.'
      : 'Anchor coverage forensic pack incomplete — see checks.',
  };
}

export default verifyAnchorCoverageForensicPack;
