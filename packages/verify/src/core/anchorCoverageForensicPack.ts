import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';
import { ATTRIBUTION_ANCHOR_IDS } from './anchorCoverageAnchors.js';

export const ANCHOR_COVERAGE_FORENSIC_PACK_SCHEMA =
  'aevesa.anchor-coverage-forensic-pack/v1' as const;

export type AnchorCoverageStatus = 'pass' | 'fail' | 'partial' | 'unknown';

export type AttributionReadiness = 'attribution_ready' | 'partial' | 'insufficient';

export interface AnchorCoverageEvaluationInput {
  anchor_id: string;
  label: string;
  status: AnchorCoverageStatus;
  evidence_refs: string[];
  member_digest?: string | null;
  notes?: string | null;
}

export interface ComposedAnchorEvidenceInput {
  delegation_chain_digest: string | null;
  memory_commitment_digest: string | null;
  tool_manifest_fingerprint_digest: string | null;
  hitl_receipt_digest: string | null;
  input_provenance_entry_hash: string | null;
  witness_samples_ok: number;
  material_receipt_count: number;
}

export interface AnchorCoverageForensicPackInput {
  organization_id: string;
  session_id: string;
  generated_at?: string;
  incident_ref?: string | null;
  formal_attribution_ref?: string;
  anchor_coverage_evaluation: AnchorCoverageEvaluationInput[];
  composed_anchor_evidence: ComposedAnchorEvidenceInput;
  composed_members: Array<{
    member_schema: string;
    member_digest: string;
    verify_ok: boolean;
    label: string;
    entry_count?: number | null;
  }>;
  disclaimer?: string;
}



function countByStatus(
  rows: AnchorCoverageEvaluationInput[],
  status: AnchorCoverageStatus,
): number {
  return rows.filter((e) => e.status === status).length;
}

export function deriveAttributionReadiness(
  evals: AnchorCoverageEvaluationInput[],
): AttributionReadiness {
  const pass = countByStatus(evals, 'pass');
  const fail = countByStatus(evals, 'fail');
  if (fail === 0 && pass >= 4) return 'attribution_ready';
  if (fail >= 3) return 'insufficient';
  return 'partial';
}

export interface AnchorCoverageMetricsSnapshot {
  delegation_chain_digest?: string | null;
  delegation_chain_verify_ok?: boolean;
  memory_commitment_digest?: string | null;
  memory_commitment_verify_ok?: boolean;
  tool_manifest_fingerprint_digest?: string | null;
  tool_manifest_verify_ok?: boolean;
  hitl_receipt_digest?: string | null;
  hitl_present?: boolean;
  input_provenance_entry_hash?: string | null;
  witness_samples_ok?: number;
  material_receipt_count?: number;
}

/**
 * Evaluate five anchor classes from hash-only metrics snapshot.
 */
export function evaluateAnchorCoverageFromMetrics(
  metrics: AnchorCoverageMetricsSnapshot,
): AnchorCoverageEvaluationInput[] {
  const delegationOk =
    metrics.delegation_chain_verify_ok === true &&
    typeof metrics.delegation_chain_digest === 'string' &&
    /^[a-f0-9]{64}$/.test(metrics.delegation_chain_digest);

  const memoryOk =
    metrics.memory_commitment_verify_ok === true &&
    typeof metrics.memory_commitment_digest === 'string' &&
    /^[a-f0-9]{64}$/.test(metrics.memory_commitment_digest);

  const manifestOk =
    metrics.tool_manifest_verify_ok === true &&
    typeof metrics.tool_manifest_fingerprint_digest === 'string' &&
    /^[a-f0-9]{64}$/.test(metrics.tool_manifest_fingerprint_digest);

  const hitlOk =
    metrics.hitl_present === true ||
    (typeof metrics.hitl_receipt_digest === 'string' &&
      /^[a-f0-9]{64}$/.test(metrics.hitl_receipt_digest));

  const provenanceHash = metrics.input_provenance_entry_hash;
  const witnessOk = Number(metrics.witness_samples_ok) || 0;
  const provenanceStatus: AnchorCoverageStatus =
    provenanceHash && /^[a-f0-9]{64}$/.test(provenanceHash)
      ? witnessOk > 0
        ? 'pass'
        : 'partial'
      : 'fail';

  const byId: Record<string, AnchorCoverageEvaluationInput> = {
    input_provenance: {
      anchor_id: 'input_provenance',
      label: 'Exogenous input provenance (ledger anchor + witness path)',
      status: provenanceStatus,
      evidence_refs: [
        'proof.primary_anchor.entry_hash',
        'aevesa.witness-cosign-verify/v1',
      ],
      member_digest: provenanceHash ?? null,
      notes: provenanceHash
        ? witnessOk > 0
          ? `${witnessOk} witness cosign sample(s) OK on ledger anchor.`
          : 'Ledger anchor present; witness cosign samples absent.'
        : 'No exogenous ledger anchor on material action record.',
    },
    authenticated_delegation: {
      anchor_id: 'authenticated_delegation',
      label: 'Authenticated delegation chain at intercept',
      status: delegationOk ? 'pass' : metrics.delegation_chain_digest ? 'partial' : 'fail',
      evidence_refs: ['kovera-delegation-chain/1', 'aevesa.delegation-chain-live-export/v1'],
      member_digest: metrics.delegation_chain_digest ?? null,
      notes: delegationOk
        ? 'Live delegation chain verified offline.'
        : 'Delegation chain digest missing or verify failed.',
    },
    internal_state_probe: {
      anchor_id: 'internal_state_probe',
      label: 'Internal-state probe (memory commitment at material action)',
      status: memoryOk ? 'pass' : metrics.memory_commitment_digest ? 'partial' : 'fail',
      evidence_refs: ['aevesa.memory-commitment/v1', 'liability-receipt/v1.memory_commitment'],
      member_digest: metrics.memory_commitment_digest ?? null,
      notes: memoryOk
        ? 'Memory root hash bound at material-action intercept (ASI06).'
        : 'Memory commitment extension absent or verify failed.',
    },
    execution_context: {
      anchor_id: 'execution_context',
      label: 'Execution context bind (MCP manifest fingerprint at invoke)',
      status: manifestOk ? 'pass' : metrics.tool_manifest_fingerprint_digest ? 'partial' : 'fail',
      evidence_refs: [
        'aevesa.tool-manifest-fingerprint/v1',
        'liability-receipt/v1.tool_manifest_fingerprint',
      ],
      member_digest: metrics.tool_manifest_fingerprint_digest ?? null,
      notes: manifestOk
        ? 'AttestMCP manifest fingerprint bound at tool invoke (ASI04).'
        : 'Tool manifest fingerprint absent or verify failed.',
    },
    human_oversight: {
      anchor_id: 'human_oversight',
      label: 'Human oversight anchor (HITL receipt or release)',
      status: hitlOk ? 'pass' : 'unknown',
      evidence_refs: ['liability-receipt/v1.hitl', 'aevesa.hitl-release-receipt/v1'],
      member_digest: metrics.hitl_receipt_digest ?? null,
      notes: hitlOk
        ? 'HITL block or release receipt present on forensic material action.'
        : 'No HITL anchor on indexed material receipts (may be acceptable for low-risk paths).',
    },
  };

  return ATTRIBUTION_ANCHOR_IDS.map((id) => byId[id]);
}

export function buildAnchorCoverageForensicPackPreimage(
  input: Omit<AnchorCoverageForensicPackInput, 'disclaimer'> & {
    generated_at: string;
    attribution_readiness: AttributionReadiness;
  },
): Record<string, unknown> {
  const composed = input.composed_anchor_evidence;
  return {
    schema: ANCHOR_COVERAGE_FORENSIC_PACK_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    session_id: String(input.session_id || '').trim(),
    generated_at: input.generated_at,
    incident_ref: input.incident_ref ?? null,
    formal_attribution_ref:
      input.formal_attribution_ref ||
      'tamper-evident-not-trustworthy-2026-anchor-coverage-construct',
    anchor_coverage_evaluation: input.anchor_coverage_evaluation.map((row) => ({
      anchor_id: row.anchor_id,
      label: row.label,
      status: row.status,
      evidence_refs: [...(row.evidence_refs || [])].sort(),
      member_digest: row.member_digest ?? null,
      notes: row.notes ?? null,
    })),
    composed_anchor_evidence: {
      delegation_chain_digest: composed.delegation_chain_digest ?? null,
      memory_commitment_digest: composed.memory_commitment_digest ?? null,
      tool_manifest_fingerprint_digest: composed.tool_manifest_fingerprint_digest ?? null,
      hitl_receipt_digest: composed.hitl_receipt_digest ?? null,
      input_provenance_entry_hash: composed.input_provenance_entry_hash ?? null,
      witness_samples_ok: Number(composed.witness_samples_ok) || 0,
      material_receipt_count: Number(composed.material_receipt_count) || 0,
      anchors_pass_count: countByStatus(input.anchor_coverage_evaluation, 'pass'),
      anchors_fail_count: countByStatus(input.anchor_coverage_evaluation, 'fail'),
      anchors_partial_count: countByStatus(input.anchor_coverage_evaluation, 'partial'),
    },
    composed_members: [...(input.composed_members || [])]
      .map((m) => ({
        member_schema: String(m.member_schema || '').trim(),
        member_digest: String(m.member_digest || '').trim().toLowerCase(),
        verify_ok: m.verify_ok === true,
        label: String(m.label || '').trim(),
        entry_count: m.entry_count != null ? Number(m.entry_count) : null,
      }))
      .sort((a, b) => a.member_schema.localeCompare(b.member_schema)),
    attribution_readiness: input.attribution_readiness,
  };
}

export function buildAnchorCoverageForensicPackDocument(input: AnchorCoverageForensicPackInput) {
  const generated_at = input.generated_at || new Date().toISOString();
  const attribution_readiness = deriveAttributionReadiness(input.anchor_coverage_evaluation);
  const preimage = buildAnchorCoverageForensicPackPreimage({
    ...input,
    generated_at,
    attribution_readiness,
  });
  const pack_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    disclaimer:
      input.disclaimer ||
      'Anchor coverage forensic alignment — not legal attribution, loss adjustment, or expert witness opinion.',
    pack_digest,
  };
}

export { ATTRIBUTION_ANCHOR_IDS };
