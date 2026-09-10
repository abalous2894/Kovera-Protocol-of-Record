import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';
import { CARRIER_SIX_CONTROL_IDS } from './carrierUnderwritingControls.js';

export const CARRIER_UNDERWRITING_EVIDENCE_PACK_SCHEMA =
  'aevesa.carrier-underwriting-evidence-pack/v1' as const;

export type SixControlStatus = 'pass' | 'fail' | 'partial' | 'unknown';

export interface SixControlEvaluationInput {
  control_id: string;
  label: string;
  status: SixControlStatus;
  evidence_refs: string[];
  notes?: string | null;
}

export interface AccountableExecutiveAttestationInput {
  executive_id?: string | null;
  executive_display_name?: string | null;
  role_title?: string | null;
  attested_at?: string | null;
  attestation_statement: string;
  organization_id: string;
}

export interface ComposedEvidenceInput {
  insurance_signal_digest_schema: string;
  insurance_signal_metrics_digest: string | null;
  kill_switch_profile_ok: boolean;
  kill_switch_drill_freshness_digest?: string | null;
  prove_bundle_samples_ok: number;
  witness_samples_ok: number;
  agent_inventory_count: number;
}

export interface CarrierUnderwritingEvidencePackInput {
  organization_id: string;
  generated_at?: string;
  period_start: string;
  period_end: string;
  lookback_days: number;
  market_context?: Record<string, unknown>;
  six_control_evaluation: SixControlEvaluationInput[];
  accountable_executive_attestation: AccountableExecutiveAttestationInput;
  composed_evidence: ComposedEvidenceInput;
  disclaimer?: string;
}



/**
 * Digest-bound accountable executive attestation (named executive ceremony).
 */
export function buildAccountableExecutiveAttestationDigest(
  input: AccountableExecutiveAttestationInput,
): string {
  const preimage = {
    schema: 'aevesa.accountable-executive-attestation/v1',
    organization_id: String(input.organization_id || '').trim(),
    executive_id: input.executive_id ? String(input.executive_id).trim() : null,
    executive_display_name: input.executive_display_name
      ? String(input.executive_display_name).trim()
      : null,
    role_title: input.role_title ? String(input.role_title).trim() : null,
    attested_at: input.attested_at ? String(input.attested_at).trim() : null,
    attestation_statement: String(input.attestation_statement || '').trim(),
  };
  return sha256HexUtf8(stableStringify(preimage));
}

export function buildAccountableExecutiveAttestationBlock(
  input: AccountableExecutiveAttestationInput,
) {
  const attestation_digest = buildAccountableExecutiveAttestationDigest(input);
  return {
    required: true as const,
    executive_id: input.executive_id ?? null,
    executive_display_name: input.executive_display_name ?? null,
    role_title: input.role_title ?? null,
    attested_at: input.attested_at ?? null,
    attestation_statement: String(input.attestation_statement || '').trim(),
    attestation_digest,
  };
}

function countByStatus(evals: SixControlEvaluationInput[], status: SixControlStatus): number {
  return evals.filter((e) => e.status === status).length;
}

export function deriveOverallReadiness(evals: SixControlEvaluationInput[]): 'ready' | 'partial' | 'insufficient' {
  const pass = countByStatus(evals, 'pass');
  const fail = countByStatus(evals, 'fail');
  if (fail === 0 && pass >= 5) return 'ready';
  if (fail >= 3) return 'insufficient';
  return 'partial';
}

/**
 * Canonical pack preimage — excludes pack_digest.
 */
export function buildCarrierUnderwritingPackPreimage(
  input: Omit<CarrierUnderwritingEvidencePackInput, 'disclaimer' | 'accountable_executive_attestation'> & {
    generated_at: string;
    accountable_executive_attestation: ReturnType<typeof buildAccountableExecutiveAttestationBlock>;
    overall_readiness: 'ready' | 'partial' | 'insufficient';
    composed_evidence: ComposedEvidenceInput & {
      controls_pass_count?: number;
      controls_fail_count?: number;
      controls_partial_count?: number;
    };
  },
): Record<string, unknown> {
  const composed = input.composed_evidence;
  return {
    schema: CARRIER_UNDERWRITING_EVIDENCE_PACK_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    generated_at: input.generated_at,
    period_start: String(input.period_start || '').trim(),
    period_end: String(input.period_end || '').trim(),
    lookback_days: Number(input.lookback_days) || 90,
    market_context: input.market_context ?? null,
    six_control_evaluation: input.six_control_evaluation.map((row) => ({
      control_id: row.control_id,
      label: row.label,
      status: row.status,
      evidence_refs: [...(row.evidence_refs || [])].sort(),
      notes: row.notes ?? null,
    })),
    accountable_executive_attestation: input.accountable_executive_attestation,
    composed_evidence: {
      insurance_signal_digest_schema: composed.insurance_signal_digest_schema,
      insurance_signal_metrics_digest: composed.insurance_signal_metrics_digest ?? null,
      kill_switch_profile_ok: composed.kill_switch_profile_ok === true,
      kill_switch_drill_freshness_digest: composed.kill_switch_drill_freshness_digest ?? null,
      prove_bundle_samples_ok: Number(composed.prove_bundle_samples_ok) || 0,
      witness_samples_ok: Number(composed.witness_samples_ok) || 0,
      agent_inventory_count: Number(composed.agent_inventory_count) || 0,
      controls_pass_count: countByStatus(input.six_control_evaluation, 'pass'),
      controls_fail_count: countByStatus(input.six_control_evaluation, 'fail'),
      controls_partial_count: countByStatus(input.six_control_evaluation, 'partial'),
    },
    overall_readiness: input.overall_readiness,
  };
}

export function buildCarrierUnderwritingEvidencePackDocument(input: CarrierUnderwritingEvidencePackInput) {
  const generated_at = input.generated_at || new Date().toISOString();
  const executiveBlock = buildAccountableExecutiveAttestationBlock(input.accountable_executive_attestation);
  const overall_readiness = deriveOverallReadiness(input.six_control_evaluation);
  const composed_evidence = {
    ...input.composed_evidence,
    controls_pass_count: countByStatus(input.six_control_evaluation, 'pass'),
    controls_fail_count: countByStatus(input.six_control_evaluation, 'fail'),
    controls_partial_count: countByStatus(input.six_control_evaluation, 'partial'),
  };
  const preimage = buildCarrierUnderwritingPackPreimage({
    ...input,
    generated_at,
    accountable_executive_attestation: executiveBlock,
    overall_readiness,
    composed_evidence,
  });
  const pack_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    composed_evidence,
    disclaimer:
      input.disclaimer ||
      'Evidence alignment for carrier underwriting diligence — not legal advice, coverage grant, or actuarial approval.',
    pack_digest,
  };
}

export interface CarrierMetricsSnapshot {
  hitl_coverage_pct?: number | null;
  kill_switch_profile_ok?: boolean;
  kill_switch_drill_freshness_digest?: string | null;
  prove_bundle_samples_ok?: number;
  witness_samples_ok?: number;
  agent_inventory_count?: number;
  receipt_sample_count?: number;
  sbom_tool_count?: number;
  ghost_score?: number | null;
  executive_id?: string | null;
  executive_display_name?: string | null;
  role_title?: string | null;
  attested_at?: string | null;
  attestation_statement?: string | null;
  insurance_signal_metrics_digest?: string | null;
}

/**
 * Evaluate CSA six-control checklist from hash-only metrics snapshot.
 */
export function evaluateSixControlsFromMetrics(
  metrics: CarrierMetricsSnapshot,
): SixControlEvaluationInput[] {
  const killSwitchOk =
    metrics.kill_switch_profile_ok === true ||
    (typeof metrics.kill_switch_drill_freshness_digest === 'string' &&
      /^[a-f0-9]{64}$/.test(metrics.kill_switch_drill_freshness_digest));

  const hitlPct = metrics.hitl_coverage_pct;
  const hitlStatus: SixControlStatus =
    hitlPct != null && hitlPct >= 50 ? 'pass' : hitlPct != null && hitlPct > 0 ? 'partial' : 'unknown';

  const sbomCount = Number(metrics.sbom_tool_count) || 0;
  const receiptCount = Number(metrics.receipt_sample_count) || 0;
  const provenanceStatus: SixControlStatus =
    sbomCount > 0 && receiptCount > 0 ? 'pass' : sbomCount > 0 || receiptCount > 0 ? 'partial' : 'fail';

  const hasExecutive =
    metrics.executive_id &&
    metrics.executive_display_name &&
    metrics.attestation_statement &&
    metrics.attested_at;
  const executiveStatus: SixControlStatus = hasExecutive ? 'pass' : 'fail';

  const witnessOk = Number(metrics.witness_samples_ok) || 0;
  const authStatus: SixControlStatus =
    (hitlPct != null && hitlPct >= 25) || witnessOk > 0 ? 'pass' : hitlPct != null ? 'partial' : 'unknown';

  const proveOk = Number(metrics.prove_bundle_samples_ok) || 0;
  const stackStatus: SixControlStatus =
    proveOk > 0 && witnessOk > 0
      ? 'pass'
      : proveOk > 0 || witnessOk > 0 || receiptCount > 0
        ? 'partial'
        : 'fail';

  const byId: Record<string, SixControlEvaluationInput> = {
    human_kill_switch: {
      control_id: 'human_kill_switch',
      label: 'Documented human kill switch',
      status: killSwitchOk ? 'pass' : 'fail',
      evidence_refs: killSwitchOk
        ? ['insurance/kill-switch-attestation.json', 'aevesa.kill-switch-attestation/v1']
        : ['insurance/kill-switch-attestation.json'],
      notes: killSwitchOk
        ? 'Kill-switch profile verified or drill freshness digest present.'
        : 'No verified kill-switch attestation or drill freshness on record.',
    },
    hitl_inventory: {
      control_id: 'hitl_inventory',
      label: 'Human-in-the-loop inventory',
      status: hitlStatus,
      evidence_refs: ['insurance/bounded-autonomy-summary.json', 'insurance/art14-session-excerpt.json'],
      notes:
        hitlPct != null
          ? `HITL coverage ${hitlPct}% over lookback window.`
          : 'HITL coverage unavailable for lookback window.',
    },
    data_provenance: {
      control_id: 'data_provenance',
      label: 'Data provenance / classification audit trail',
      status: provenanceStatus,
      evidence_refs: ['insurance/ai-sbom-excerpt.json', 'insurance/sample-receipts.json'],
      notes: `${sbomCount} tool/model anchors · ${receiptCount} sample receipts.`,
    },
    accountable_executive: {
      control_id: 'accountable_executive',
      label: 'Named accountable AI executive attestation',
      status: executiveStatus,
      evidence_refs: ['accountable_executive_attestation.attestation_digest'],
      notes: hasExecutive
        ? `Attested by ${metrics.executive_display_name} (${metrics.executive_id}).`
        : 'Named executive attestation required — digest-bound ceremony missing.',
    },
    deepfake_resistant_auth: {
      control_id: 'deepfake_resistant_auth',
      label: 'Out-of-band / HITL authentication on high-risk actions',
      status: authStatus,
      evidence_refs: ['insurance/bounded-autonomy-summary.json', 'insurance/witness-status.json'],
      notes:
        witnessOk > 0
          ? `${witnessOk} witness cosign sample(s) OK.`
          : 'Relying on HITL coverage metrics when witness samples absent.',
    },
    stack_enforcement: {
      control_id: 'stack_enforcement',
      label: 'Enforcement evidence on owned stack (not policy-only)',
      status: stackStatus,
      evidence_refs: [
        'insurance/underwriter-prove-bundle.json',
        'insurance/conformance-badges.json',
        'insurance/sample-receipts.json',
      ],
      notes: `${proveOk} prove-bundle sample(s) OK · ${witnessOk} witness sample(s) OK.`,
    },
  };

  return CARRIER_SIX_CONTROL_IDS.map((id) => byId[id]);
}

export { CARRIER_SIX_CONTROL_IDS };
