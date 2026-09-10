/** Wave 10 Track W — AP2 systematic analysis dispute-evidence threat IDs (T-39–T-47). */

export const AP2_DISPUTE_THREAT_IDS = [
  'T-39',
  'T-40',
  'T-41',
  'T-42',
  'T-43',
  'T-44',
  'T-45',
  'T-46',
  'T-47',
] as const;

export type Ap2DisputeThreatId = (typeof AP2_DISPUTE_THREAT_IDS)[number];

export type Ap2ThreatMitigationStatus = 'mitigated' | 'partial' | 'unmitigated' | 'n_a';

export const AP2_DISPUTE_ANALYSIS_REF = 'arxiv-ap2-systematic-analysis-v0.2-2026' as const;

export const AP2_DISPUTE_THREAT_LABELS: Record<Ap2DisputeThreatId, string> = {
  'T-39': 'Pre-signing conduct absent from signed AP2 mandates',
  'T-40': 'Missing per-role / per-decision audit trail',
  'T-41': 'Missing behavioral telemetry before authorization',
  'T-42': 'Cross-mandate correlation gap (intent → cart → payment)',
  'T-43': 'Mandate replay without bound conduct context',
  'T-44': 'Dispute evidence deletion / vendor log custody loss',
  'T-45': 'Unsigned cart mutation after agent tool path',
  'T-46': 'Agent impersonation / delegation ambiguity at checkout',
  'T-47': 'MCP consent mimicry without tamper-evident audit trail',
};

export interface Ap2ThreatEvaluationRow {
  threat_id: Ap2DisputeThreatId;
  label: string;
  status: Ap2ThreatMitigationStatus;
  aevesa_evidence_refs: string[];
  notes?: string | null;
}

export interface Ap2DisputeEvidenceInput {
  analysis_ref?: string;
  threat_evaluation: Ap2ThreatEvaluationRow[];
  dispute_readiness: 'complete' | 'partial' | 'mandate_only';
  portal_highlight_threat_ids?: Ap2DisputeThreatId[];
}

export interface Ap2DisputeEvaluationContext {
  coverage?: string;
  tool_hop_digests?: string[];
  policy_digest?: string | null;
  model_ref_digest?: string | null;
  hitl_approval_digest?: string | null;
  receipt_entry_hashes?: string[];
  liability_receipt_profile?: string | null;
  correlation_id?: string;
  intent_mandate_id?: string | null;
  cart_mandate_id?: string | null;
  payment_mandate_id?: string | null;
}

function hasHex64(value: unknown): boolean {
  return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
}

/**
 * Evaluate AP2 dispute threats T-39–T-47 from hash-only conduct snapshot.
 */
export function evaluateAp2DisputeThreats(ctx: Ap2DisputeEvaluationContext): Ap2ThreatEvaluationRow[] {
  const hops = ctx.tool_hop_digests || [];
  const receipts = ctx.receipt_entry_hashes || [];
  const fullConduct = ctx.coverage === 'full_conduct' && hops.length > 0;
  const correlation = Boolean(String(ctx.correlation_id || '').trim());
  const mandatesComplete =
    correlation &&
    Boolean(ctx.intent_mandate_id) &&
    Boolean(ctx.cart_mandate_id) &&
    Boolean(ctx.payment_mandate_id);

  const byId: Record<Ap2DisputeThreatId, Ap2ThreatEvaluationRow> = {
    'T-39': {
      threat_id: 'T-39',
      label: AP2_DISPUTE_THREAT_LABELS['T-39'],
      status: fullConduct ? 'mitigated' : correlation ? 'partial' : 'unmitigated',
      aevesa_evidence_refs: ['conduct.tool_hop_digests', 'conduct.coverage'],
      notes: fullConduct
        ? `${hops.length} tool-hop digest(s) bind pre-signing path.`
        : 'Mandate correlation only — pre-signing conduct not fully captured.',
    },
    'T-40': {
      threat_id: 'T-40',
      label: AP2_DISPUTE_THREAT_LABELS['T-40'],
      status:
        receipts.length > 0 && ctx.liability_receipt_profile
          ? 'mitigated'
          : receipts.length > 0
            ? 'partial'
            : 'unmitigated',
      aevesa_evidence_refs: ['receipt_entry_hashes', 'liability_receipt_profile'],
      notes:
        receipts.length > 0
          ? `${receipts.length} ledger anchor(s) linked to conduct receipt.`
          : 'No per-decision receipt anchors on conduct export.',
    },
    'T-41': {
      threat_id: 'T-41',
      label: AP2_DISPUTE_THREAT_LABELS['T-41'],
      status:
        fullConduct && hasHex64(ctx.model_ref_digest)
          ? 'mitigated'
          : fullConduct
            ? 'partial'
            : 'unmitigated',
      aevesa_evidence_refs: ['conduct.tool_hop_digests', 'conduct.model_ref_digest'],
      notes: hasHex64(ctx.model_ref_digest)
        ? 'Model reference digest bound at conduct mint.'
        : 'Tool-hop digests present; model ref optional.',
    },
    'T-42': {
      threat_id: 'T-42',
      label: AP2_DISPUTE_THREAT_LABELS['T-42'],
      status: mandatesComplete ? 'mitigated' : correlation ? 'partial' : 'unmitigated',
      aevesa_evidence_refs: ['mandate_refs.correlation_id', 'mandate_refs.*_mandate_id'],
      notes: mandatesComplete
        ? 'Intent, cart, and payment mandate IDs correlated.'
        : 'Correlation ID present; not all mandate IDs bound.',
    },
    'T-43': {
      threat_id: 'T-43',
      label: AP2_DISPUTE_THREAT_LABELS['T-43'],
      status: correlation && fullConduct ? 'mitigated' : correlation ? 'partial' : 'unmitigated',
      aevesa_evidence_refs: ['conduct_digest', 'mandate_refs.correlation_id'],
      notes: 'Conduct digest binds mint-time preimage to mandate correlation.',
    },
    'T-44': {
      threat_id: 'T-44',
      label: AP2_DISPUTE_THREAT_LABELS['T-44'],
      status: receipts.length > 0 ? 'partial' : 'unmitigated',
      aevesa_evidence_refs: ['receipt_entry_hashes', 'aevesa.deployer-log-custody-pack/v1'],
      notes:
        receipts.length > 0
          ? 'Ledger anchors referenced — pair with deployer custody pack for SR8 retention posture.'
          : 'No exogenous ledger anchors — vendor log deletion risk remains.',
    },
    'T-45': {
      threat_id: 'T-45',
      label: AP2_DISPUTE_THREAT_LABELS['T-45'],
      status:
        fullConduct && hasHex64(ctx.policy_digest) ? 'mitigated' : fullConduct ? 'partial' : 'unmitigated',
      aevesa_evidence_refs: ['conduct.policy_digest', 'conduct.tool_hop_digests'],
      notes: hasHex64(ctx.policy_digest)
        ? 'Policy digest binds evaluation that preceded cart mandate.'
        : 'Tool hops without policy digest — cart mutation gap may remain.',
    },
    'T-46': {
      threat_id: 'T-46',
      label: AP2_DISPUTE_THREAT_LABELS['T-46'],
      status: hasHex64(ctx.hitl_approval_digest)
        ? 'mitigated'
        : ctx.liability_receipt_profile === 'HITL_RELEASED'
          ? 'partial'
          : 'partial',
      aevesa_evidence_refs: ['conduct.hitl_approval_digest', 'liability_receipt_profile'],
      notes: hasHex64(ctx.hitl_approval_digest)
        ? 'Human approval digest bound on conduct path.'
        : 'Delegation chain evidence is complementary (Track G export).',
    },
    'T-47': {
      threat_id: 'T-47',
      label: AP2_DISPUTE_THREAT_LABELS['T-47'],
      status:
        fullConduct && hasHex64(ctx.policy_digest)
          ? 'mitigated'
          : fullConduct
            ? 'partial'
            : 'unmitigated',
      aevesa_evidence_refs: [
        'conduct.tool_hop_digests',
        'aevesa.tool-manifest-fingerprint/v1',
        'liability-receipt/v1',
      ],
      notes: 'MCP/tool invoke digests provide tamper-evident path — pair with manifest fingerprint at invoke.',
    },
  };

  return AP2_DISPUTE_THREAT_IDS.map((id) => byId[id]);
}

export function deriveDisputeReadiness(
  rows: Ap2ThreatEvaluationRow[],
): 'complete' | 'partial' | 'mandate_only' {
  const core = ['T-39', 'T-40', 'T-41'] as const;
  const coreMitigated = core.every((id) => rows.find((r) => r.threat_id === id)?.status === 'mitigated');
  if (coreMitigated) return 'complete';
  const anyMitigated = rows.some((r) => r.status === 'mitigated');
  return anyMitigated ? 'partial' : 'mandate_only';
}

export function buildAp2DisputeEvidenceBlock(
  ctx: Ap2DisputeEvaluationContext,
  opts?: { analysis_ref?: string; portal_highlight_threat_ids?: Ap2DisputeThreatId[] },
): Ap2DisputeEvidenceInput {
  const threat_evaluation = evaluateAp2DisputeThreats(ctx);
  return {
    analysis_ref: opts?.analysis_ref || AP2_DISPUTE_ANALYSIS_REF,
    threat_evaluation,
    dispute_readiness: deriveDisputeReadiness(threat_evaluation),
    portal_highlight_threat_ids: opts?.portal_highlight_threat_ids || ['T-39', 'T-40', 'T-41'],
  };
}

export default {
  AP2_DISPUTE_THREAT_IDS,
  AP2_DISPUTE_THREAT_LABELS,
  AP2_DISPUTE_ANALYSIS_REF,
  evaluateAp2DisputeThreats,
  deriveDisputeReadiness,
  buildAp2DisputeEvidenceBlock,
};
