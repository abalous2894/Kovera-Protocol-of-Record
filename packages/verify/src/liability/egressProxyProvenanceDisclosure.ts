/**
 * Wave 17-D Phase 5 — egress proxy assurance tier disclosure for composite / broker surfaces.
 */

export const EGRESS_PROXY_ASSURANCE_TIER_VALUES = [
  'self_attested',
  'internal_collector_authenticated',
  'externally_signed',
] as const;

export type EgressProxyAssuranceTier = (typeof EGRESS_PROXY_ASSURANCE_TIER_VALUES)[number];

export const EGRESS_PROXY_SELF_ATTESTED_LIMITATION =
  'Proxy feed was not collector-authenticated — do not treat as independently observed external proxy evidence.';

const TIER_RANK: Record<EgressProxyAssuranceTier, number> = {
  self_attested: 0,
  internal_collector_authenticated: 1,
  externally_signed: 2,
};

export interface EgressProxyProvenanceDisclosureInput {
  assurance_tier?: string | null;
  independently_observed_claim_allowed?: boolean | null;
  collector_id?: string | null;
  mtls_bound?: boolean | null;
  limitations?: string[] | null;
}

export interface EgressProxyProvenanceDisclosureEvaluation {
  assurance_tier: EgressProxyAssuranceTier | null;
  independently_observed_claim_allowed: boolean;
  broker_downgrade_required: boolean;
  composite_verdict_cap: 'pass' | 'warn' | 'unknown' | null;
  note: string | null;
}

function normalizeTier(value: unknown): EgressProxyAssuranceTier | null {
  const tier = String(value || '').trim() as EgressProxyAssuranceTier;
  return (EGRESS_PROXY_ASSURANCE_TIER_VALUES as readonly string[]).includes(tier) ? tier : null;
}

export function egressProxyTierMeetsMinimum(
  tier: string | null | undefined,
  minimumTier: EgressProxyAssuranceTier,
): boolean {
  const current = TIER_RANK[normalizeTier(tier) ?? 'self_attested'] ?? -1;
  return current >= TIER_RANK[minimumTier];
}

/** Evaluate broker / composite disclosure for optional proxy_attribution_provenance block. */
export function evaluateEgressProxyProvenanceDisclosure(
  provenance: unknown,
): EgressProxyProvenanceDisclosureEvaluation {
  if (!provenance || typeof provenance !== 'object') {
    return {
      assurance_tier: null,
      independently_observed_claim_allowed: false,
      broker_downgrade_required: false,
      composite_verdict_cap: null,
      note: null,
    };
  }

  const doc = provenance as EgressProxyProvenanceDisclosureInput;
  const tier = normalizeTier(doc.assurance_tier);
  const independentlyObserved =
    doc.independently_observed_claim_allowed === true ||
    egressProxyTierMeetsMinimum(tier, 'internal_collector_authenticated');

  if (!tier || tier === 'self_attested') {
    return {
      assurance_tier: tier ?? 'self_attested',
      independently_observed_claim_allowed: false,
      broker_downgrade_required: true,
      composite_verdict_cap: 'warn',
      note: EGRESS_PROXY_SELF_ATTESTED_LIMITATION,
    };
  }

  return {
    assurance_tier: tier,
    independently_observed_claim_allowed: independentlyObserved,
    broker_downgrade_required: false,
    composite_verdict_cap: null,
    note: null,
  };
}

/**
 * Extract proxy_attribution_provenance from CAP export snapshot or mint wrapper.
 */
export function extractProxyAttributionProvenance(doc: unknown): unknown {
  if (!doc || typeof doc !== 'object') return null;
  const record = doc as Record<string, unknown>;
  if (record.proxy_attribution_provenance && typeof record.proxy_attribution_provenance === 'object') {
    return record.proxy_attribution_provenance;
  }
  const mint = record.egress_mint;
  if (mint && typeof mint === 'object') {
    const mintRecord = mint as Record<string, unknown>;
    if (
      mintRecord.proxy_attribution_provenance &&
      typeof mintRecord.proxy_attribution_provenance === 'object'
    ) {
      return mintRecord.proxy_attribution_provenance;
    }
  }
  return null;
}
