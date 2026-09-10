import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';
import { listDeclaredAgentIds } from './declaredAgentRoster.js';
import { listObservedAgentIds } from './observedAgentConductSet.js';

/** Wave 12 Track A — verifiable declared roster vs observed conduct delta (shadow-agent proof). */

export const AGENT_CENSUS_COMPLETENESS_PACK_SCHEMA =
  'aevesa.agent-census-completeness-pack/v1' as const;

export type CensusReadiness = 'complete' | 'shadow_gap' | 'roster_only' | 'partial';

export interface ComposedCensusMemberRef {
  member_schema: string;
  member_digest: string;
  verify_ok: boolean;
  label: string;
  entry_count?: number | null;
}

export interface CensusDeltaInput {
  shadow_agent_ids?: string[];
  dormant_roster_ids?: string[];
  matched_agent_ids?: string[];
}

export interface CensusAssertionsInput {
  roster_observed_delta_bound: boolean;
  shadow_agents_detected: boolean;
  third_party_verifiable: boolean;
}

export interface CensusSessionBinding {
  period_label: string;
  declared_roster_digest: string;
  observed_set_digest: string;
  delta_digest: string;
  normalization_bound: boolean;
}

export interface AgentCensusCompletenessPackInput {
  organization_id: string;
  period_label: string;
  generated_at?: string;
  census_assertions: CensusAssertionsInput;
  census_delta: CensusDeltaInput;
  composed_members: ComposedCensusMemberRef[];
  census_session_binding: CensusSessionBinding;
  disclaimer?: string;
}



export function computeCensusDelta(
  declaredIds: string[],
  observedIds: string[],
): {
  shadow_agent_ids: string[];
  dormant_roster_ids: string[];
  matched_agent_ids: string[];
  shadow_count: number;
  dormant_count: number;
  matched_count: number;
} {
  const declared = new Set(declaredIds.map((id) => id.toLowerCase()));
  const observed = new Set(observedIds.map((id) => id.toLowerCase()));

  const shadow_agent_ids = [...observed].filter((id) => !declared.has(id)).sort();
  const dormant_roster_ids = [...declared].filter((id) => !observed.has(id)).sort();
  const matched_agent_ids = [...declared].filter((id) => observed.has(id)).sort();

  return {
    shadow_agent_ids,
    dormant_roster_ids,
    matched_agent_ids,
    shadow_count: shadow_agent_ids.length,
    dormant_count: dormant_roster_ids.length,
    matched_count: matched_agent_ids.length,
  };
}

export function buildDeltaDigest(delta: ReturnType<typeof computeCensusDelta>): string {
  return sha256HexUtf8(
    stableStringify({
      shadow_agent_ids: delta.shadow_agent_ids,
      dormant_roster_ids: delta.dormant_roster_ids,
      matched_agent_ids: delta.matched_agent_ids,
    }),
  );
}

export function deriveCensusReadiness(
  delta: ReturnType<typeof computeCensusDelta>,
  members: ComposedCensusMemberRef[],
): CensusReadiness {
  const rosterOk = members.some(
    (m) => m.member_schema === 'aevesa.declared-agent-roster/v1' && m.verify_ok === true,
  );
  const observedOk = members.some(
    (m) => m.member_schema === 'aevesa.observed-agent-conduct-set/v1' && m.verify_ok === true,
  );

  if (!rosterOk && !observedOk) return 'partial';
  if (rosterOk && !observedOk) return 'roster_only';
  if (delta.shadow_count > 0) return 'shadow_gap';
  if (delta.dormant_count > 0 && delta.matched_count > 0) return 'partial';
  if (delta.shadow_count === 0 && delta.matched_count > 0 && rosterOk && observedOk) return 'complete';
  return 'partial';
}

export function buildCensusAssertionsBlock(
  input: CensusAssertionsInput,
  delta: ReturnType<typeof computeCensusDelta>,
  members: ComposedCensusMemberRef[],
) {
  const readiness = deriveCensusReadiness(delta, members);
  const hasShadow = delta.shadow_count > 0;
  return {
    roster_observed_delta_bound: input.roster_observed_delta_bound === true,
    shadow_agents_detected: hasShadow || input.shadow_agents_detected === true,
    third_party_verifiable: input.third_party_verifiable === true,
    census_readiness: readiness,
    shadow_count: delta.shadow_count,
    dormant_count: delta.dormant_count,
    matched_count: delta.matched_count,
  };
}

export function buildCensusDeltaBlock(delta: ReturnType<typeof computeCensusDelta>) {
  return {
    shadow_agent_ids: delta.shadow_agent_ids,
    dormant_roster_ids: delta.dormant_roster_ids,
    matched_agent_ids: delta.matched_agent_ids,
    shadow_count: delta.shadow_count,
    dormant_count: delta.dormant_count,
    matched_count: delta.matched_count,
    delta_digest: buildDeltaDigest(delta),
  };
}

export function buildAgentCensusCompletenessPackPreimage(
  input: Omit<AgentCensusCompletenessPackInput, 'disclaimer'> & {
    generated_at: string;
    census_assertions: ReturnType<typeof buildCensusAssertionsBlock>;
    census_delta: ReturnType<typeof buildCensusDeltaBlock>;
    composed_members: ComposedCensusMemberRef[];
  },
): Record<string, unknown> {
  const members = [...(input.composed_members || [])]
    .map((m) => ({
      member_schema: String(m.member_schema || '').trim(),
      member_digest: String(m.member_digest || '').trim().toLowerCase(),
      verify_ok: m.verify_ok === true,
      label: String(m.label || '').trim(),
      entry_count: m.entry_count != null ? Number(m.entry_count) : null,
    }))
    .sort((a, b) => a.member_schema.localeCompare(b.member_schema));

  const binding = input.census_session_binding;

  return {
    schema: AGENT_CENSUS_COMPLETENESS_PACK_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    period_label: String(input.period_label || '').trim(),
    generated_at: input.generated_at,
    census_assertions: input.census_assertions,
    census_delta: input.census_delta,
    composed_members: members,
    census_session_binding: {
      period_label: String(binding.period_label || '').trim(),
      declared_roster_digest: String(binding.declared_roster_digest || '').trim().toLowerCase(),
      observed_set_digest: String(binding.observed_set_digest || '').trim().toLowerCase(),
      delta_digest: String(binding.delta_digest || '').trim().toLowerCase(),
      normalization_bound: binding.normalization_bound === true,
    },
  };
}

export function buildAgentCensusCompletenessPackDocument(input: AgentCensusCompletenessPackInput) {
  const generated_at = input.generated_at || new Date().toISOString();
  const raw = input.census_delta as CensusDeltaInput & ReturnType<typeof buildCensusDeltaBlock>;
  const deltaCore =
    raw.shadow_count != null
      ? {
          shadow_agent_ids: raw.shadow_agent_ids || [],
          dormant_roster_ids: raw.dormant_roster_ids || [],
          matched_agent_ids: raw.matched_agent_ids || [],
          shadow_count: raw.shadow_count,
          dormant_count: raw.dormant_count,
          matched_count: raw.matched_count,
        }
      : computeCensusDelta(
          [...(raw.dormant_roster_ids || []), ...(raw.matched_agent_ids || [])],
          [...(raw.shadow_agent_ids || []), ...(raw.matched_agent_ids || [])],
        );
  const deltaBlock = buildCensusDeltaBlock(deltaCore);

  const census_assertions = buildCensusAssertionsBlock(
    input.census_assertions,
    deltaCore,
    input.composed_members,
  );

  const preimage = buildAgentCensusCompletenessPackPreimage({
    ...input,
    generated_at,
    census_assertions,
    census_delta: deltaBlock,
    composed_members: input.composed_members,
  });
  const pack_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    pack_digest,
    disclaimer:
      input.disclaimer ||
      'Census evidence export only — Aevesa does not replace network discovery or identity-vendor shadow-AI tooling.',
  };
}

/** Recompute delta from roster + observed member documents. */
export function computeCensusDeltaFromMembers(
  declaredRoster: { agents?: Array<{ agent_id?: string }> },
  observedSet: { observed_agents?: Array<{ agent_id?: string }> },
) {
  return computeCensusDelta(listDeclaredAgentIds(declaredRoster), listObservedAgentIds(observedSet));
}

export default {
  AGENT_CENSUS_COMPLETENESS_PACK_SCHEMA,
  computeCensusDelta,
  buildDeltaDigest,
  deriveCensusReadiness,
  buildCensusAssertionsBlock,
  buildCensusDeltaBlock,
  buildAgentCensusCompletenessPackDocument,
  computeCensusDeltaFromMembers,
};
