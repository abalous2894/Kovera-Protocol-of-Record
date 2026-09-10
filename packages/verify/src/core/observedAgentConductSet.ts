import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';
import { agentIdDigest, normalizeAgentId } from './declaredAgentRoster.js';

/** Wave 12 Track A — agents observed in conduct evidence for a period. */

export const OBSERVED_AGENT_CONDUCT_SET_SCHEMA = 'aevesa.observed-agent-conduct-set/v1' as const;

export interface ObservedAgentEntry {
  agent_id: string;
  session_count: number;
  conduct_entry_hashes?: string[];
}

export interface ObservationWindow {
  start: string;
  end: string;
}

export interface ObservedAgentConductSetInput {
  organization_id: string;
  period_label: string;
  observation_window: ObservationWindow;
  generated_at?: string;
  observed_agents: ObservedAgentEntry[];
}

const HEX64 = /^[a-f0-9]{64}$/;



function sortHex64(values: string[]): string[] {
  return [...values]
    .map((v) => String(v || '').trim().toLowerCase())
    .filter((v) => HEX64.test(v))
    .sort();
}

export function buildObservedAgentConductSetPreimage(
  input: ObservedAgentConductSetInput & { generated_at: string },
): Record<string, unknown> {
  const observed_agents = [...(input.observed_agents || [])]
    .map((a) => ({
      agent_id: normalizeAgentId(a.agent_id),
      agent_id_digest: agentIdDigest(a.agent_id),
      session_count: Math.max(0, Number(a.session_count) || 0),
      conduct_entry_hashes: sortHex64(a.conduct_entry_hashes || []),
    }))
    .sort((a, b) => a.agent_id.localeCompare(b.agent_id));

  return {
    schema: OBSERVED_AGENT_CONDUCT_SET_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    period_label: String(input.period_label || '').trim(),
    observation_window: {
      start: String(input.observation_window?.start || '').trim(),
      end: String(input.observation_window?.end || '').trim(),
    },
    generated_at: input.generated_at,
    observed_agents,
    observed_count: observed_agents.length,
  };
}

export function buildObservedAgentConductSetDocument(input: ObservedAgentConductSetInput) {
  const generated_at = input.generated_at || new Date().toISOString();
  const preimage = buildObservedAgentConductSetPreimage({ ...input, generated_at });
  const observed_set_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    observed_set_digest,
  };
}

export function listObservedAgentIds(set: { observed_agents?: Array<{ agent_id?: string }> }): string[] {
  return (set.observed_agents || [])
    .map((a) => normalizeAgentId(String(a?.agent_id || '')))
    .filter(Boolean)
    .sort();
}

export default {
  OBSERVED_AGENT_CONDUCT_SET_SCHEMA,
  buildObservedAgentConductSetDocument,
  buildObservedAgentConductSetPreimage,
  listObservedAgentIds,
};
