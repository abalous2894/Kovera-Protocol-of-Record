import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';

/** Wave 12 Track A — declared agent inventory snapshot (enrollment registry export). */

export const DECLARED_AGENT_ROSTER_SCHEMA = 'aevesa.declared-agent-roster/v1' as const;

export type DeclaredAgentStatus = 'enrolled' | 'discovered' | 'blocked' | 'deprecated';

export interface DeclaredAgentEntry {
  agent_id: string;
  owner_ref?: string | null;
  status: DeclaredAgentStatus;
}

export interface DeclaredAgentRosterInput {
  organization_id: string;
  period_label: string;
  generated_at?: string;
  source_schema?: string;
  agents: DeclaredAgentEntry[];
}



export function normalizeAgentId(agentId: string): string {
  return String(agentId || '')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, '-');
}

export function agentIdDigest(agentId: string): string {
  return sha256HexUtf8(normalizeAgentId(agentId));
}

export function buildDeclaredAgentRosterPreimage(
  input: DeclaredAgentRosterInput & { generated_at: string },
): Record<string, unknown> {
  const agents = [...(input.agents || [])]
    .map((a) => ({
      agent_id: normalizeAgentId(a.agent_id),
      agent_id_digest: agentIdDigest(a.agent_id),
      owner_ref: a.owner_ref ? String(a.owner_ref).trim() : null,
      status: a.status,
    }))
    .sort((a, b) => a.agent_id.localeCompare(b.agent_id));

  return {
    schema: DECLARED_AGENT_ROSTER_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    period_label: String(input.period_label || '').trim(),
    generated_at: input.generated_at,
    source_schema: input.source_schema || 'aevesa.apor.agent-enrollment-registry/v1',
    agents,
    declared_count: agents.length,
  };
}

export function buildDeclaredAgentRosterDocument(input: DeclaredAgentRosterInput) {
  const generated_at = input.generated_at || new Date().toISOString();
  const preimage = buildDeclaredAgentRosterPreimage({ ...input, generated_at });
  const roster_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    roster_digest,
  };
}

export function listDeclaredAgentIds(roster: { agents?: Array<{ agent_id?: string }> }): string[] {
  return (roster.agents || [])
    .map((a) => normalizeAgentId(String(a?.agent_id || '')))
    .filter(Boolean)
    .sort();
}

export default {
  DECLARED_AGENT_ROSTER_SCHEMA,
  buildDeclaredAgentRosterDocument,
  buildDeclaredAgentRosterPreimage,
  normalizeAgentId,
  agentIdDigest,
  listDeclaredAgentIds,
};
