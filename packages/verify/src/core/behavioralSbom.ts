import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';

export const BEHAVIORAL_SBOM_SCHEMA = 'aevesa.behavioral-sbom/v1' as const;

export const BEHAVIORAL_GAP_CLASSES = [
  'receipted_enrolled',
  'receipted_not_enrolled',
  'discovered_not_enrolled',
  'configured_not_receipted',
] as const;

export type BehavioralGapClass = (typeof BEHAVIORAL_GAP_CLASSES)[number];

export type BehavioralRegistryStatus = 'discovered' | 'enrolled' | 'blocked' | null;

export interface BehavioralAgentRecord {
  agent_id: string;
  registry_status?: BehavioralRegistryStatus;
  receipt_count?: number;
  first_receipt_entry_hash?: string | null;
  last_receipt_at?: string | null;
  /** When true, agent appears in optional configured slice (CMDB / Cyera-style inventory). */
  configured?: boolean;
}

export interface ConfiguredAgentRecord {
  agent_id: string;
  source?: string | null;
}

export interface BehavioralSbomEvaluateInput {
  organization_id: string;
  behavioral_agents: BehavioralAgentRecord[];
  configured_agents?: ConfiguredAgentRecord[];
  generated_at?: string;
}



function normalizeAgentId(agentId: string): string {
  return String(agentId || '').trim();
}

function sortAgentIds(records: BehavioralAgentRecord[]): BehavioralAgentRecord[] {
  return [...records]
    .map((r) => ({
      agent_id: normalizeAgentId(r.agent_id),
      registry_status: r.registry_status ?? null,
      receipt_count: Number(r.receipt_count) || 0,
      ...(r.first_receipt_entry_hash != null
        ? { first_receipt_entry_hash: String(r.first_receipt_entry_hash) }
        : {}),
      ...(r.last_receipt_at != null ? { last_receipt_at: String(r.last_receipt_at) } : {}),
      ...(r.configured === true ? { configured: true } : {}),
    }))
    .filter((r) => r.agent_id.length > 0)
    .sort((a, b) => a.agent_id.localeCompare(b.agent_id));
}

/**
 * Classify config-vs-behavior gap for one agent row.
 */
export function classifyBehavioralAgentGap(record: BehavioralAgentRecord): BehavioralGapClass | null {
  const receiptCount = Number(record.receipt_count) || 0;
  const hasReceipts = receiptCount > 0;
  const configured = record.configured === true;
  const status = record.registry_status ?? null;

  if (configured && !hasReceipts) {
    return 'configured_not_receipted';
  }
  if (hasReceipts && status === 'enrolled') {
    return 'receipted_enrolled';
  }
  if (hasReceipts && status === 'discovered') {
    return 'discovered_not_enrolled';
  }
  if (hasReceipts && status !== 'enrolled') {
    return 'receipted_not_enrolled';
  }
  return null;
}

function mergeConfiguredSlice(
  behavioral: BehavioralAgentRecord[],
  configured?: ConfiguredAgentRecord[],
): BehavioralAgentRecord[] {
  const byId = new Map<string, BehavioralAgentRecord>();
  for (const row of behavioral) {
    const id = normalizeAgentId(row.agent_id);
    if (!id) continue;
    byId.set(id, { ...row, agent_id: id });
  }
  for (const cfg of configured || []) {
    const id = normalizeAgentId(cfg.agent_id);
    if (!id) continue;
    const existing = byId.get(id);
    if (existing) {
      byId.set(id, { ...existing, configured: true });
    } else {
      byId.set(id, {
        agent_id: id,
        registry_status: null,
        receipt_count: 0,
        configured: true,
      });
    }
  }
  return sortAgentIds([...byId.values()]);
}

/**
 * Evaluate behavioral SBOM gap summary — Wave 7 Track B.
 */
export function evaluateBehavioralSbom(input: BehavioralSbomEvaluateInput): {
  organization_id: string;
  generated_at: string;
  behavioral_agents: BehavioralAgentRecord[];
  configured_agents: ConfiguredAgentRecord[];
  gap_summary: Record<BehavioralGapClass, number>;
  agents_with_gaps: Array<{ agent_id: string; gap_class: BehavioralGapClass }>;
  sbom_root: string;
  sbom_digest: string;
} {
  const organization_id = String(input.organization_id || '').trim();
  const generated_at =
    typeof input.generated_at === 'string' && input.generated_at.trim()
      ? input.generated_at.trim()
      : new Date().toISOString();

  const configured_agents = (input.configured_agents || [])
    .map((c) => ({
      agent_id: normalizeAgentId(c.agent_id),
      ...(c.source != null ? { source: String(c.source) } : {}),
    }))
    .filter((c) => c.agent_id.length > 0)
    .sort((a, b) => a.agent_id.localeCompare(b.agent_id));

  const behavioral_agents = mergeConfiguredSlice(input.behavioral_agents || [], configured_agents);

  const gap_summary: Record<BehavioralGapClass, number> = {
    receipted_enrolled: 0,
    receipted_not_enrolled: 0,
    discovered_not_enrolled: 0,
    configured_not_receipted: 0,
  };

  const agents_with_gaps: Array<{ agent_id: string; gap_class: BehavioralGapClass }> = [];

  for (const row of behavioral_agents) {
    const gap = classifyBehavioralAgentGap(row);
    if (!gap) continue;
    gap_summary[gap] += 1;
    if (gap !== 'receipted_enrolled') {
      agents_with_gaps.push({ agent_id: row.agent_id, gap_class: gap });
    }
  }

  agents_with_gaps.sort((a, b) => a.agent_id.localeCompare(b.agent_id));

  const sbom_root = sha256HexUtf8(
    stableStringify({
      schema: BEHAVIORAL_SBOM_SCHEMA,
      organization_id,
      behavioral_agent_ids: behavioral_agents.map((a) => a.agent_id),
    }),
  );

  const sbom_digest = sha256HexUtf8(
    stableStringify({
      schema: BEHAVIORAL_SBOM_SCHEMA,
      organization_id,
      generated_at,
      sbom_root,
      gap_summary,
      agents_with_gaps,
    }),
  );

  return {
    organization_id,
    generated_at,
    behavioral_agents,
    configured_agents,
    gap_summary,
    agents_with_gaps,
    sbom_root,
    sbom_digest,
  };
}

export function buildBehavioralSbomDocument(input: BehavioralSbomEvaluateInput): Record<string, unknown> {
  const evaluated = evaluateBehavioralSbom(input);
  return {
    schema: BEHAVIORAL_SBOM_SCHEMA,
    organization_id: evaluated.organization_id,
    generated_at: evaluated.generated_at,
    behavioral_agents: evaluated.behavioral_agents,
    ...(evaluated.configured_agents.length
      ? { configured_agents: evaluated.configured_agents }
      : {}),
    gap_summary: evaluated.gap_summary,
    agents_with_gaps: evaluated.agents_with_gaps,
    sbom_root: evaluated.sbom_root,
    sbom_digest: evaluated.sbom_digest,
  };
}
