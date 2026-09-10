import {
  BEHAVIORAL_SBOM_SCHEMA,
  BEHAVIORAL_GAP_CLASSES,
  evaluateBehavioralSbom,
  type BehavioralAgentRecord,
  type BehavioralGapClass,
  type ConfiguredAgentRecord,
} from '../core/behavioralSbom.js';

export const BEHAVIORAL_SBOM_SKU = 'aevesa-behavioral-sbom-v1' as const;

export interface BehavioralSbomDocument {
  schema?: string;
  organization_id?: string;
  generated_at?: string;
  behavioral_agents?: BehavioralAgentRecord[];
  configured_agents?: ConfiguredAgentRecord[];
  gap_summary?: Partial<Record<BehavioralGapClass, number>>;
  agents_with_gaps?: Array<{ agent_id?: string; gap_class?: string }>;
  sbom_root?: string;
  sbom_digest?: string;
}

export interface BehavioralSbomVerifyOptions {
  /** Require at least one behavioral agent row */
  requireBehavioralAgents?: boolean;
  /** Fail when any non-aligned gap remains */
  requireNoGaps?: boolean;
}

export interface BehavioralSbomVerifyChecks {
  schemaValid: boolean;
  organizationIdPresent: boolean;
  behavioralAgentsPresent: boolean;
  gapSummaryValid: boolean;
  sbomRootMatches: boolean;
  sbomDigestMatches: boolean;
  agentsWithGapsAligned: boolean;
  profileComplete: boolean;
}

export interface BehavioralSbomVerifyResult {
  schema: typeof BEHAVIORAL_SBOM_SCHEMA;
  sku: typeof BEHAVIORAL_SBOM_SKU;
  ok: boolean;
  checks: BehavioralSbomVerifyChecks;
  gtmLine: string;
  note: string | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function parseBehavioralAgents(raw: unknown): BehavioralAgentRecord[] {
  if (!Array.isArray(raw)) return [];
  const out: BehavioralAgentRecord[] = [];
  for (const item of raw) {
    const rec = asRecord(item);
    if (!rec) continue;
    const agent_id = String(rec.agent_id || '').trim();
    if (!agent_id) continue;
    out.push({
      agent_id,
      registry_status:
        rec.registry_status === 'discovered' ||
        rec.registry_status === 'enrolled' ||
        rec.registry_status === 'blocked'
          ? rec.registry_status
          : rec.registry_status == null
            ? null
            : null,
      receipt_count: Number(rec.receipt_count) || 0,
      ...(rec.first_receipt_entry_hash != null
        ? { first_receipt_entry_hash: String(rec.first_receipt_entry_hash) }
        : {}),
      ...(rec.last_receipt_at != null ? { last_receipt_at: String(rec.last_receipt_at) } : {}),
      ...(rec.configured === true ? { configured: true } : {}),
    });
  }
  return out;
}

function parseConfiguredAgents(raw: unknown): ConfiguredAgentRecord[] {
  if (!Array.isArray(raw)) return [];
  const out: ConfiguredAgentRecord[] = [];
  for (const item of raw) {
    const rec = asRecord(item);
    if (!rec) continue;
    const agent_id = String(rec.agent_id || '').trim();
    if (!agent_id) continue;
    out.push({
      agent_id,
      ...(rec.source != null ? { source: String(rec.source) } : {}),
    });
  }
  return out;
}

/**
 * Verify behavioral SBOM bundle — Wave 7 Track B receipt-driven inventory profile.
 */
export function verifyBehavioralSbomBundle(
  input: unknown,
  options: BehavioralSbomVerifyOptions = {},
): BehavioralSbomVerifyResult {
  const doc = asRecord(input) as BehavioralSbomDocument | null;
  const schemaValid = doc?.schema === BEHAVIORAL_SBOM_SCHEMA;

  const organization_id = String(doc?.organization_id || '').trim();
  const organizationIdPresent = organization_id.length > 0;

  const behavioral_agents = parseBehavioralAgents(doc?.behavioral_agents);
  const configured_agents = parseConfiguredAgents(doc?.configured_agents);
  const behavioralAgentsPresent =
    behavioral_agents.length > 0 || options.requireBehavioralAgents !== true;

  let gapSummaryValid = false;
  let sbomRootMatches = false;
  let sbomDigestMatches = false;
  let agentsWithGapsAligned = false;

  if (organizationIdPresent) {
    const evaluated = evaluateBehavioralSbom({
      organization_id,
      behavioral_agents,
      configured_agents,
      generated_at: doc?.generated_at,
    });

    gapSummaryValid = BEHAVIORAL_GAP_CLASSES.every((key) => {
      const expected = evaluated.gap_summary[key];
      const actual = doc?.gap_summary?.[key];
      return Number(actual) === expected;
    });

    sbomRootMatches = Boolean(doc?.sbom_root) && doc!.sbom_root === evaluated.sbom_root;
    sbomDigestMatches = Boolean(doc?.sbom_digest) && doc!.sbom_digest === evaluated.sbom_digest;

    const expectedGaps = JSON.stringify(evaluated.agents_with_gaps);
    const actualGaps = JSON.stringify(
      (doc?.agents_with_gaps || [])
        .map((g) => ({
          agent_id: String(g?.agent_id || '').trim(),
          gap_class: String(g?.gap_class || '').trim(),
        }))
        .filter((g) => g.agent_id && BEHAVIORAL_GAP_CLASSES.includes(g.gap_class as BehavioralGapClass))
        .sort((a, b) => a.agent_id.localeCompare(b.agent_id)),
    );
    agentsWithGapsAligned = expectedGaps === actualGaps;
  }

  const requireNoGaps = options.requireNoGaps === true;
  const hasNonAlignedGaps =
    organizationIdPresent &&
    evaluateBehavioralSbom({
      organization_id,
      behavioral_agents,
      configured_agents,
      generated_at: doc?.generated_at,
    }).agents_with_gaps.length > 0;

  const profileComplete =
    schemaValid &&
    organizationIdPresent &&
    behavioralAgentsPresent &&
    gapSummaryValid &&
    sbomRootMatches &&
    sbomDigestMatches &&
    agentsWithGapsAligned &&
    (!requireNoGaps || !hasNonAlignedGaps);

  let note: string | null = null;
  if (profileComplete) {
    note = requireNoGaps
      ? 'Behavioral SBOM verified — config vs behavior aligned offline'
      : 'Behavioral SBOM verified — gap summary attested offline';
  } else if (!sbomDigestMatches) {
    note = 'sbom_digest does not match behavioral agent preimage';
  } else if (!agentsWithGapsAligned) {
    note = 'agents_with_gaps does not match evaluated gap classes';
  } else if (!behavioralAgentsPresent) {
    note = 'behavioral_agents slice is required';
  } else if (requireNoGaps && hasNonAlignedGaps) {
    note = 'Behavioral SBOM requires no config-vs-behavior gaps';
  } else {
    note = 'Behavioral SBOM verification failed';
  }

  return {
    schema: BEHAVIORAL_SBOM_SCHEMA,
    sku: BEHAVIORAL_SBOM_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      organizationIdPresent,
      behavioralAgentsPresent,
      gapSummaryValid,
      sbomRootMatches,
      sbomDigestMatches,
      agentsWithGapsAligned,
      profileComplete,
    },
    gtmLine:
      "We don't out-discover Cyera. We out-prove what actually executed — and show the config-vs-behavior gap, offline.",
    note,
  };
}
