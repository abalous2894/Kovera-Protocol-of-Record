import { sha256HexUtf8 } from '../core/sha256.js';
import { DECLARED_AGENT_ROSTER_SCHEMA, buildDeclaredAgentRosterPreimage } from '../core/declaredAgentRoster.js';
import { stableStringify } from '../core/stableStringify.js';

export const DECLARED_AGENT_ROSTER_SKU = 'aevesa-declared-agent-roster-v1' as const;

const HEX64 = /^[a-f0-9]{64}$/;
const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|ssn|phone|address|pan|cvv)$/i;
const VALID_STATUS = new Set(['enrolled', 'discovered', 'blocked', 'deprecated']);

export interface DeclaredAgentRosterVerifyResult {
  schema: typeof DECLARED_AGENT_ROSTER_SCHEMA;
  sku: typeof DECLARED_AGENT_ROSTER_SKU;
  ok: boolean;
  checks: Record<string, boolean>;
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
  if (Array.isArray(value)) return value.some((v) => hasForbiddenKeys(v, depth + 1));
  if (typeof value !== 'object') return false;
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (FORBIDDEN_KEYS.test(key)) return true;
    if (hasForbiddenKeys(child, depth + 1)) return true;
  }
  return false;
}

export function verifyDeclaredAgentRoster(docInput: unknown): DeclaredAgentRosterVerifyResult {
  const doc = asRecord(docInput);
  const schemaValid = doc?.schema === DECLARED_AGENT_ROSTER_SCHEMA;
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;
  const periodLabelPresent = String(doc?.period_label || '').trim().length > 0;

  const agents = Array.isArray(doc?.agents) ? doc.agents : [];
  const agentsPresent = agents.length > 0;
  const agentFieldsValid =
    agents.length === 0 ||
    agents.every(
      (a) =>
        String(a?.agent_id || '').trim().length > 0 &&
        HEX64.test(String(a?.agent_id_digest || '').toLowerCase()) &&
        VALID_STATUS.has(String(a?.status || '')),
    );

  let rosterDigestMatches = false;
  if (schemaValid && doc && agentFieldsValid) {
    const preimage = buildDeclaredAgentRosterPreimage({
      organization_id: String(doc.organization_id),
      period_label: String(doc.period_label),
      generated_at: String(doc.generated_at || ''),
      source_schema: doc.source_schema != null ? String(doc.source_schema) : undefined,
      agents: agents.map((a) => ({
        agent_id: String(a?.agent_id || ''),
        owner_ref: a?.owner_ref != null ? String(a.owner_ref) : null,
        status: String(a?.status || '') as 'enrolled',
      })),
    });
    const expected = sha256HexUtf8(stableStringify(preimage));
    rosterDigestMatches = String(doc.roster_digest || '').toLowerCase() === expected;
  }

  const hashOnlySurface = !hasForbiddenKeys(doc);
  const profileComplete =
    schemaValid &&
    organizationIdPresent &&
    periodLabelPresent &&
    agentsPresent &&
    agentFieldsValid &&
    rosterDigestMatches &&
    hashOnlySurface;

  let note: string | null = null;
  if (!schemaValid) note = `schema must be ${DECLARED_AGENT_ROSTER_SCHEMA}`;
  else if (!rosterDigestMatches) note = 'roster_digest does not match canonical preimage';

  return {
    schema: DECLARED_AGENT_ROSTER_SCHEMA,
    sku: DECLARED_AGENT_ROSTER_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      organizationIdPresent,
      periodLabelPresent,
      agentsPresent,
      agentFieldsValid,
      rosterDigestMatches,
      hashOnlySurface,
      profileComplete,
    },
    gtmLine: 'Declared roster bound to observed conduct — shadow agents provable offline.',
    note,
  };
}
