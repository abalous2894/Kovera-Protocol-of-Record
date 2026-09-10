import { sha256HexUtf8 } from '../core/sha256.js';
import { OBSERVED_AGENT_CONDUCT_SET_SCHEMA, buildObservedAgentConductSetPreimage } from '../core/observedAgentConductSet.js';
import { stableStringify } from '../core/stableStringify.js';

export const OBSERVED_AGENT_CONDUCT_SET_SKU = 'aevesa-observed-agent-conduct-set-v1' as const;

const HEX64 = /^[a-f0-9]{64}$/;
const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|ssn|phone|address|pan|cvv)$/i;

export interface ObservedAgentConductSetVerifyResult {
  schema: typeof OBSERVED_AGENT_CONDUCT_SET_SCHEMA;
  sku: typeof OBSERVED_AGENT_CONDUCT_SET_SKU;
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

export function verifyObservedAgentConductSet(
  docInput: unknown,
): ObservedAgentConductSetVerifyResult {
  const doc = asRecord(docInput);
  const schemaValid = doc?.schema === OBSERVED_AGENT_CONDUCT_SET_SCHEMA;
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;
  const periodLabelPresent = String(doc?.period_label || '').trim().length > 0;

  const window = asRecord(doc?.observation_window) || {};
  const windowValid =
    String(window.start || '').trim().length > 0 && String(window.end || '').trim().length > 0;

  const observed = Array.isArray(doc?.observed_agents) ? doc.observed_agents : [];
  const observedPresent = observed.length > 0;
  const observedFieldsValid =
    observed.length === 0 ||
    observed.every(
      (a) =>
        String(a?.agent_id || '').trim().length > 0 &&
        HEX64.test(String(a?.agent_id_digest || '').toLowerCase()) &&
        Number(a?.session_count) >= 0,
    );

  let observedSetDigestMatches = false;
  if (schemaValid && doc && observedFieldsValid && windowValid) {
    const preimage = buildObservedAgentConductSetPreimage({
      organization_id: String(doc.organization_id),
      period_label: String(doc.period_label),
      generated_at: String(doc.generated_at || ''),
      observation_window: {
        start: String(window.start),
        end: String(window.end),
      },
      observed_agents: observed.map((a) => ({
        agent_id: String(a?.agent_id || ''),
        session_count: Number(a?.session_count) || 0,
        conduct_entry_hashes: Array.isArray(a?.conduct_entry_hashes)
          ? a.conduct_entry_hashes.map(String)
          : [],
      })),
    });
    const expected = sha256HexUtf8(stableStringify(preimage));
    observedSetDigestMatches = String(doc.observed_set_digest || '').toLowerCase() === expected;
  }

  const hashOnlySurface = !hasForbiddenKeys(doc);
  const profileComplete =
    schemaValid &&
    organizationIdPresent &&
    periodLabelPresent &&
    windowValid &&
    observedPresent &&
    observedFieldsValid &&
    observedSetDigestMatches &&
    hashOnlySurface;

  let note: string | null = null;
  if (!schemaValid) note = `schema must be ${OBSERVED_AGENT_CONDUCT_SET_SCHEMA}`;
  else if (!observedSetDigestMatches) note = 'observed_set_digest does not match canonical preimage';

  return {
    schema: OBSERVED_AGENT_CONDUCT_SET_SCHEMA,
    sku: OBSERVED_AGENT_CONDUCT_SET_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      organizationIdPresent,
      periodLabelPresent,
      windowValid,
      observedPresent,
      observedFieldsValid,
      observedSetDigestMatches,
      hashOnlySurface,
      profileComplete,
    },
    gtmLine: 'Conduct-observed agent set — binds what agents actually acted, not what the roster claims.',
    note,
  };
}
