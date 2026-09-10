import { sha256HexUtf8 } from '../core/sha256.js';
import { buildPolicyAtChangeSnapshotPreimage, POLICY_AT_CHANGE_SNAPSHOT_SCHEMA } from '../core/vendorModelChange.js';
import { stableStringify } from '../core/stableStringify.js';

export const POLICY_AT_CHANGE_SNAPSHOT_SKU = 'aevesa-policy-at-change-snapshot-v1' as const;

const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|ssn|phone|address|pan|cvv)$/i;
const HEX64 = /^[a-f0-9]{64}$/;

export interface PolicyAtChangeSnapshotVerifyResult {
  schema: typeof POLICY_AT_CHANGE_SNAPSHOT_SCHEMA;
  sku: typeof POLICY_AT_CHANGE_SNAPSHOT_SKU;
  ok: boolean;
  checks: Record<string, boolean>;
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

export function verifyPolicyAtChangeSnapshot(docInput: unknown): PolicyAtChangeSnapshotVerifyResult {
  const doc = asRecord(docInput);
  const schemaValid = doc?.schema === POLICY_AT_CHANGE_SNAPSHOT_SCHEMA;
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;
  const changeIdPresent = String(doc?.change_id || '').trim().length > 0;
  const policyHashValid = HEX64.test(String(doc?.policy_version_hash || '').toLowerCase());

  let digestMatches = false;
  if (schemaValid && doc && policyHashValid) {
    const preimage = buildPolicyAtChangeSnapshotPreimage({
      organization_id: String(doc.organization_id),
      change_id: String(doc.change_id),
      policy_version_hash: String(doc.policy_version_hash),
      treaty_version: doc.treaty_version != null ? String(doc.treaty_version) : null,
      generated_at: String(doc.generated_at || ''),
    });
    const expected = sha256HexUtf8(stableStringify(preimage));
    digestMatches = String(doc.policy_at_change_digest || '').toLowerCase() === expected;
  }

  const hashOnlySurface = !hasForbiddenKeys(doc);

  const profileComplete =
    schemaValid &&
    organizationIdPresent &&
    changeIdPresent &&
    policyHashValid &&
    digestMatches &&
    hashOnlySurface;

  let note: string | null = null;
  if (!schemaValid) note = `schema must be ${POLICY_AT_CHANGE_SNAPSHOT_SCHEMA}`;
  else if (!digestMatches) note = 'policy_at_change_digest does not match canonical preimage';

  return {
    schema: POLICY_AT_CHANGE_SNAPSHOT_SCHEMA,
    sku: POLICY_AT_CHANGE_SNAPSHOT_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      organizationIdPresent,
      changeIdPresent,
      policyHashValid,
      digestMatches,
      hashOnlySurface,
      profileComplete,
    },
    note,
  };
}
