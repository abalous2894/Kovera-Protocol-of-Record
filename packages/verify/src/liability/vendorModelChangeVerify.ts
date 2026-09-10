import { sha256HexUtf8 } from '../core/sha256.js';
import { VENDOR_MODEL_CHANGE_SCHEMA, buildVendorModelChangePreimage } from '../core/vendorModelChange.js';
import { stableStringify } from '../core/stableStringify.js';
import type { ModelChangeType } from '../core/vendorModelChange.js';

export const VENDOR_MODEL_CHANGE_SKU = 'aevesa-vendor-model-change-v1' as const;

const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|ssn|phone|address|pan|cvv)$/i;
const HEX64 = /^[a-f0-9]{64}$/;

export interface VendorModelChangeVerifyResult {
  schema: typeof VENDOR_MODEL_CHANGE_SCHEMA;
  sku: typeof VENDOR_MODEL_CHANGE_SKU;
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

export function verifyVendorModelChange(docInput: unknown): VendorModelChangeVerifyResult {
  const doc = asRecord(docInput);
  const schemaValid = doc?.schema === VENDOR_MODEL_CHANGE_SCHEMA;
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;
  const vendorIdPresent = String(doc?.vendor_id || '').trim().length > 0;
  const changeIdPresent = String(doc?.change_id || '').trim().length > 0;
  const effectiveAtPresent = String(doc?.effective_at || '').trim().length > 0;
  const beforeFp = String(doc?.model_fingerprint_before || '').trim();
  const afterFp = String(doc?.model_fingerprint_after || '').trim();
  const fingerprintsDiffer = beforeFp.length > 0 && afterFp.length > 0 && beforeFp !== afterFp;

  const guardrailBefore = doc?.guardrail_policy_digest_before;
  const guardrailAfter = doc?.guardrail_policy_digest_after;
  const guardrailDigestsValid =
    (guardrailBefore == null || HEX64.test(String(guardrailBefore).toLowerCase())) &&
    (guardrailAfter == null || HEX64.test(String(guardrailAfter).toLowerCase()));

  let changeDigestMatches = false;
  if (schemaValid && doc && fingerprintsDiffer && guardrailDigestsValid) {
    const preimage = buildVendorModelChangePreimage({
      organization_id: String(doc.organization_id),
      vendor_id: String(doc.vendor_id),
      vendor_display_name: doc.vendor_display_name != null ? String(doc.vendor_display_name) : null,
      change_id: String(doc.change_id),
      change_type: String(doc.change_type || 'model_version') as ModelChangeType,
      effective_at: String(doc.effective_at),
      generated_at: String(doc.generated_at || ''),
      model_fingerprint_before: beforeFp,
      model_fingerprint_after: afterFp,
      guardrail_policy_digest_before:
        guardrailBefore != null ? String(guardrailBefore) : null,
      guardrail_policy_digest_after: guardrailAfter != null ? String(guardrailAfter) : null,
      change_summary: doc.change_summary != null ? String(doc.change_summary) : null,
    });
    const expected = sha256HexUtf8(stableStringify(preimage));
    changeDigestMatches = String(doc.change_digest || '').toLowerCase() === expected;
  }

  const hashOnlySurface = !hasForbiddenKeys(doc);

  const profileComplete =
    schemaValid &&
    organizationIdPresent &&
    vendorIdPresent &&
    changeIdPresent &&
    effectiveAtPresent &&
    fingerprintsDiffer &&
    guardrailDigestsValid &&
    changeDigestMatches &&
    hashOnlySurface;

  let note: string | null = null;
  if (!schemaValid) note = `schema must be ${VENDOR_MODEL_CHANGE_SCHEMA}`;
  else if (!fingerprintsDiffer) note = 'model fingerprints before/after must differ';
  else if (!changeDigestMatches) note = 'change_digest does not match canonical preimage';

  return {
    schema: VENDOR_MODEL_CHANGE_SCHEMA,
    sku: VENDOR_MODEL_CHANGE_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      organizationIdPresent,
      vendorIdPresent,
      changeIdPresent,
      effectiveAtPresent,
      fingerprintsDiffer,
      guardrailDigestsValid,
      changeDigestMatches,
      hashOnlySurface,
      profileComplete,
    },
    note,
  };
}
