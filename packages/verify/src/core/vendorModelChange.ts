import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';

/** Wave 12 Track E — vendor model or guardrail change event (hash-only fingerprints). */

export const VENDOR_MODEL_CHANGE_SCHEMA = 'aevesa.vendor-model-change/v1' as const;

export type ModelChangeType =
  | 'model_version'
  | 'guardrail_policy'
  | 'safety_classifier'
  | 'combined';

export interface VendorModelChangeInput {
  organization_id: string;
  vendor_id: string;
  vendor_display_name?: string | null;
  change_id: string;
  change_type: ModelChangeType;
  effective_at: string;
  generated_at?: string;
  model_fingerprint_before: string;
  model_fingerprint_after: string;
  guardrail_policy_digest_before?: string | null;
  guardrail_policy_digest_after?: string | null;
  change_summary?: string | null;
}



export function buildModelFingerprintDigest(fingerprint: string): string {
  return sha256HexUtf8(
    stableStringify({
      schema: 'aevesa.model-fingerprint/v1',
      fingerprint: String(fingerprint || '').trim(),
    }),
  );
}

export function buildVendorModelChangePreimage(
  input: VendorModelChangeInput & { generated_at: string },
): Record<string, unknown> {
  return {
    schema: VENDOR_MODEL_CHANGE_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    vendor_id: String(input.vendor_id || '').trim(),
    vendor_display_name: input.vendor_display_name ? String(input.vendor_display_name).trim() : null,
    change_id: String(input.change_id || '').trim(),
    change_type: input.change_type,
    effective_at: String(input.effective_at || '').trim(),
    generated_at: input.generated_at,
    model_fingerprint_before: String(input.model_fingerprint_before || '').trim(),
    model_fingerprint_after: String(input.model_fingerprint_after || '').trim(),
    model_fingerprint_digest_before: buildModelFingerprintDigest(input.model_fingerprint_before),
    model_fingerprint_digest_after: buildModelFingerprintDigest(input.model_fingerprint_after),
    guardrail_policy_digest_before: input.guardrail_policy_digest_before
      ? String(input.guardrail_policy_digest_before).trim().toLowerCase()
      : null,
    guardrail_policy_digest_after: input.guardrail_policy_digest_after
      ? String(input.guardrail_policy_digest_after).trim().toLowerCase()
      : null,
    change_summary: input.change_summary ? String(input.change_summary).trim() : null,
  };
}

export function buildVendorModelChangeDocument(input: VendorModelChangeInput) {
  const generated_at = input.generated_at || new Date().toISOString();
  const preimage = buildVendorModelChangePreimage({ ...input, generated_at });
  const change_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    change_digest,
  };
}

export function computeLeadTimeHours(notifiedAt: string, effectiveAt: string): number | null {
  const notifiedMs = Date.parse(String(notifiedAt || ''));
  const effectiveMs = Date.parse(String(effectiveAt || ''));
  if (!Number.isFinite(notifiedMs) || !Number.isFinite(effectiveMs)) return null;
  return Math.round((effectiveMs - notifiedMs) / 3600000);
}

export const MIN_VENDOR_NOTIFICATION_LEAD_HOURS = 48;

export const POLICY_AT_CHANGE_SNAPSHOT_SCHEMA = 'aevesa.policy-at-change-snapshot/v1' as const;

export interface PolicyAtChangeSnapshotInput {
  organization_id: string;
  change_id: string;
  policy_version_hash: string;
  treaty_version?: string | null;
  generated_at?: string;
}

export function buildPolicyAtChangeSnapshotPreimage(
  input: PolicyAtChangeSnapshotInput & { generated_at: string },
): Record<string, unknown> {
  return {
    schema: POLICY_AT_CHANGE_SNAPSHOT_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    change_id: String(input.change_id || '').trim(),
    generated_at: input.generated_at,
    policy_version_hash: String(input.policy_version_hash || '').trim().toLowerCase(),
    treaty_version: input.treaty_version ? String(input.treaty_version).trim() : null,
  };
}

export function buildPolicyAtChangeSnapshotDocument(input: PolicyAtChangeSnapshotInput) {
  const generated_at = input.generated_at || new Date().toISOString();
  const preimage = buildPolicyAtChangeSnapshotPreimage({ ...input, generated_at });
  const policy_at_change_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    policy_at_change_digest,
  };
}

export default {
  VENDOR_MODEL_CHANGE_SCHEMA,
  POLICY_AT_CHANGE_SNAPSHOT_SCHEMA,
  MIN_VENDOR_NOTIFICATION_LEAD_HOURS,
  buildVendorModelChangeDocument,
  buildPolicyAtChangeSnapshotDocument,
  buildModelFingerprintDigest,
  computeLeadTimeHours,
};
