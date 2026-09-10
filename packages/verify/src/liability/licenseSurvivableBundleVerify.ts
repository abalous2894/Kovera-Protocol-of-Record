import { sha256HexUtf8 } from '../core/sha256.js';
import { LICENSE_SURVIVABLE_BUNDLE_SCHEMA, buildLicenseSurvivableBundlePreimage } from '../core/licenseSurvivableBundle.js';
import { stableStringify } from '../core/stableStringify.js';
import { verifyEvidenceResurrectionBatchBundle } from './evidenceResurrectionVerify.js';

export const LICENSE_SURVIVABLE_BUNDLE_SKU = 'aevesa-license-survivable-bundle-v1' as const;

export interface LicenseSurvivableBundleDocument {
  schema?: string;
  bundle_id?: string;
  organization_id?: string;
  attestation_mode?: string;
  resurrection_batch_id?: string;
  exported_at?: string;
  batch_manifest?: Record<string, unknown>;
  receipts?: Array<{
    receipt_id?: string;
    entry_hash?: string;
    gateway_decision_id?: string;
    attestation_mode?: string;
    verify_url?: string;
    receipt?: Record<string, unknown> | null;
  }>;
  verify_manifest?: Record<string, unknown>;
  bundle_digest?: string;
}

export interface LicenseSurvivableVerifyResult {
  schema: typeof LICENSE_SURVIVABLE_BUNDLE_SCHEMA;
  sku: typeof LICENSE_SURVIVABLE_BUNDLE_SKU;
  ok: boolean;
  checks: {
    schemaValid: boolean;
    organizationIdPresent: boolean;
    attestationModeResurrected: boolean;
    bundleDigestMatches: boolean;
    batchManifestValid: boolean;
    receiptsLabeledResurrected: boolean;
    profileComplete: boolean;
  };
  gtmLine: string;
  note: string | null;
}

export function verifyLicenseSurvivableBundle(
  input: unknown,
): LicenseSurvivableVerifyResult {
  const doc = input != null && typeof input === 'object' && !Array.isArray(input)
    ? (input as LicenseSurvivableBundleDocument)
    : null;

  const schemaValid = doc?.schema === LICENSE_SURVIVABLE_BUNDLE_SCHEMA;
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;
  const attestationModeResurrected = doc?.attestation_mode === 'resurrected';

  let bundleDigestMatches = false;
  if (doc?.bundle_id && organizationIdPresent && doc?.exported_at && doc?.verify_manifest) {
    const manifest = doc.verify_manifest as {
      offline_cli?: string;
      portal_base?: string;
      receipt_schema?: string;
      batch_schema?: string;
    };
    const expected = sha256HexUtf8(
      stableStringify(
        buildLicenseSurvivableBundlePreimage({
          bundle_id: String(doc.bundle_id),
          organization_id: String(doc.organization_id),
          resurrection_batch_id: String(doc.resurrection_batch_id || ''),
          batch_manifest: (doc.batch_manifest || {}) as Record<string, unknown>,
          receipts: (doc.receipts || []).map((r) => ({
            receipt_id: r.receipt_id,
            entry_hash: String(r.entry_hash || ''),
            gateway_decision_id: r.gateway_decision_id,
            attestation_mode: (r.attestation_mode === 'live' ? 'live' : 'resurrected') as 'resurrected' | 'live',
            verify_url: String(r.verify_url || ''),
            receipt: r.receipt ?? null,
          })),
          verify_manifest: {
            offline_cli: String(manifest.offline_cli || ''),
            portal_base: String(manifest.portal_base || ''),
            receipt_schema: String(manifest.receipt_schema || ''),
            batch_schema: String(manifest.batch_schema || ''),
            bundle_schema: LICENSE_SURVIVABLE_BUNDLE_SCHEMA,
          },
          exported_at: String(doc.exported_at),
        }),
      ),
    );
    bundleDigestMatches = Boolean(doc.bundle_digest) && doc.bundle_digest === expected;
  }

  const batchVerify = doc?.batch_manifest
    ? verifyEvidenceResurrectionBatchBundle(doc.batch_manifest)
    : { ok: false };
  const batchManifestValid = batchVerify.ok === true;

  const receiptsLabeledResurrected =
    Array.isArray(doc?.receipts) &&
    doc!.receipts.length > 0 &&
    doc!.receipts.every((r) => r.attestation_mode === 'resurrected');

  const profileComplete =
    schemaValid &&
    organizationIdPresent &&
    attestationModeResurrected &&
    bundleDigestMatches &&
    batchManifestValid &&
    receiptsLabeledResurrected;

  let note: string | null = null;
  if (profileComplete) {
    note = 'License-survivable bundle verified — resurrected receipts + batch manifest offline';
  } else if (!bundleDigestMatches) {
    note = 'bundle_digest does not match bundle preimage';
  } else if (!batchManifestValid) {
    note = 'embedded batch_manifest failed evidence resurrection verify';
  } else if (!receiptsLabeledResurrected) {
    note = 'all receipts must carry attestation_mode resurrected';
  } else {
    note = 'License-survivable bundle verification failed';
  }

  return {
    schema: LICENSE_SURVIVABLE_BUNDLE_SCHEMA,
    sku: LICENSE_SURVIVABLE_BUNDLE_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      organizationIdPresent,
      attestationModeResurrected,
      bundleDigestMatches,
      batchManifestValid,
      receiptsLabeledResurrected,
      profileComplete,
    },
    gtmLine:
      'Platform logs expire with your contract. Resurrected receipts verify without Microsoft, Databricks, or Cyera.',
    note,
  };
}
