import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';

export const LICENSE_SURVIVABLE_BUNDLE_SCHEMA = 'aevesa.license-survivable-bundle/v1' as const;

export interface LicenseSurvivableReceiptEntry {
  receipt_id?: string;
  entry_hash: string;
  gateway_decision_id?: string;
  attestation_mode: 'resurrected' | 'live';
  verify_url: string;
  receipt?: Record<string, unknown> | null;
}

export interface LicenseSurvivableVerifyManifest {
  offline_cli: string;
  portal_base: string;
  receipt_schema: string;
  batch_schema: string;
  bundle_schema?: string;
}

export interface LicenseSurvivableBundleInput {
  bundle_id: string;
  organization_id: string;
  resurrection_batch_id: string;
  batch_manifest: Record<string, unknown>;
  receipts: LicenseSurvivableReceiptEntry[];
  verify_manifest: LicenseSurvivableVerifyManifest;
  exported_at?: string;
}



export function buildLicenseSurvivableBundlePreimage(input: LicenseSurvivableBundleInput): Record<string, unknown> {
  const receipts = [...(input.receipts || [])].sort((a, b) =>
    String(a.entry_hash).localeCompare(String(b.entry_hash)),
  );
  return {
    schema: LICENSE_SURVIVABLE_BUNDLE_SCHEMA,
    bundle_id: String(input.bundle_id || '').trim(),
    organization_id: String(input.organization_id || '').trim(),
    attestation_mode: 'resurrected',
    resurrection_batch_id: String(input.resurrection_batch_id || '').trim(),
    exported_at: input.exported_at || new Date(0).toISOString(),
    batch_manifest: input.batch_manifest,
    receipts: receipts.map((r) => ({
      receipt_id: r.receipt_id ?? null,
      entry_hash: r.entry_hash,
      gateway_decision_id: r.gateway_decision_id ?? null,
      attestation_mode: r.attestation_mode,
      verify_url: r.verify_url,
    })),
    verify_manifest: input.verify_manifest,
  };
}

export function buildLicenseSurvivableBundleDocument(input: LicenseSurvivableBundleInput) {
  const exported_at = input.exported_at || new Date().toISOString();
  const preimage = buildLicenseSurvivableBundlePreimage({ ...input, exported_at });
  const bundle_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    exported_at,
    receipts: [...(input.receipts || [])].sort((a, b) =>
      String(a.entry_hash).localeCompare(String(b.entry_hash)),
    ),
    bundle_digest,
  };
}
