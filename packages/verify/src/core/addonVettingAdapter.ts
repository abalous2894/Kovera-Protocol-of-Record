import { sha256HexUtf8 } from './sha256.js';
import { stableStringify } from './stableStringify.js';

/** Wave 14 Track B — add-on vetting vendor envelope normalization (INT-02). */

export const AIR_SECURITY_ADDON_VETTING_SCHEMA = 'air.security.addon-vetting/v1' as const;
export const INTERNAL_REVIEW_ADDON_VETTING_SCHEMA = 'internal.addon-vetting/v1' as const;
export const MARKETPLACE_CURATOR_ADDON_VETTING_SCHEMA = 'marketplace.addon-vetting/v1' as const;

export const ADDON_VETTING_VENDOR_IDS = [
  'air_security',
  'internal_review',
  'marketplace_curator',
  'hash_only',
] as const;

export type AddonVettingVendorId = (typeof ADDON_VETTING_VENDOR_IDS)[number];

export const ADDON_VETTING_VERDICTS = ['APPROVED', 'DENIED', 'QUARANTINED'] as const;
export type AddonVettingVerdict = (typeof ADDON_VETTING_VERDICTS)[number];

export interface AddonVettingEnvelope {
  vetting_vendor_id: AddonVettingVendorId;
  vendor_vetting_id: string;
  vetting_verdict: AddonVettingVerdict;
  evaluated_at: string;
  manifest_fingerprint_digest: string;
  manifest_version_id: string;
  addon_id_digest: string;
  policy_digest: string | null;
  re_vet_cadence_days: number | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function digestString(value: string): string {
  return sha256HexUtf8(
    stableStringify({
      schema: 'aevesa.addon-string-digest/v1',
      value: String(value || '').trim(),
    }),
  );
}

function digestJson(value: unknown): string {
  return sha256HexUtf8(stableStringify(value));
}

export function mapVettingVerdict(raw: unknown): AddonVettingVerdict {
  const normalized = String(raw || '').trim().toUpperCase();
  if (normalized === 'DENY' || normalized === 'DENIED' || normalized === 'BLOCK') return 'DENIED';
  if (normalized === 'QUARANTINE' || normalized === 'QUARANTINED' || normalized === 'HOLD') {
    return 'QUARANTINED';
  }
  return 'APPROVED';
}

export function canonicalizeAddonVettingEnvelope(
  envelope: AddonVettingEnvelope,
): Record<string, unknown> {
  return {
    vetting_vendor_id: envelope.vetting_vendor_id,
    vendor_vetting_id: String(envelope.vendor_vetting_id || '').trim(),
    vetting_verdict: envelope.vetting_verdict,
    evaluated_at: String(envelope.evaluated_at || '').trim(),
    manifest_fingerprint_digest: String(envelope.manifest_fingerprint_digest || '')
      .trim()
      .toLowerCase(),
    manifest_version_id: String(envelope.manifest_version_id || '').trim(),
    addon_id_digest: String(envelope.addon_id_digest || '').trim().toLowerCase(),
    policy_digest: envelope.policy_digest
      ? String(envelope.policy_digest).trim().toLowerCase()
      : null,
    re_vet_cadence_days:
      envelope.re_vet_cadence_days != null ? Number(envelope.re_vet_cadence_days) : null,
  };
}

export function buildAddonVettingAttestationDigest(envelope: AddonVettingEnvelope): string {
  return sha256HexUtf8(
    stableStringify({
      schema: 'aevesa.addon-vetting-attestation-envelope/v1',
      ...canonicalizeAddonVettingEnvelope(envelope),
    }),
  );
}

export function normalizeAirSecurityAddonVetting(rawInput: unknown): AddonVettingEnvelope {
  const raw = asRecord(rawInput);
  if (!raw) {
    throw new Error('AIR Security add-on vetting payload must be an object');
  }

  const addon = asRecord(raw.addon) || {};
  const addonId =
    (typeof addon.id === 'string' && addon.id)
    || (typeof raw.addon_id === 'string' && raw.addon_id)
    || 'unknown-addon';

  const manifestDigest =
    (typeof raw.manifest_fingerprint_digest === 'string' && raw.manifest_fingerprint_digest)
    || (typeof raw.manifest_digest === 'string' && raw.manifest_digest)
    || digestJson({
      addon_type: addon.type ?? raw.addon_type ?? 'mcp_server',
      addon_id: addonId,
      manifest_version: raw.manifest_version_id ?? raw.manifest_version ?? '1',
    });

  const envelope: AddonVettingEnvelope = {
    vetting_vendor_id: 'air_security',
    vendor_vetting_id: String(raw.vetting_id || raw.decision_id || raw.id || '').trim(),
    vetting_verdict: mapVettingVerdict(raw.verdict ?? raw.decision ?? raw.status),
    evaluated_at: String(raw.evaluated_at || raw.vetted_at || raw.checked_at || '').trim(),
    manifest_fingerprint_digest: manifestDigest,
    manifest_version_id: String(
      raw.manifest_version_id ?? raw.manifest_version ?? addon.version ?? '1',
    ).trim(),
    addon_id_digest: digestString(addonId),
    policy_digest:
      typeof raw.policy_digest === 'string'
        ? raw.policy_digest
        : typeof raw.policy_id === 'string'
          ? digestString(raw.policy_id)
          : null,
    re_vet_cadence_days:
      raw.re_vet_cadence_days != null
        ? Number(raw.re_vet_cadence_days)
        : raw.cadence_days != null
          ? Number(raw.cadence_days)
          : 7,
  };

  if (!envelope.vendor_vetting_id) {
    throw new Error('AIR Security add-on vetting payload missing vetting_id');
  }
  if (!envelope.evaluated_at) {
    throw new Error('AIR Security add-on vetting payload missing evaluated_at');
  }

  return envelope;
}

export function normalizeInternalReviewAddonVetting(rawInput: unknown): AddonVettingEnvelope {
  const raw = asRecord(rawInput);
  if (!raw) {
    throw new Error('Internal review add-on vetting payload must be an object');
  }

  const envelope: AddonVettingEnvelope = {
    vetting_vendor_id: 'internal_review',
    vendor_vetting_id: String(raw.review_id || raw.vetting_id || '').trim(),
    vetting_verdict: mapVettingVerdict(raw.verdict ?? raw.status),
    evaluated_at: String(raw.reviewed_at || raw.evaluated_at || '').trim(),
    manifest_fingerprint_digest: String(
      raw.manifest_fingerprint_digest || raw.manifest_digest || '',
    ).trim(),
    manifest_version_id: String(raw.manifest_version_id || raw.manifest_version || '1').trim(),
    addon_id_digest: digestString(String(raw.addon_id || raw.package_id || 'internal-addon')),
    policy_digest: typeof raw.policy_digest === 'string' ? raw.policy_digest : null,
    re_vet_cadence_days: raw.re_vet_cadence_days != null ? Number(raw.re_vet_cadence_days) : 30,
  };

  if (!envelope.vendor_vetting_id || !envelope.evaluated_at) {
    throw new Error('Internal review vetting payload missing review_id or reviewed_at');
  }

  return envelope;
}

export function normalizeMarketplaceCuratorAddonVetting(rawInput: unknown): AddonVettingEnvelope {
  const raw = asRecord(rawInput);
  if (!raw) {
    throw new Error('Marketplace curator add-on vetting payload must be an object');
  }

  const listing = asRecord(raw.listing) || {};
  const listingId =
    (typeof listing.id === 'string' && listing.id)
    || (typeof raw.listing_id === 'string' && raw.listing_id)
    || 'marketplace-listing';

  const envelope: AddonVettingEnvelope = {
    vetting_vendor_id: 'marketplace_curator',
    vendor_vetting_id: String(raw.curator_vetting_id || raw.vetting_id || listingId).trim(),
    vetting_verdict: mapVettingVerdict(raw.verdict ?? raw.approval_status),
    evaluated_at: String(raw.curated_at || raw.evaluated_at || '').trim(),
    manifest_fingerprint_digest: String(
      raw.manifest_fingerprint_digest || raw.listing_manifest_digest || '',
    ).trim(),
    manifest_version_id: String(
      raw.manifest_version_id ?? listing.version ?? raw.version ?? '1',
    ).trim(),
    addon_id_digest: digestString(listingId),
    policy_digest: typeof raw.policy_digest === 'string' ? raw.policy_digest : null,
    re_vet_cadence_days: raw.re_vet_cadence_days != null ? Number(raw.re_vet_cadence_days) : 14,
  };

  if (!envelope.vendor_vetting_id || !envelope.evaluated_at) {
    throw new Error('Marketplace curator vetting payload missing vetting id or evaluated_at');
  }

  return envelope;
}

export function coerceAddonVettingEnvelope(
  rawInput: unknown,
  vendorHint?: string | null,
): AddonVettingEnvelope {
  const raw = asRecord(rawInput);
  const schema = String(raw?.schema || vendorHint || '').trim().toLowerCase();

  if (schema.includes('air.security') || vendorHint === 'air_security') {
    return normalizeAirSecurityAddonVetting(rawInput);
  }
  if (schema.includes('internal.addon-vetting') || vendorHint === 'internal_review') {
    return normalizeInternalReviewAddonVetting(rawInput);
  }
  if (schema.includes('marketplace.addon-vetting') || vendorHint === 'marketplace_curator') {
    return normalizeMarketplaceCuratorAddonVetting(rawInput);
  }

  if (raw?.vetting_vendor_id === 'internal_review') {
    return normalizeInternalReviewAddonVetting(rawInput);
  }
  if (raw?.vetting_vendor_id === 'marketplace_curator') {
    return normalizeMarketplaceCuratorAddonVetting(rawInput);
  }

  return normalizeAirSecurityAddonVetting(rawInput);
}

export default {
  AIR_SECURITY_ADDON_VETTING_SCHEMA,
  INTERNAL_REVIEW_ADDON_VETTING_SCHEMA,
  MARKETPLACE_CURATOR_ADDON_VETTING_SCHEMA,
  ADDON_VETTING_VENDOR_IDS,
  ADDON_VETTING_VERDICTS,
  mapVettingVerdict,
  canonicalizeAddonVettingEnvelope,
  buildAddonVettingAttestationDigest,
  normalizeAirSecurityAddonVetting,
  normalizeInternalReviewAddonVetting,
  normalizeMarketplaceCuratorAddonVetting,
  coerceAddonVettingEnvelope,
};
