import { sha256HexUtf8 } from './sha256.js';
import { stableStringify } from './stableStringify.js';
import {
  buildAddonVettingAttestationDigest,
  type AddonVettingEnvelope,
  type AddonVettingVendorId,
  type AddonVettingVerdict,
} from './addonVettingAdapter.js';

/** Wave 14 Track B — add-on vetting provenance bind (INT-02). */

export const ADDON_VETTING_PROVENANCE_SCHEMA = 'aevesa.addon-vetting-provenance/v1' as const;

/** Default AIR-shaped weekly re-vet cadence when vendor omits explicit window. */
export const DEFAULT_ADDON_VETTING_CADENCE_DAYS = 7;

export type ProvenanceReadiness = 'provenance_ready' | 'partial' | 'stale';

export interface ProvenanceAssertionsInput {
  third_party_verifiable: boolean;
}

export interface ProvenanceSessionBinding {
  session_id: string;
  manifest_fingerprint_digest: string;
  vetting_attestation_digest: string;
  action_executed_at: string;
  normalization_bound: boolean;
}

export interface AddonVettingProvenanceInput {
  organization_id: string;
  session_id: string;
  generated_at?: string;
  vetting_vendor_id: AddonVettingVendorId;
  vendor_vetting_id: string;
  vetting_verdict: AddonVettingVerdict;
  vetting_attestation_digest: string;
  manifest_fingerprint_digest: string;
  manifest_version_id: string;
  addon_id_digest: string;
  policy_digest?: string | null;
  vetting_evaluated_at: string;
  action_executed_at: string;
  re_vet_cadence_days?: number | null;
  tool_manifest_fingerprint?: Record<string, unknown> | null;
  liability_receipt_digest?: string | null;
  provenance_session_binding: ProvenanceSessionBinding;
  provenance_assertions: ProvenanceAssertionsInput;
  disclaimer?: string;
}

export function computeDaysBetweenVettingAndAction(
  vettingEvaluatedAt: string,
  actionExecutedAt: string,
): number | null {
  const vettingMs = Date.parse(String(vettingEvaluatedAt || '').trim());
  const actionMs = Date.parse(String(actionExecutedAt || '').trim());
  if (!Number.isFinite(vettingMs) || !Number.isFinite(actionMs)) return null;
  const diffMs = actionMs - vettingMs;
  if (diffMs < 0) return null;
  return Math.floor(diffMs / (24 * 60 * 60 * 1000));
}

export function deriveProvenanceReadiness(
  vettingCoversExecution: boolean,
  reVetCadenceMet: boolean,
  verdictApproved: boolean,
  thirdPartyVerifiable: boolean,
  normalizationBound: boolean,
  manifestFingerprintMatches: boolean,
): ProvenanceReadiness {
  if (
    vettingCoversExecution
    && reVetCadenceMet
    && verdictApproved
    && thirdPartyVerifiable
    && normalizationBound
    && manifestFingerprintMatches
  ) {
    return 'provenance_ready';
  }
  if (!reVetCadenceMet || !vettingCoversExecution) return 'stale';
  if (verdictApproved && normalizationBound && manifestFingerprintMatches) {
    return 'partial';
  }
  return 'partial';
}

export function evaluateVettingCoverage(
  vettingVerdict: AddonVettingVerdict,
  vettingEvaluatedAt: string,
  actionExecutedAt: string,
  reVetCadenceDays: number,
): { vetting_covers_execution: boolean; re_vet_cadence_met: boolean } {
  const days = computeDaysBetweenVettingAndAction(vettingEvaluatedAt, actionExecutedAt);
  const cadenceDays = Math.max(1, Number(reVetCadenceDays) || DEFAULT_ADDON_VETTING_CADENCE_DAYS);
  const re_vet_cadence_met = days != null && days <= cadenceDays;
  const vetting_covers_execution =
    vettingVerdict === 'APPROVED'
    && days != null
    && days >= 0
    && re_vet_cadence_met;
  return { vetting_covers_execution, re_vet_cadence_met };
}

export function buildProvenanceAssertionsBlock(
  input: ProvenanceAssertionsInput,
  vettingVerdict: AddonVettingVerdict,
  vettingEvaluatedAt: string,
  actionExecutedAt: string,
  reVetCadenceDays: number,
  normalizationBound: boolean,
  manifestFingerprintMatches: boolean,
) {
  const coverage = evaluateVettingCoverage(
    vettingVerdict,
    vettingEvaluatedAt,
    actionExecutedAt,
    reVetCadenceDays,
  );

  const provenance_readiness = deriveProvenanceReadiness(
    coverage.vetting_covers_execution,
    coverage.re_vet_cadence_met,
    vettingVerdict === 'APPROVED',
    input.third_party_verifiable === true,
    normalizationBound,
    manifestFingerprintMatches,
  );

  return {
    third_party_verifiable: input.third_party_verifiable === true,
    vetting_covers_execution: coverage.vetting_covers_execution,
    re_vet_cadence_met: coverage.re_vet_cadence_met,
    provenance_readiness,
  };
}

export function buildAddonVettingProvenancePreimage(
  input: Omit<AddonVettingProvenanceInput, 'disclaimer' | 'provenance_assertions'> & {
    generated_at: string;
    provenance_assertions: ReturnType<typeof buildProvenanceAssertionsBlock>;
  },
): Record<string, unknown> {
  const binding = input.provenance_session_binding;

  return {
    schema: ADDON_VETTING_PROVENANCE_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    session_id: String(input.session_id || '').trim(),
    generated_at: input.generated_at,
    vetting_vendor_id: input.vetting_vendor_id,
    vendor_vetting_id: String(input.vendor_vetting_id || '').trim(),
    vetting_verdict: input.vetting_verdict,
    vetting_attestation_digest: String(input.vetting_attestation_digest || '')
      .trim()
      .toLowerCase(),
    manifest_fingerprint_digest: String(input.manifest_fingerprint_digest || '')
      .trim()
      .toLowerCase(),
    manifest_version_id: String(input.manifest_version_id || '').trim(),
    addon_id_digest: String(input.addon_id_digest || '').trim().toLowerCase(),
    policy_digest: input.policy_digest
      ? String(input.policy_digest).trim().toLowerCase()
      : null,
    vetting_evaluated_at: String(input.vetting_evaluated_at || '').trim(),
    action_executed_at: String(input.action_executed_at || '').trim(),
    re_vet_cadence_days:
      input.re_vet_cadence_days != null
        ? Number(input.re_vet_cadence_days)
        : DEFAULT_ADDON_VETTING_CADENCE_DAYS,
    liability_receipt_digest: input.liability_receipt_digest
      ? String(input.liability_receipt_digest).toLowerCase()
      : null,
    provenance_session_binding: {
      session_id: String(binding.session_id || '').trim(),
      manifest_fingerprint_digest: String(binding.manifest_fingerprint_digest || '')
        .trim()
        .toLowerCase(),
      vetting_attestation_digest: String(binding.vetting_attestation_digest || '')
        .trim()
        .toLowerCase(),
      action_executed_at: String(binding.action_executed_at || '').trim(),
      normalization_bound: binding.normalization_bound === true,
    },
    provenance_assertions: input.provenance_assertions,
  };
}

export interface AddonVettingProvenanceDocument {
  schema: typeof ADDON_VETTING_PROVENANCE_SCHEMA;
  organization_id: string;
  session_id: string;
  generated_at: string;
  vetting_vendor_id: AddonVettingVendorId;
  vendor_vetting_id: string;
  vetting_verdict: AddonVettingVerdict;
  vetting_attestation_digest: string;
  manifest_fingerprint_digest: string;
  manifest_version_id: string;
  addon_id_digest: string;
  policy_digest: string | null;
  vetting_evaluated_at: string;
  action_executed_at: string;
  re_vet_cadence_days: number;
  tool_manifest_fingerprint?: Record<string, unknown> | null;
  liability_receipt_digest: string | null;
  provenance_session_binding: ProvenanceSessionBinding;
  provenance_assertions: ReturnType<typeof buildProvenanceAssertionsBlock>;
  bind_digest: string;
  disclaimer: string;
}

export function buildAddonVettingProvenanceDocument(
  input: AddonVettingProvenanceInput,
): AddonVettingProvenanceDocument {
  const generated_at = input.generated_at || new Date().toISOString();
  const re_vet_cadence_days =
    input.re_vet_cadence_days != null
      ? Number(input.re_vet_cadence_days)
      : DEFAULT_ADDON_VETTING_CADENCE_DAYS;

  const manifestMember = input.tool_manifest_fingerprint ?? null;
  const memberManifestDigest =
    manifestMember != null && typeof manifestMember.manifest_fingerprint === 'string'
      ? String(manifestMember.manifest_fingerprint).toLowerCase()
      : null;
  const manifestFingerprintMatches =
    memberManifestDigest == null
    || memberManifestDigest === String(input.manifest_fingerprint_digest || '').toLowerCase();

  const provenance_assertions = buildProvenanceAssertionsBlock(
    input.provenance_assertions,
    input.vetting_verdict,
    input.vetting_evaluated_at,
    input.action_executed_at,
    re_vet_cadence_days,
    input.provenance_session_binding.normalization_bound === true,
    manifestFingerprintMatches,
  );

  const {
    tool_manifest_fingerprint: _toolManifest,
    disclaimer: _disclaimer,
    provenance_assertions: _assertions,
    ...preimageFields
  } = input;

  const preimage = buildAddonVettingProvenancePreimage({
    ...preimageFields,
    generated_at,
    re_vet_cadence_days,
    provenance_assertions,
  });
  const bind_digest = sha256HexUtf8(stableStringify(preimage));

  return {
    ...(preimage as Omit<
      AddonVettingProvenanceDocument,
      'tool_manifest_fingerprint' | 'bind_digest' | 'disclaimer'
    >),
    tool_manifest_fingerprint: input.tool_manifest_fingerprint ?? null,
    bind_digest,
    disclaimer:
      input.disclaimer ??
      'Add-on vetting provenance bind — links vetting verdict to manifest fingerprint at execution; not legal advice.',
  };
}

export function buildAddonVettingProvenanceFromEnvelope(
  envelope: AddonVettingEnvelope,
  input: {
    organization_id: string;
    session_id: string;
    action_executed_at: string;
    generated_at?: string;
    tool_manifest_fingerprint?: Record<string, unknown> | null;
    liability_receipt_digest?: string | null;
    provenance_assertions?: ProvenanceAssertionsInput;
    disclaimer?: string;
  },
): AddonVettingProvenanceDocument {
  const vetting_attestation_digest = buildAddonVettingAttestationDigest(envelope);
  const generated_at = input.generated_at || new Date().toISOString();

  const provenance_session_binding: ProvenanceSessionBinding = {
    session_id: String(input.session_id || '').trim(),
    manifest_fingerprint_digest: String(envelope.manifest_fingerprint_digest || '')
      .trim()
      .toLowerCase(),
    vetting_attestation_digest,
    action_executed_at: String(input.action_executed_at || '').trim(),
    normalization_bound: true,
  };

  return buildAddonVettingProvenanceDocument({
    organization_id: input.organization_id,
    session_id: input.session_id,
    generated_at,
    vetting_vendor_id: envelope.vetting_vendor_id,
    vendor_vetting_id: envelope.vendor_vetting_id,
    vetting_verdict: envelope.vetting_verdict,
    vetting_attestation_digest,
    manifest_fingerprint_digest: envelope.manifest_fingerprint_digest,
    manifest_version_id: envelope.manifest_version_id,
    addon_id_digest: envelope.addon_id_digest,
    policy_digest: envelope.policy_digest,
    vetting_evaluated_at: envelope.evaluated_at,
    action_executed_at: input.action_executed_at,
    re_vet_cadence_days: envelope.re_vet_cadence_days,
    tool_manifest_fingerprint: input.tool_manifest_fingerprint ?? null,
    liability_receipt_digest: input.liability_receipt_digest ?? null,
    provenance_session_binding,
    provenance_assertions: input.provenance_assertions ?? { third_party_verifiable: true },
    disclaimer: input.disclaimer,
  });
}

export function recomputeVettingAttestationDigestFromDocument(
  doc: Pick<
    AddonVettingProvenanceInput,
    | 'vetting_vendor_id'
    | 'vendor_vetting_id'
    | 'vetting_verdict'
    | 'vetting_evaluated_at'
    | 'manifest_fingerprint_digest'
    | 'manifest_version_id'
    | 'addon_id_digest'
    | 're_vet_cadence_days'
    | 'policy_digest'
  > & { policy_digest?: string | null },
): string {
  return buildAddonVettingAttestationDigest({
    vetting_vendor_id: doc.vetting_vendor_id,
    vendor_vetting_id: doc.vendor_vetting_id,
    vetting_verdict: doc.vetting_verdict,
    evaluated_at: doc.vetting_evaluated_at,
    manifest_fingerprint_digest: doc.manifest_fingerprint_digest,
    manifest_version_id: doc.manifest_version_id,
    addon_id_digest: doc.addon_id_digest,
    policy_digest: doc.policy_digest ?? null,
    re_vet_cadence_days: doc.re_vet_cadence_days ?? DEFAULT_ADDON_VETTING_CADENCE_DAYS,
  });
}

export default {
  ADDON_VETTING_PROVENANCE_SCHEMA,
  DEFAULT_ADDON_VETTING_CADENCE_DAYS,
  buildAddonVettingProvenanceDocument,
  buildAddonVettingProvenanceFromEnvelope,
  buildAddonVettingProvenancePreimage,
  buildProvenanceAssertionsBlock,
  computeDaysBetweenVettingAndAction,
  deriveProvenanceReadiness,
  evaluateVettingCoverage,
  recomputeVettingAttestationDigestFromDocument,
};
