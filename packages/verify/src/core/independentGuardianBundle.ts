import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';
import type { WitnessDiversityBlock } from './witnessDiversity.js';
import type { TransparencyLogMonitorAttestationDocument } from './transparencyLogMonitorAttestation.js';

export const INDEPENDENT_GUARDIAN_BUNDLE_SCHEMA = 'aevesa.independent-guardian-bundle/v1' as const;

export const INDEPENDENT_GUARDIAN_BUNDLE_MODES = [
  'dual_profile',
  'custodian_only',
  'denied_only',
] as const;

export type IndependentGuardianBundleMode = (typeof INDEPENDENT_GUARDIAN_BUNDLE_MODES)[number];

export const INDEPENDENT_GUARDIAN_MEMBER_PROFILES = ['PERMITTED', 'DENIED'] as const;

export type IndependentGuardianMemberProfile = (typeof INDEPENDENT_GUARDIAN_MEMBER_PROFILES)[number];

export interface IndependentGuardianMember {
  member_id: string;
  entry_hash: string;
  receipt_profile: IndependentGuardianMemberProfile;
  receipt?: Record<string, unknown> | null;
}

export interface IndependentGuardianVerifyManifest {
  offline_cli: string;
  portal_base: string;
  receipt_schema: string;
  custodian_verify_schema: string;
  bundle_schema: string;
}

export interface IndependentGuardianBundleInput {
  bundle_id: string;
  organization_id: string;
  bundle_mode: IndependentGuardianBundleMode;
  members: IndependentGuardianMember[];
  verify_manifest: IndependentGuardianVerifyManifest;
  exported_at?: string;
  non_goals?: string[];
  witness_diversity?: WitnessDiversityBlock | null;
  transparency_log_monitor_attestation?: TransparencyLogMonitorAttestationDocument | null;
}



export function buildIndependentGuardianBundlePreimage(
  input: IndependentGuardianBundleInput,
): Record<string, unknown> {
  const members = [...(input.members || [])]
    .sort((a, b) => String(a.member_id).localeCompare(String(b.member_id)))
    .map((m) => ({
      member_id: String(m.member_id || '').trim(),
      entry_hash: String(m.entry_hash || '').trim().toLowerCase(),
      receipt_profile: m.receipt_profile,
    }));

  return {
    schema: INDEPENDENT_GUARDIAN_BUNDLE_SCHEMA,
    bundle_id: String(input.bundle_id || '').trim(),
    organization_id: String(input.organization_id || '').trim(),
    bundle_mode: input.bundle_mode,
    exported_at: input.exported_at || new Date(0).toISOString(),
    members,
    verify_manifest: input.verify_manifest,
    non_goals: input.non_goals ?? [],
    ...(input.witness_diversity ? { witness_diversity: input.witness_diversity } : {}),
    ...(input.transparency_log_monitor_attestation
      ? { transparency_log_monitor_attestation: input.transparency_log_monitor_attestation }
      : {}),
  };
}

export function buildIndependentGuardianBundleDocument(input: IndependentGuardianBundleInput) {
  const exported_at = input.exported_at || new Date().toISOString();
  const preimage = buildIndependentGuardianBundlePreimage({ ...input, exported_at });
  const bundle_digest = sha256HexUtf8(stableStringify(preimage));
  const members = [...(input.members || [])].sort((a, b) =>
    String(a.member_id).localeCompare(String(b.member_id)),
  );

  return {
    ...preimage,
    exported_at,
    members,
    bundle_digest,
  };
}
