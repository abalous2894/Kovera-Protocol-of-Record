import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';

/** Wave 11 Track E — multi-vendor conduct normalization compose. */

export const CROSS_PLATFORM_CONDUCT_PACK_SCHEMA =
  'aevesa.cross-platform-conduct-pack/v1' as const;

export type CrossPlatformReadiness = 'unified' | 'partial' | 'single_vendor';

export interface ComposedConductMemberRef {
  member_schema: string;
  member_digest: string;
  verify_ok: boolean;
  label: string;
  vendor_plane: string;
  entry_count?: number | null;
}

export interface VendorSessionBindingInput {
  session_id: string;
  correlation_id: string;
  vendor_planes: string[];
  agt_receipt_digest: string;
  ap2_conduct_digest: string;
  conduct_manifest_digest: string;
  normalization_bound: boolean;
}

export interface CrossPlatformAssertionsInput {
  agt_normalized_to_ap2: boolean;
  session_correlation_bound: boolean;
  multi_vendor_conduct_unified: boolean;
  third_party_verifiable: boolean;
}

export interface CrossPlatformConductPackInput {
  organization_id: string;
  generated_at?: string;
  cross_platform_assertions: CrossPlatformAssertionsInput;
  composed_members: ComposedConductMemberRef[];
  vendor_session_binding: VendorSessionBindingInput;
  disclaimer?: string;
}



export function deriveCrossPlatformReadiness(
  members: ComposedConductMemberRef[],
  normalizationBound: boolean,
): CrossPlatformReadiness {
  const agt = (members || []).find(
    (m) => m.member_schema === 'aevesa.agt-conduct-receipt/v1' && m.verify_ok === true,
  );
  const ap2 = (members || []).find(
    (m) => m.member_schema === 'aevesa.ap2-conduct-receipt/v1' && m.verify_ok === true,
  );
  const manifest = (members || []).find(
    (m) => m.member_schema === 'aevesa.traceable-conduct-manifest/v1' && m.verify_ok === true,
  );
  if (agt && ap2 && manifest && normalizationBound) return 'unified';
  if (agt || ap2) return 'partial';
  return 'single_vendor';
}

export function buildCrossPlatformAssertionsBlock(
  input: CrossPlatformAssertionsInput,
  members: ComposedConductMemberRef[],
  normalizationBound: boolean,
) {
  const readiness = deriveCrossPlatformReadiness(members, normalizationBound);
  const vendorCount = new Set((members || []).map((m) => m.vendor_plane).filter(Boolean)).size;
  return {
    agt_normalized_to_ap2: input.agt_normalized_to_ap2 === true,
    session_correlation_bound: input.session_correlation_bound === true && normalizationBound,
    multi_vendor_conduct_unified: vendorCount >= 2 || input.multi_vendor_conduct_unified === true,
    third_party_verifiable: input.third_party_verifiable === true,
    cross_platform_readiness: readiness,
  };
}

export function buildCrossPlatformConductPackPreimage(
  input: Omit<CrossPlatformConductPackInput, 'disclaimer'> & {
    generated_at: string;
    cross_platform_assertions: ReturnType<typeof buildCrossPlatformAssertionsBlock>;
    composed_members: ComposedConductMemberRef[];
  },
): Record<string, unknown> {
  const members = [...(input.composed_members || [])]
    .map((m) => ({
      member_schema: String(m.member_schema || '').trim(),
      member_digest: String(m.member_digest || '').trim().toLowerCase(),
      verify_ok: m.verify_ok === true,
      label: String(m.label || '').trim(),
      vendor_plane: String(m.vendor_plane || '').trim(),
      entry_count: m.entry_count != null ? Number(m.entry_count) : null,
    }))
    .sort((a, b) => a.member_schema.localeCompare(b.member_schema));

  const binding = input.vendor_session_binding;
  return {
    schema: CROSS_PLATFORM_CONDUCT_PACK_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    generated_at: input.generated_at,
    cross_platform_assertions: input.cross_platform_assertions,
    composed_members: members,
    vendor_session_binding: {
      session_id: String(binding.session_id || '').trim(),
      correlation_id: String(binding.correlation_id || '').trim(),
      vendor_planes: [...(binding.vendor_planes || [])].sort(),
      agt_receipt_digest: String(binding.agt_receipt_digest || '').trim().toLowerCase(),
      ap2_conduct_digest: String(binding.ap2_conduct_digest || '').trim().toLowerCase(),
      conduct_manifest_digest: String(binding.conduct_manifest_digest || '').trim().toLowerCase(),
      normalization_bound: binding.normalization_bound === true,
    },
  };
}

export function buildCrossPlatformConductPackDocument(input: CrossPlatformConductPackInput) {
  const generated_at = input.generated_at || new Date().toISOString();
  const cross_platform_assertions = buildCrossPlatformAssertionsBlock(
    input.cross_platform_assertions,
    input.composed_members,
    input.vendor_session_binding.normalization_bound === true,
  );
  const preimage = buildCrossPlatformConductPackPreimage({
    ...input,
    generated_at,
    cross_platform_assertions,
    composed_members: input.composed_members,
  });
  const pack_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    pack_digest,
    disclaimer:
      input.disclaimer ||
      'Cross-vendor conduct export only — Aevesa does not replace Microsoft AGT, PANW, or CrowdStrike enforcement planes.',
  };
}

export default {
  CROSS_PLATFORM_CONDUCT_PACK_SCHEMA,
  deriveCrossPlatformReadiness,
  buildCrossPlatformAssertionsBlock,
  buildCrossPlatformConductPackDocument,
  buildCrossPlatformConductPackPreimage,
};
