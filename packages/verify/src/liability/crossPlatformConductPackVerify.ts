import { sha256HexUtf8 } from '../core/sha256.js';
import { CROSS_PLATFORM_CONDUCT_PACK_SCHEMA, buildCrossPlatformConductPackPreimage, deriveCrossPlatformReadiness } from '../core/crossPlatformConductPack.js';
import { stableStringify } from '../core/stableStringify.js';
import type { CrossPlatformReadiness } from '../core/crossPlatformConductPack.js';

export const CROSS_PLATFORM_CONDUCT_PACK_SKU = 'aevesa-cross-platform-conduct-pack-v1' as const;

const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|ssn|phone|address|pan|cvv)$/i;
const HEX64 = /^[a-f0-9]{64}$/;

export interface CrossPlatformConductPackVerifyResult {
  schema: typeof CROSS_PLATFORM_CONDUCT_PACK_SCHEMA;
  sku: typeof CROSS_PLATFORM_CONDUCT_PACK_SKU;
  ok: boolean;
  checks: Record<string, boolean>;
  cross_platform_readiness: CrossPlatformReadiness | null;
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

export function verifyCrossPlatformConductPack(
  docInput: unknown,
): CrossPlatformConductPackVerifyResult {
  const doc = asRecord(docInput);
  const schemaValid = doc?.schema === CROSS_PLATFORM_CONDUCT_PACK_SCHEMA;
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;

  const members = Array.isArray(doc?.composed_members) ? doc.composed_members : [];
  const composedMembersPresent = members.length >= 3;
  const memberDigestsValid =
    members.length === 0 ||
    members.every((m) => HEX64.test(String(m?.member_digest || '').toLowerCase()));

  const binding = asRecord(doc?.vendor_session_binding) || {};
  const normalizationBound = binding.normalization_bound === true;
  const bindingDigestsValid =
    HEX64.test(String(binding.agt_receipt_digest || '').toLowerCase()) &&
    HEX64.test(String(binding.ap2_conduct_digest || '').toLowerCase()) &&
    HEX64.test(String(binding.conduct_manifest_digest || '').toLowerCase());

  const agtMember = members.find((m) => m?.member_schema === 'aevesa.agt-conduct-receipt/v1');
  const ap2Member = members.find((m) => m?.member_schema === 'aevesa.ap2-conduct-receipt/v1');
  const manifestMember = members.find(
    (m) => m?.member_schema === 'aevesa.traceable-conduct-manifest/v1',
  );

  const bindingMatchesMembers =
    (!agtMember ||
      String(binding.agt_receipt_digest || '').toLowerCase() ===
        String(agtMember.member_digest || '').toLowerCase()) &&
    (!ap2Member ||
      String(binding.ap2_conduct_digest || '').toLowerCase() ===
        String(ap2Member.member_digest || '').toLowerCase()) &&
    (!manifestMember ||
      String(binding.conduct_manifest_digest || '').toLowerCase() ===
        String(manifestMember.member_digest || '').toLowerCase());

  const derivedReadiness = deriveCrossPlatformReadiness(
    members.map((m) => ({
      member_schema: String(m?.member_schema || ''),
      member_digest: String(m?.member_digest || ''),
      verify_ok: m?.verify_ok === true,
      label: String(m?.label || ''),
      vendor_plane: String(m?.vendor_plane || ''),
      entry_count: m?.entry_count ?? null,
    })),
    normalizationBound,
  );

  const assertions = asRecord(doc?.cross_platform_assertions) || {};
  const agtOk = agtMember?.verify_ok === true;
  const ap2Ok = ap2Member?.verify_ok === true;
  const manifestOk = manifestMember?.verify_ok === true;

  let crossPlatformAssertionsConsistent =
    assertions.third_party_verifiable === true &&
    String(binding.correlation_id || '').trim().length > 0;
  if (derivedReadiness === 'unified') {
    crossPlatformAssertionsConsistent =
      crossPlatformAssertionsConsistent &&
      assertions.agt_normalized_to_ap2 === true &&
      assertions.session_correlation_bound === true &&
      assertions.multi_vendor_conduct_unified === true &&
      agtOk &&
      ap2Ok &&
      manifestOk &&
      normalizationBound;
  } else if (derivedReadiness === 'partial') {
    crossPlatformAssertionsConsistent = crossPlatformAssertionsConsistent && (agtOk || ap2Ok);
  }

  const readinessConsistent = assertions.cross_platform_readiness === derivedReadiness;

  let packDigestMatches = false;
  if (schemaValid && doc && bindingDigestsValid) {
    const preimage = buildCrossPlatformConductPackPreimage({
      organization_id: String(doc.organization_id),
      generated_at: String(doc.generated_at || ''),
      cross_platform_assertions: {
        agt_normalized_to_ap2: assertions.agt_normalized_to_ap2 === true,
        session_correlation_bound: assertions.session_correlation_bound === true,
        multi_vendor_conduct_unified: assertions.multi_vendor_conduct_unified === true,
        third_party_verifiable: assertions.third_party_verifiable === true,
        cross_platform_readiness: String(
          assertions.cross_platform_readiness || derivedReadiness,
        ) as CrossPlatformReadiness,
      },
      composed_members: members.map((m) => ({
        member_schema: String(m?.member_schema || ''),
        member_digest: String(m?.member_digest || ''),
        verify_ok: m?.verify_ok === true,
        label: String(m?.label || ''),
        vendor_plane: String(m?.vendor_plane || ''),
        entry_count: m?.entry_count ?? null,
      })),
      vendor_session_binding: {
        session_id: String(binding.session_id || ''),
        correlation_id: String(binding.correlation_id || ''),
        vendor_planes: Array.isArray(binding.vendor_planes) ? binding.vendor_planes.map(String) : [],
        agt_receipt_digest: String(binding.agt_receipt_digest || ''),
        ap2_conduct_digest: String(binding.ap2_conduct_digest || ''),
        conduct_manifest_digest: String(binding.conduct_manifest_digest || ''),
        normalization_bound: normalizationBound,
      },
    });
    const expected = sha256HexUtf8(stableStringify(preimage));
    packDigestMatches = String(doc.pack_digest || '').toLowerCase() === expected;
  }

  const hashOnlySurface = !hasForbiddenKeys(doc);

  const profileComplete =
    schemaValid &&
    organizationIdPresent &&
    composedMembersPresent &&
    memberDigestsValid &&
    bindingDigestsValid &&
    bindingMatchesMembers &&
    crossPlatformAssertionsConsistent &&
    packDigestMatches &&
    hashOnlySurface &&
    readinessConsistent;

  let note: string | null = null;
  if (!schemaValid) note = `schema must be ${CROSS_PLATFORM_CONDUCT_PACK_SCHEMA}`;
  else if (!bindingMatchesMembers) note = 'vendor_session_binding digests must match composed members';
  else if (!packDigestMatches) note = 'pack_digest does not match canonical preimage';
  else if (!crossPlatformAssertionsConsistent) {
    note = 'cross_platform_assertions inconsistent with composed members';
  } else if (!readinessConsistent) note = 'cross_platform_readiness inconsistent with member verify state';

  return {
    schema: CROSS_PLATFORM_CONDUCT_PACK_SCHEMA,
    sku: CROSS_PLATFORM_CONDUCT_PACK_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      organizationIdPresent,
      composedMembersPresent,
      memberDigestsValid,
      bindingDigestsValid,
      bindingMatchesMembers,
      crossPlatformAssertionsConsistent,
      packDigestMatches,
      hashOnlySurface,
      readinessConsistent,
      profileComplete,
    },
    cross_platform_readiness: derivedReadiness,
    gtmLine:
      'Microsoft + PANW + CrowdStrike each enforce on their plane. Aevesa normalizes conduct to one offline-verifiable session proof.',
    note,
  };
}
