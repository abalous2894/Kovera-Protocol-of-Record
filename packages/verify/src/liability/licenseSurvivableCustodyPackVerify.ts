import { sha256HexUtf8 } from '../core/sha256.js';
import { LICENSE_SURVIVABLE_CUSTODY_PACK_SCHEMA, buildLicenseSurvivableCustodyPackPreimage, derivePostTerminationReadiness } from '../core/licenseSurvivableCustodyPack.js';
import { stableStringify } from '../core/stableStringify.js';
import type { PostTerminationReadiness } from '../core/licenseSurvivableCustodyPack.js';

export const LICENSE_SURVIVABLE_CUSTODY_PACK_SKU =
  'aevesa-license-survivable-custody-pack-v1' as const;

const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|ssn|phone|address|pan|cvv)$/i;
const HEX64 = /^[a-f0-9]{64}$/;

export interface LicenseSurvivableCustodyPackDocument {
  schema?: string;
  organization_id?: string;
  session_id?: string;
  vendor_termination_ref?: string | null;
  generated_at?: string;
  custody_survival_assertions?: {
    deployer_controlled?: boolean;
    vendor_admin_plane_independent?: boolean;
    license_survivable?: boolean;
    post_termination_verify?: boolean;
    third_party_verifiable?: boolean;
    post_termination_readiness?: PostTerminationReadiness;
    deployer_custody_bound?: boolean;
  };
  composed_members?: Array<{
    member_schema?: string;
    member_digest?: string;
    verify_ok?: boolean;
    label?: string;
    entry_count?: number | null;
  }>;
  post_termination_verify?: {
    offline_cli?: string;
    portal_base?: string;
    no_backend_required?: boolean;
    deployer_custody_schema?: string;
    license_survivable_schema?: string;
    bundle_schema?: string;
  };
  pack_digest?: string;
}

export interface LicenseSurvivableCustodyPackVerifyChecks {
  schemaValid: boolean;
  organizationIdPresent: boolean;
  sessionIdPresent: boolean;
  composedMembersPresent: boolean;
  memberDigestsValid: boolean;
  postTerminationManifestPresent: boolean;
  custodyAssertionsConsistent: boolean;
  packDigestMatches: boolean;
  hashOnlySurface: boolean;
  readinessConsistent: boolean;
  profileComplete: boolean;
}

export interface LicenseSurvivableCustodyPackVerifyResult {
  schema: typeof LICENSE_SURVIVABLE_CUSTODY_PACK_SCHEMA;
  sku: typeof LICENSE_SURVIVABLE_CUSTODY_PACK_SKU;
  ok: boolean;
  checks: LicenseSurvivableCustodyPackVerifyChecks;
  post_termination_readiness: PostTerminationReadiness | null;
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
  if (Array.isArray(value)) {
    return value.some((v) => hasForbiddenKeys(v, depth + 1));
  }
  if (typeof value !== 'object') return false;
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (FORBIDDEN_KEYS.test(key)) return true;
    if (hasForbiddenKeys(child, depth + 1)) return true;
  }
  return false;
}

export function verifyLicenseSurvivableCustodyPack(
  docInput: unknown,
): LicenseSurvivableCustodyPackVerifyResult {
  const doc = asRecord(docInput) as LicenseSurvivableCustodyPackDocument | null;
  const schemaValid = doc?.schema === LICENSE_SURVIVABLE_CUSTODY_PACK_SCHEMA;

  const organization_id = String(doc?.organization_id || '').trim();
  const organizationIdPresent = organization_id.length > 0;

  const session_id = String(doc?.session_id || '').trim();
  const sessionIdPresent = session_id.length > 0;

  const members = Array.isArray(doc?.composed_members) ? doc.composed_members : [];
  const composedMembersPresent = members.length >= 2;
  const memberDigestsValid =
    members.length === 0 ||
    members.every((m) => HEX64.test(String(m?.member_digest || '').toLowerCase()));

  const derivedReadiness = derivePostTerminationReadiness(
    members.map((m) => ({
      member_schema: String(m?.member_schema || ''),
      member_digest: String(m?.member_digest || ''),
      verify_ok: m?.verify_ok === true,
      label: String(m?.label || ''),
      entry_count: m?.entry_count ?? null,
    })),
  );

  const assertions = doc?.custody_survival_assertions || {};
  const deployerMemberOk = members.some(
    (m) => m?.member_schema === 'aevesa.deployer-log-custody-pack/v1' && m?.verify_ok === true,
  );
  const survivableMemberOk = members.some(
    (m) => m?.member_schema === 'aevesa.license-survivable-bundle/v1' && m?.verify_ok === true,
  );

  const manifest = doc?.post_termination_verify || {};
  const postTerminationManifestPresent =
    String(manifest.offline_cli || '').trim().length > 0 &&
    String(manifest.portal_base || '').trim().length > 0 &&
    manifest.no_backend_required === true &&
    String(manifest.bundle_schema || '').trim() === LICENSE_SURVIVABLE_CUSTODY_PACK_SCHEMA;

  let custodyAssertionsConsistent =
    assertions.deployer_controlled === true &&
    assertions.vendor_admin_plane_independent === true &&
    assertions.post_termination_verify === true &&
    assertions.third_party_verifiable === true;
  if (derivedReadiness === 'complete') {
    custodyAssertionsConsistent =
      custodyAssertionsConsistent &&
      assertions.license_survivable === true &&
      deployerMemberOk &&
      survivableMemberOk;
  } else if (derivedReadiness === 'partial') {
    custodyAssertionsConsistent =
      custodyAssertionsConsistent && (deployerMemberOk || survivableMemberOk);
  }

  const readinessConsistent = assertions.post_termination_readiness === derivedReadiness;

  let packDigestMatches = false;
  if (schemaValid && doc && postTerminationManifestPresent) {
    const preimage = buildLicenseSurvivableCustodyPackPreimage({
      organization_id,
      session_id,
      vendor_termination_ref: doc.vendor_termination_ref ?? null,
      generated_at: String(doc.generated_at || ''),
      custody_survival_assertions: {
        deployer_controlled: assertions.deployer_controlled === true,
        vendor_admin_plane_independent: assertions.vendor_admin_plane_independent === true,
        license_survivable: assertions.license_survivable === true,
        post_termination_verify: assertions.post_termination_verify === true,
        third_party_verifiable: assertions.third_party_verifiable === true,
        post_termination_readiness: String(
          assertions.post_termination_readiness || derivedReadiness,
        ) as PostTerminationReadiness,
        deployer_custody_bound: assertions.deployer_custody_bound === true,
      },
      composed_members: members.map((m) => ({
        member_schema: String(m?.member_schema || ''),
        member_digest: String(m?.member_digest || ''),
        verify_ok: m?.verify_ok === true,
        label: String(m?.label || ''),
        entry_count: m?.entry_count ?? null,
      })),
      post_termination_verify: {
        offline_cli: String(manifest.offline_cli || ''),
        portal_base: String(manifest.portal_base || ''),
        no_backend_required: manifest.no_backend_required === true,
        deployer_custody_schema: String(manifest.deployer_custody_schema || ''),
        license_survivable_schema: String(manifest.license_survivable_schema || ''),
        bundle_schema: String(manifest.bundle_schema || ''),
      },
    });
    const expected = sha256HexUtf8(stableStringify(preimage));
    packDigestMatches = String(doc.pack_digest || '').toLowerCase() === expected;
  }

  const hashOnlySurface = !hasForbiddenKeys(doc);

  const profileComplete =
    schemaValid &&
    organizationIdPresent &&
    sessionIdPresent &&
    composedMembersPresent &&
    memberDigestsValid &&
    postTerminationManifestPresent &&
    custodyAssertionsConsistent &&
    packDigestMatches &&
    hashOnlySurface &&
    readinessConsistent;

  const ok = profileComplete;

  let note: string | null = null;
  if (!schemaValid) note = `schema must be ${LICENSE_SURVIVABLE_CUSTODY_PACK_SCHEMA}`;
  else if (!postTerminationManifestPresent) note = 'post_termination_verify manifest incomplete';
  else if (!packDigestMatches) note = 'pack_digest does not match canonical preimage';
  else if (!custodyAssertionsConsistent) {
    note = 'custody_survival_assertions inconsistent with composed members';
  } else if (!readinessConsistent) note = 'post_termination_readiness inconsistent with member verify state';
  else if (!memberDigestsValid) note = 'composed member_digest must be SHA-256 hex';

  return {
    schema: LICENSE_SURVIVABLE_CUSTODY_PACK_SCHEMA,
    sku: LICENSE_SURVIVABLE_CUSTODY_PACK_SKU,
    ok,
    checks: {
      schemaValid,
      organizationIdPresent,
      sessionIdPresent,
      composedMembersPresent,
      memberDigestsValid,
      postTerminationManifestPresent,
      custodyAssertionsConsistent,
      packDigestMatches,
      hashOnlySurface,
      readinessConsistent,
      profileComplete,
    },
    post_termination_readiness: derivedReadiness,
    gtmLine:
      'Platform logs expire with your contract. Aevesa proves deployer custody and resurrected receipts verify after vendor termination — no backend login.',
    note,
  };
}
