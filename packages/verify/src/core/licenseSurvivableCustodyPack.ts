import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';

/** Wave 11 Track B — post-termination deployer custody + license-survivable bundle compose. */

export const LICENSE_SURVIVABLE_CUSTODY_PACK_SCHEMA =
  'aevesa.license-survivable-custody-pack/v1' as const;

export type PostTerminationReadiness = 'complete' | 'partial' | 'custody_only';

export interface ComposedCustodySurvivalMemberRef {
  member_schema: string;
  member_digest: string;
  verify_ok: boolean;
  label: string;
  entry_count?: number | null;
}

export interface PostTerminationVerifyManifest {
  offline_cli: string;
  portal_base: string;
  no_backend_required: boolean;
  deployer_custody_schema: string;
  license_survivable_schema: string;
  bundle_schema: string;
}

export interface CustodySurvivalAssertionsInput {
  deployer_controlled: boolean;
  vendor_admin_plane_independent: boolean;
  license_survivable: boolean;
  post_termination_verify: boolean;
  third_party_verifiable: boolean;
}

export interface LicenseSurvivableCustodyPackInput {
  organization_id: string;
  session_id: string;
  vendor_termination_ref?: string | null;
  generated_at?: string;
  custody_survival_assertions: CustodySurvivalAssertionsInput;
  composed_members: ComposedCustodySurvivalMemberRef[];
  post_termination_verify: PostTerminationVerifyManifest;
  disclaimer?: string;
}



export function derivePostTerminationReadiness(
  members: ComposedCustodySurvivalMemberRef[],
): PostTerminationReadiness {
  const deployer = (members || []).find(
    (m) => m.member_schema === 'aevesa.deployer-log-custody-pack/v1' && m.verify_ok === true,
  );
  const survivable = (members || []).find(
    (m) => m.member_schema === 'aevesa.license-survivable-bundle/v1' && m.verify_ok === true,
  );
  if (deployer && survivable) return 'complete';
  if (deployer || survivable) return 'partial';
  return 'custody_only';
}

export function buildCustodySurvivalAssertionsBlock(
  input: CustodySurvivalAssertionsInput,
  members: ComposedCustodySurvivalMemberRef[],
) {
  const readiness = derivePostTerminationReadiness(members);
  const hasDeployer = (members || []).some(
    (m) => m.member_schema === 'aevesa.deployer-log-custody-pack/v1' && m.verify_ok === true,
  );
  const hasSurvivable = (members || []).some(
    (m) => m.member_schema === 'aevesa.license-survivable-bundle/v1' && m.verify_ok === true,
  );
  return {
    deployer_controlled: input.deployer_controlled === true,
    vendor_admin_plane_independent: input.vendor_admin_plane_independent === true,
    license_survivable: hasSurvivable || input.license_survivable === true,
    post_termination_verify: input.post_termination_verify === true,
    third_party_verifiable: input.third_party_verifiable === true,
    post_termination_readiness: readiness,
    deployer_custody_bound: hasDeployer,
  };
}

export function buildLicenseSurvivableCustodyPackPreimage(
  input: Omit<LicenseSurvivableCustodyPackInput, 'disclaimer'> & {
    generated_at: string;
    custody_survival_assertions: ReturnType<typeof buildCustodySurvivalAssertionsBlock>;
    composed_members: ComposedCustodySurvivalMemberRef[];
  },
): Record<string, unknown> {
  const members = [...(input.composed_members || [])]
    .map((m) => ({
      member_schema: String(m.member_schema || '').trim(),
      member_digest: String(m.member_digest || '').trim().toLowerCase(),
      verify_ok: m.verify_ok === true,
      label: String(m.label || '').trim(),
      entry_count: m.entry_count != null ? Number(m.entry_count) : null,
    }))
    .sort((a, b) => a.member_schema.localeCompare(b.member_schema));

  return {
    schema: LICENSE_SURVIVABLE_CUSTODY_PACK_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    session_id: String(input.session_id || '').trim(),
    vendor_termination_ref: input.vendor_termination_ref
      ? String(input.vendor_termination_ref).trim()
      : null,
    generated_at: input.generated_at,
    custody_survival_assertions: input.custody_survival_assertions,
    composed_members: members,
    post_termination_verify: {
      offline_cli: String(input.post_termination_verify.offline_cli || '').trim(),
      portal_base: String(input.post_termination_verify.portal_base || '').trim(),
      no_backend_required: input.post_termination_verify.no_backend_required === true,
      deployer_custody_schema: String(
        input.post_termination_verify.deployer_custody_schema || '',
      ).trim(),
      license_survivable_schema: String(
        input.post_termination_verify.license_survivable_schema || '',
      ).trim(),
      bundle_schema: String(input.post_termination_verify.bundle_schema || '').trim(),
    },
  };
}

export function buildLicenseSurvivableCustodyPackDocument(input: LicenseSurvivableCustodyPackInput) {
  const generated_at = input.generated_at || new Date().toISOString();
  const custody_survival_assertions = buildCustodySurvivalAssertionsBlock(
    input.custody_survival_assertions,
    input.composed_members,
  );
  const preimage = buildLicenseSurvivableCustodyPackPreimage({
    ...input,
    generated_at,
    custody_survival_assertions,
    composed_members: input.composed_members,
  });
  const pack_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    pack_digest,
    disclaimer:
      input.disclaimer ||
      'Evidence export only — Aevesa does not certify regulatory compliance or vendor contract interpretation.',
  };
}

export default {
  LICENSE_SURVIVABLE_CUSTODY_PACK_SCHEMA,
  derivePostTerminationReadiness,
  buildCustodySurvivalAssertionsBlock,
  buildLicenseSurvivableCustodyPackDocument,
  buildLicenseSurvivableCustodyPackPreimage,
};
