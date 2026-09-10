import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';
import type { WitnessDiversityBlock } from './witnessDiversity.js';

/** Wave 11 Track D — witness cosign + anchor coverage + custodian path compose. */

export const INDEPENDENCE_WITNESS_PACK_SCHEMA = 'aevesa.independence-witness-pack/v1' as const;

export type IndependenceReadiness = 'independent' | 'partial' | 'operator_only';

export interface ComposedIndependenceMemberRef {
  member_schema: string;
  member_digest: string;
  verify_ok: boolean;
  label: string;
  entry_count?: number | null;
}

export interface IndependenceVerifyManifest {
  offline_cli: string;
  portal_base: string;
  no_operator_login_required: boolean;
  guardian_schema: string;
  anchor_coverage_schema: string;
  bundle_schema: string;
}

export interface IndependenceAssertionsInput {
  witness_cosign_present: boolean;
  anchor_coverage_sufficient: boolean;
  custodian_path_verified: boolean;
  operator_self_sign_excluded: boolean;
  third_party_verifiable: boolean;
}

export interface IndependenceWitnessPackInput {
  organization_id: string;
  session_id: string;
  generated_at?: string;
  competitor_context_ref?: string | null;
  independence_assertions: IndependenceAssertionsInput;
  composed_members: ComposedIndependenceMemberRef[];
  independence_verify: IndependenceVerifyManifest;
  witness_diversity?: WitnessDiversityBlock | null;
  disclaimer?: string;
}



export function deriveIndependenceReadiness(
  members: ComposedIndependenceMemberRef[],
): IndependenceReadiness {
  const guardian = (members || []).find(
    (m) => m.member_schema === 'aevesa.independent-guardian-bundle/v1' && m.verify_ok === true,
  );
  const anchor = (members || []).find(
    (m) => m.member_schema === 'aevesa.anchor-coverage-forensic-pack/v1' && m.verify_ok === true,
  );
  const witnessPath = (members || []).find(
    (m) => m.member_schema === 'aevesa.witness-custody-path/v1' && m.verify_ok === true,
  );
  if (guardian && anchor && witnessPath) return 'independent';
  if (guardian || anchor) return 'partial';
  return 'operator_only';
}

export function buildIndependenceAssertionsBlock(
  input: IndependenceAssertionsInput,
  members: ComposedIndependenceMemberRef[],
) {
  const readiness = deriveIndependenceReadiness(members);
  const hasGuardian = (members || []).some(
    (m) => m.member_schema === 'aevesa.independent-guardian-bundle/v1' && m.verify_ok === true,
  );
  const hasAnchor = (members || []).some(
    (m) => m.member_schema === 'aevesa.anchor-coverage-forensic-pack/v1' && m.verify_ok === true,
  );
  const hasWitnessPath = (members || []).some(
    (m) => m.member_schema === 'aevesa.witness-custody-path/v1' && m.verify_ok === true,
  );
  return {
    witness_cosign_present: hasGuardian || input.witness_cosign_present === true,
    anchor_coverage_sufficient: hasAnchor || input.anchor_coverage_sufficient === true,
    custodian_path_verified: hasWitnessPath || input.custodian_path_verified === true,
    operator_self_sign_excluded: input.operator_self_sign_excluded === true,
    third_party_verifiable: input.third_party_verifiable === true,
    independence_readiness: readiness,
  };
}

export function buildIndependenceWitnessPackPreimage(
  input: Omit<IndependenceWitnessPackInput, 'disclaimer'> & {
    generated_at: string;
    independence_assertions: ReturnType<typeof buildIndependenceAssertionsBlock>;
    composed_members: ComposedIndependenceMemberRef[];
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
    schema: INDEPENDENCE_WITNESS_PACK_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    session_id: String(input.session_id || '').trim(),
    generated_at: input.generated_at,
    competitor_context_ref: input.competitor_context_ref
      ? String(input.competitor_context_ref).trim()
      : null,
    independence_assertions: input.independence_assertions,
    composed_members: members,
    independence_verify: {
      offline_cli: String(input.independence_verify.offline_cli || '').trim(),
      portal_base: String(input.independence_verify.portal_base || '').trim(),
      no_operator_login_required: input.independence_verify.no_operator_login_required === true,
      guardian_schema: String(input.independence_verify.guardian_schema || '').trim(),
      anchor_coverage_schema: String(input.independence_verify.anchor_coverage_schema || '').trim(),
      bundle_schema: String(input.independence_verify.bundle_schema || '').trim(),
    },
    ...(input.witness_diversity ? { witness_diversity: input.witness_diversity } : {}),
  };
}

export function buildIndependenceWitnessPackDocument(input: IndependenceWitnessPackInput) {
  const generated_at = input.generated_at || new Date().toISOString();
  const independence_assertions = buildIndependenceAssertionsBlock(
    input.independence_assertions,
    input.composed_members,
  );
  const preimage = buildIndependenceWitnessPackPreimage({
    ...input,
    generated_at,
    independence_assertions,
    composed_members: input.composed_members,
    witness_diversity: input.witness_diversity ?? undefined,
  });
  const pack_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    pack_digest,
    disclaimer:
      input.disclaimer ||
      'Independence evidence export only — Aevesa does not certify neutrality vs Testari, Tersign, or Microsoft AGT.',
  };
}

export default {
  INDEPENDENCE_WITNESS_PACK_SCHEMA,
  deriveIndependenceReadiness,
  buildIndependenceAssertionsBlock,
  buildIndependenceWitnessPackDocument,
  buildIndependenceWitnessPackPreimage,
};
