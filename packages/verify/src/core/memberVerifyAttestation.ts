import { sha256HexUtf8 } from './sha256.js';
import { stableStringify } from './stableStringify.js';

/** Wave 16 PC-09 — witness-attested member verify without full co-paste. */
export const MEMBER_VERIFY_ATTESTATION_SCHEMA = 'aevesa.member-verify-attestation/v1' as const;
export const MEMBER_VERIFY_ATTESTATION_SKU = 'aevesa-member-verify-attestation-v1' as const;

export interface MemberVerifyAttestationInput {
  member_schema: string;
  member_digest: string;
  verify_ok: boolean;
  verify_result_schema: string;
  verified_at?: string;
}

export interface MemberVerifyAttestationWitnessCosign {
  witnessed?: boolean;
  ok?: boolean;
  cosign?: {
    fragment?: {
      schema?: string;
      receipt_digest?: string;
      party?: string;
      role?: string;
      signed_at?: string;
      signature_alg?: string;
      signature?: string;
    } | null;
  } | null;
}

export interface MemberVerifyAttestationDocument {
  schema: typeof MEMBER_VERIFY_ATTESTATION_SCHEMA;
  member_schema: string;
  member_digest: string;
  verify_ok: boolean;
  verify_result_schema: string;
  verified_at: string;
  attestation_digest: string;
  witness_cosign?: MemberVerifyAttestationWitnessCosign | null;
}

export function buildMemberVerifyAttestationPreimage(
  input: MemberVerifyAttestationInput & { verified_at: string },
): Record<string, unknown> {
  return {
    schema: MEMBER_VERIFY_ATTESTATION_SCHEMA,
    member_schema: String(input.member_schema || '').trim(),
    member_digest: String(input.member_digest || '').trim().toLowerCase(),
    verify_ok: input.verify_ok === true,
    verify_result_schema: String(input.verify_result_schema || '').trim(),
    verified_at: input.verified_at,
  };
}

export function computeMemberVerifyAttestationDigest(
  input: MemberVerifyAttestationInput & { verified_at: string },
): string {
  return sha256HexUtf8(stableStringify(buildMemberVerifyAttestationPreimage(input)));
}

export function buildMemberVerifyAttestationDocument(
  input: MemberVerifyAttestationInput,
  witnessCosign: MemberVerifyAttestationWitnessCosign | null = null,
): MemberVerifyAttestationDocument {
  const verified_at = input.verified_at || new Date().toISOString();
  const attestation_digest = computeMemberVerifyAttestationDigest({ ...input, verified_at });
  return {
    schema: MEMBER_VERIFY_ATTESTATION_SCHEMA,
    member_schema: String(input.member_schema || '').trim(),
    member_digest: String(input.member_digest || '').trim().toLowerCase(),
    verify_ok: input.verify_ok === true,
    verify_result_schema: String(input.verify_result_schema || '').trim(),
    verified_at,
    attestation_digest,
    ...(witnessCosign ? { witness_cosign: witnessCosign } : {}),
  };
}
