import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';
import {
  buildAccountableExecutiveAttestationBlock,
  buildAccountableExecutiveAttestationDigest,
  type AccountableExecutiveAttestationInput,
} from './carrierUnderwritingEvidencePack.js';

/** Wave 12 Track C — named executive attestation cryptographically bound to an evidence set. */

export const EXECUTIVE_ATTESTATION_BINDING_PACK_SCHEMA =
  'aevesa.executive-attestation-binding-pack/v1' as const;

export type BindingReadiness = 'bound' | 'partial' | 'unbound';

export interface AttestationBindingInput {
  scope_statement: string;
  attestation_digest: string;
  evidence_set_digest: string;
  binding_valid?: boolean;
}

export interface BindingAssertionsInput {
  named_executive_present: boolean;
  evidence_set_complete: boolean;
  attestation_fresh: boolean;
  third_party_verifiable: boolean;
}

export interface ExecutiveAttestationBindingPackInput {
  organization_id: string;
  attestation_period_label: string;
  generated_at?: string;
  accountable_executive_attestation: AccountableExecutiveAttestationInput;
  attested_evidence_set: {
    evidence_set_digest: string;
    member_count: number;
    members: Array<{
      member_schema: string;
      member_digest: string;
      label: string;
      verify_ok: boolean;
      entry_count?: number | null;
    }>;
  };
  attestation_binding: AttestationBindingInput;
  binding_assertions: BindingAssertionsInput;
  disclaimer?: string;
}



export function buildAttestationBindingDigest(
  attestationDigest: string,
  evidenceSetDigest: string,
  scopeStatement: string,
): string {
  return sha256HexUtf8(
    stableStringify({
      attestation_digest: String(attestationDigest || '').trim().toLowerCase(),
      evidence_set_digest: String(evidenceSetDigest || '').trim().toLowerCase(),
      scope_statement: String(scopeStatement || '').trim(),
    }),
  );
}

export function deriveBindingReadiness(
  executiveBlock: {
    executive_display_name?: string | null;
    attestation_digest?: string | null;
  },
  members: Array<{ verify_ok?: boolean }>,
  bindingValid: boolean,
): BindingReadiness {
  const namedExecutive =
    Boolean(String(executiveBlock.executive_display_name || '').trim()) &&
    Boolean(String(executiveBlock.attestation_digest || '').trim());
  const allVerified = members.length > 0 && members.every((m) => m.verify_ok === true);
  if (namedExecutive && allVerified && bindingValid) return 'bound';
  if (namedExecutive && members.length > 0) return 'partial';
  return 'unbound';
}

export function buildBindingAssertionsBlock(
  input: BindingAssertionsInput,
  executiveBlock: {
    executive_display_name?: string | null;
    attestation_digest?: string | null;
    attested_at?: string | null;
  },
  members: Array<{ verify_ok?: boolean }>,
  bindingValid: boolean,
  attestedAt?: string | null,
  periodEnd?: string | null,
) {
  const readiness = deriveBindingReadiness(executiveBlock, members, bindingValid);
  const namedExecutive =
    Boolean(String(executiveBlock.executive_display_name || '').trim()) &&
    Boolean(String(executiveBlock.attestation_digest || '').trim());
  const allVerified = members.length >= 2 && members.every((m) => m.verify_ok === true);

  let attestationFresh = input.attestation_fresh === true;
  if (attestedAt && periodEnd) {
    const attestedMs = Date.parse(String(attestedAt));
    const periodEndMs = Date.parse(String(periodEnd));
    if (Number.isFinite(attestedMs) && Number.isFinite(periodEndMs)) {
      attestationFresh = attestedMs <= periodEndMs + 86400000;
    }
  }

  return {
    named_executive_present: namedExecutive || input.named_executive_present === true,
    evidence_set_complete: allVerified || input.evidence_set_complete === true,
    attestation_fresh: attestationFresh,
    third_party_verifiable: input.third_party_verifiable === true,
    binding_readiness: readiness,
    member_count: members.length,
    verified_member_count: members.filter((m) => m.verify_ok === true).length,
  };
}

export function buildAttestationBindingBlock(
  attestationDigest: string,
  evidenceSetDigest: string,
  scopeStatement: string,
) {
  const binding_digest = buildAttestationBindingDigest(
    attestationDigest,
    evidenceSetDigest,
    scopeStatement,
  );
  const binding_valid =
    HEX64.test(String(attestationDigest || '').toLowerCase()) &&
    HEX64.test(String(evidenceSetDigest || '').toLowerCase()) &&
    String(scopeStatement || '').trim().length > 0;
  return {
    scope_statement: String(scopeStatement || '').trim(),
    attestation_digest: String(attestationDigest || '').trim().toLowerCase(),
    evidence_set_digest: String(evidenceSetDigest || '').trim().toLowerCase(),
    binding_digest,
    binding_valid,
  };
}

const HEX64 = /^[a-f0-9]{64}$/;

export function buildExecutiveAttestationBindingPackPreimage(
  input: Omit<
    ExecutiveAttestationBindingPackInput,
    'disclaimer' | 'accountable_executive_attestation' | 'attestation_binding' | 'binding_assertions'
  > & {
    generated_at: string;
    accountable_executive_attestation: ReturnType<typeof buildAccountableExecutiveAttestationBlock>;
    attestation_binding: ReturnType<typeof buildAttestationBindingBlock>;
    binding_assertions: ReturnType<typeof buildBindingAssertionsBlock>;
  },
): Record<string, unknown> {
  const evidenceSet = input.attested_evidence_set;
  const members = [...(evidenceSet.members || [])]
    .map((m) => ({
      member_schema: String(m.member_schema || '').trim(),
      member_digest: String(m.member_digest || '').trim().toLowerCase(),
      label: String(m.label || '').trim(),
      verify_ok: m.verify_ok === true,
      entry_count: m.entry_count != null ? Number(m.entry_count) : null,
    }))
    .sort((a, b) => a.member_schema.localeCompare(b.member_schema));

  return {
    schema: EXECUTIVE_ATTESTATION_BINDING_PACK_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    attestation_period_label: String(input.attestation_period_label || '').trim(),
    generated_at: input.generated_at,
    accountable_executive_attestation: input.accountable_executive_attestation,
    attested_evidence_set: {
      evidence_set_digest: String(evidenceSet.evidence_set_digest || '').trim().toLowerCase(),
      member_count: members.length,
      members,
    },
    attestation_binding: input.attestation_binding,
    binding_assertions: input.binding_assertions,
  };
}

export function buildExecutiveAttestationBindingPackDocument(
  input: ExecutiveAttestationBindingPackInput,
) {
  const generated_at = input.generated_at || new Date().toISOString();
  const executiveBlock = buildAccountableExecutiveAttestationBlock({
    ...input.accountable_executive_attestation,
    organization_id: input.organization_id,
  });

  const evidenceSetDigest = String(
    input.attested_evidence_set.evidence_set_digest || '',
  ).toLowerCase();
  const scopeStatement = String(
    input.attestation_binding.scope_statement || '',
  ).trim();

  const attestation_binding = buildAttestationBindingBlock(
    executiveBlock.attestation_digest,
    evidenceSetDigest,
    scopeStatement,
  );

  const binding_assertions = buildBindingAssertionsBlock(
    input.binding_assertions,
    executiveBlock,
    input.attested_evidence_set.members || [],
    attestation_binding.binding_valid === true,
    executiveBlock.attested_at,
    generated_at,
  );

  const preimage = buildExecutiveAttestationBindingPackPreimage({
    ...input,
    generated_at,
    accountable_executive_attestation: executiveBlock,
    attestation_binding,
    binding_assertions,
  });
  const pack_digest = sha256HexUtf8(stableStringify(preimage));

  return {
    ...preimage,
    pack_digest,
    disclaimer:
      input.disclaimer ||
      'Executive attestation binding for diligence — not legal advice, coverage grant, or board resolution.',
  };
}

export {
  buildAccountableExecutiveAttestationDigest,
  buildAccountableExecutiveAttestationBlock,
};

export default {
  EXECUTIVE_ATTESTATION_BINDING_PACK_SCHEMA,
  buildAttestationBindingDigest,
  deriveBindingReadiness,
  buildAttestationBindingBlock,
  buildBindingAssertionsBlock,
  buildExecutiveAttestationBindingPackDocument,
};
