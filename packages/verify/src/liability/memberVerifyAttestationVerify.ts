import { isRecord } from '../core/isRecord.js';
import { stableStringify } from '../core/stableStringify.js';
import { sha256HexUtf8 } from '../core/sha256.js';
import {
  MEMBER_VERIFY_ATTESTATION_SCHEMA,
  MEMBER_VERIFY_ATTESTATION_SKU,
  buildMemberVerifyAttestationPreimage,
  type MemberVerifyAttestationDocument,
  type MemberVerifyAttestationWitnessCosign,
} from '../core/memberVerifyAttestation.js';
import { COSIGN_FRAGMENT_SCHEMA } from './proveBundleVerify.js';

const HEX64 = /^[a-f0-9]{64}$/;
const WITNESS_PARTIES = new Set(['witness', 'aevesa_witness']);

export interface MemberVerifyAttestationVerifyOptions {
  expected_member_schema?: string | null;
  expected_member_digest?: string | null;
  /** When true, witness cosign must bind attestation_digest (PC-09). */
  requireWitnessCosign?: boolean;
}

export interface MemberVerifyAttestationVerifyChecks {
  schemaValid: boolean;
  memberSchemaPresent: boolean;
  memberDigestValid: boolean;
  verifyOkBoolean: boolean;
  verifyResultSchemaPresent: boolean;
  verifiedAtPresent: boolean;
  attestationDigestMatches: boolean;
  memberBindingMatches: boolean;
  witnessCosignProvided: boolean;
  witnessCosignStructureValid: boolean | null;
  profileComplete: boolean;
}

export interface MemberVerifyAttestationVerifyResult {
  schema: typeof MEMBER_VERIFY_ATTESTATION_SCHEMA;
  sku: typeof MEMBER_VERIFY_ATTESTATION_SKU;
  ok: boolean;
  verify_ok_claimed: boolean;
  checks: MemberVerifyAttestationVerifyChecks;
  note: string | null;
}

function normalizeHex64(value: unknown): string | null {
  const s = String(value ?? '').trim().toLowerCase();
  return HEX64.test(s) ? s : null;
}

function verifyWitnessCosignStructure(
  witnessCosign: MemberVerifyAttestationWitnessCosign | null | undefined,
  attestationDigest: string | null,
): { provided: boolean; valid: boolean | null } {
  const fragment = witnessCosign?.cosign?.fragment;
  if (!fragment || typeof fragment !== 'object') {
    return { provided: false, valid: null };
  }
  const digestOk =
    attestationDigest != null &&
    normalizeHex64(fragment.receipt_digest) === attestationDigest;
  const schemaOk = fragment.schema === COSIGN_FRAGMENT_SCHEMA;
  const party = String(fragment.party || '').trim();
  const partyOk = WITNESS_PARTIES.has(party);
  const witnessedOk = witnessCosign?.witnessed === true && witnessCosign?.ok === true;
  return {
    provided: true,
    valid: digestOk && schemaOk && partyOk && witnessedOk,
  };
}

export function verifyMemberVerifyAttestation(
  input: unknown,
  options: MemberVerifyAttestationVerifyOptions = {},
): MemberVerifyAttestationVerifyResult {
  const doc = isRecord(input) ? (input as unknown as MemberVerifyAttestationDocument) : null;

  const schemaValid = doc?.schema === MEMBER_VERIFY_ATTESTATION_SCHEMA;
  const memberSchemaPresent = Boolean(String(doc?.member_schema || '').trim());
  const memberDigestValid = HEX64.test(String(doc?.member_digest || '').trim().toLowerCase());
  const verifyOkBoolean = typeof doc?.verify_ok === 'boolean';
  const verifyResultSchemaPresent = Boolean(String(doc?.verify_result_schema || '').trim());
  const verifiedAtPresent = Boolean(String(doc?.verified_at || '').trim());

  let attestationDigestMatches = false;
  if (
    schemaValid &&
    memberSchemaPresent &&
    memberDigestValid &&
    verifyOkBoolean &&
    verifyResultSchemaPresent &&
    verifiedAtPresent &&
    doc
  ) {
    const expected = sha256HexUtf8(
      stableStringify(
        buildMemberVerifyAttestationPreimage({
          member_schema: String(doc.member_schema),
          member_digest: String(doc.member_digest),
          verify_ok: doc.verify_ok === true,
          verify_result_schema: String(doc.verify_result_schema),
          verified_at: String(doc.verified_at),
        }),
      ),
    );
    attestationDigestMatches =
      Boolean(doc.attestation_digest) && doc.attestation_digest === expected;
  }

  const expectedSchema = String(options.expected_member_schema || '').trim();
  const expectedDigest = normalizeHex64(options.expected_member_digest);
  const actualSchema = String(doc?.member_schema || '').trim();
  const actualDigest = normalizeHex64(doc?.member_digest);
  const memberBindingMatches =
    (!expectedSchema || actualSchema === expectedSchema) &&
    (!expectedDigest || actualDigest === expectedDigest);

  const attestationDigest = normalizeHex64(doc?.attestation_digest);
  const witness = verifyWitnessCosignStructure(doc?.witness_cosign ?? null, attestationDigest);
  const requireWitness = options.requireWitnessCosign === true;
  const witnessOk = !requireWitness || (witness.provided && witness.valid === true);

  const profileComplete =
    schemaValid &&
    memberSchemaPresent &&
    memberDigestValid &&
    verifyOkBoolean &&
    verifyResultSchemaPresent &&
    verifiedAtPresent &&
    attestationDigestMatches &&
    memberBindingMatches &&
    doc?.verify_ok === true &&
    witnessOk;

  let note: string | null = null;
  if (!schemaValid) note = `schema must be ${MEMBER_VERIFY_ATTESTATION_SCHEMA}`;
  else if (!attestationDigestMatches) note = 'attestation_digest mismatch';
  else if (!memberBindingMatches) note = 'member_schema or member_digest binding mismatch';
  else if (doc?.verify_ok !== true) note = 'attestation claims verify_ok false';
  else if (requireWitness && !witnessOk) {
    note = 'witness cosign must bind attestation_digest with party witness (PC-09)';
  } else if (!witness.provided) {
    note = 'member verify attestation verified structurally — witness cosign not bundled';
  } else if (profileComplete) {
    note = 'Member verify attestation verified — witness cosign binds schema, digest, verify_ok';
  }

  return {
    schema: MEMBER_VERIFY_ATTESTATION_SCHEMA,
    sku: MEMBER_VERIFY_ATTESTATION_SKU,
    ok: profileComplete,
    verify_ok_claimed: doc?.verify_ok === true,
    checks: {
      schemaValid,
      memberSchemaPresent,
      memberDigestValid,
      verifyOkBoolean,
      verifyResultSchemaPresent,
      verifiedAtPresent,
      attestationDigestMatches,
      memberBindingMatches,
      witnessCosignProvided: witness.provided,
      witnessCosignStructureValid: witness.valid,
      profileComplete,
    },
    note,
  };
}
