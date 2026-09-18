import { sha256HexUtf8 } from '../core/sha256.js';
import {
  buildAccountableExecutiveAttestationDigest,
  buildAttestationBindingDigest,
  deriveBindingReadiness,
  EXECUTIVE_ATTESTATION_BINDING_PACK_SCHEMA,
  buildExecutiveAttestationBindingPackPreimage,
} from '../core/executiveAttestationBindingPack.js';
import { stableStringify } from '../core/stableStringify.js';
import type { BindingReadiness } from '../core/executiveAttestationBindingPack.js';
import { verifyAttestedEvidenceSet } from './attestedEvidenceSetVerify.js';

export const EXECUTIVE_ATTESTATION_BINDING_PACK_SKU =
  'aevesa-executive-attestation-binding-pack-v1' as const;

const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|ssn|phone|address|pan|cvv)$/i;
const HEX64 = /^[a-f0-9]{64}$/;

export interface ExecutiveAttestationBindingPackVerifyResult {
  schema: typeof EXECUTIVE_ATTESTATION_BINDING_PACK_SCHEMA;
  sku: typeof EXECUTIVE_ATTESTATION_BINDING_PACK_SKU;
  ok: boolean;
  checks: Record<string, boolean>;
  binding_readiness: BindingReadiness | null;
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

export function verifyExecutiveAttestationBindingPack(
  docInput: unknown,
): ExecutiveAttestationBindingPackVerifyResult {
  const doc = asRecord(docInput);
  const schemaValid = doc?.schema === EXECUTIVE_ATTESTATION_BINDING_PACK_SCHEMA;
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;
  const periodLabelPresent = String(doc?.attestation_period_label || '').trim().length > 0;

  const att = asRecord(doc?.accountable_executive_attestation) || {};
  const executiveNamePresent = String(att.executive_display_name || '').trim().length > 0;
  const attestationDigestValid = HEX64.test(String(att.attestation_digest || '').toLowerCase());

  let executiveAttestationDigestMatches = false;
  if (attestationDigestValid && doc?.organization_id) {
    const expected = buildAccountableExecutiveAttestationDigest({
      organization_id: String(doc.organization_id),
      executive_id: att.executive_id != null ? String(att.executive_id) : null,
      executive_display_name:
        att.executive_display_name != null ? String(att.executive_display_name) : null,
      role_title: att.role_title != null ? String(att.role_title) : null,
      attested_at: att.attested_at != null ? String(att.attested_at) : null,
      attestation_statement: String(att.attestation_statement || ''),
    });
    executiveAttestationDigestMatches =
      String(att.attestation_digest || '').toLowerCase() === expected;
  }

  const evidenceSet = asRecord(doc?.attested_evidence_set) || {};
  const members = Array.isArray(evidenceSet.members) ? evidenceSet.members : [];
  const evidenceSetPresent = members.length >= 2;
  const memberDigestsValid =
    members.length === 0 ||
    members.every((m) => HEX64.test(String(m?.member_digest || '').toLowerCase()));

  const binding = asRecord(doc?.attestation_binding) || {};
  const scopePresent = String(binding.scope_statement || '').trim().length > 0;
  const bindingDigestsValid =
    HEX64.test(String(binding.attestation_digest || '').toLowerCase()) &&
    HEX64.test(String(binding.evidence_set_digest || '').toLowerCase()) &&
    HEX64.test(String(binding.binding_digest || '').toLowerCase());

  const bindingDigestMatches =
    bindingDigestsValid &&
    String(binding.binding_digest || '').toLowerCase() ===
      buildAttestationBindingDigest(
        String(binding.attestation_digest || ''),
        String(binding.evidence_set_digest || ''),
        String(binding.scope_statement || ''),
      ).toLowerCase();

  const bindingMatchesExecutive =
    String(binding.attestation_digest || '').toLowerCase() ===
    String(att.attestation_digest || '').toLowerCase();

  const bindingMatchesEvidenceSet =
    String(binding.evidence_set_digest || '').toLowerCase() ===
    String(evidenceSet.evidence_set_digest || '').toLowerCase();

  const bindingValid = binding.binding_valid === true && bindingDigestMatches;

  const memberDocs = asRecord(doc?.member_documents) || {};
  const memberArtifactsBundled = Object.keys(memberDocs).length > 0;
  const anyVerifyOkAsserted = members.some((m) => m?.verify_ok === true);
  const bundledEvidenceSet = memberDocs.attested_evidence_set ?? null;

  let memberVerifyRecomputed = true;
  let evidenceSetVerify: ReturnType<typeof verifyAttestedEvidenceSet> | null = null;
  if (anyVerifyOkAsserted) {
    if (bundledEvidenceSet == null) {
      memberVerifyRecomputed = false;
    } else {
      evidenceSetVerify = verifyAttestedEvidenceSet(bundledEvidenceSet);
      memberVerifyRecomputed =
        evidenceSetVerify.ok === true && evidenceSetVerify.checks.memberVerifyRecomputed === true;
    }
  }

  const selfAssertedVerifyIgnored =
    anyVerifyOkAsserted && memberArtifactsBundled && !memberVerifyRecomputed;

  const evidenceSetVerified = anyVerifyOkAsserted && memberVerifyRecomputed;
  const membersForReadiness = members.map((m) => ({
    verify_ok: m?.verify_ok === true && evidenceSetVerified,
  }));

  const derivedReadiness = deriveBindingReadiness(
    {
      executive_display_name:
        att.executive_display_name != null ? String(att.executive_display_name) : null,
      attestation_digest: String(att.attestation_digest || ''),
    },
    membersForReadiness,
    bindingValid && bindingMatchesExecutive && bindingMatchesEvidenceSet,
  );

  const assertions = asRecord(doc?.binding_assertions) || {};
  const allVerified =
    members.length >= 2 && evidenceSetVerified && members.every((m) => m?.verify_ok === true);

  let bindingAssertionsConsistent =
    assertions.third_party_verifiable === true && scopePresent;

  if (derivedReadiness === 'bound') {
    bindingAssertionsConsistent =
      bindingAssertionsConsistent &&
      assertions.named_executive_present === true &&
      assertions.evidence_set_complete === true &&
      allVerified &&
      executiveAttestationDigestMatches &&
      bindingValid &&
      bindingMatchesExecutive &&
      bindingMatchesEvidenceSet;
  } else if (derivedReadiness === 'partial') {
    bindingAssertionsConsistent =
      bindingAssertionsConsistent &&
      assertions.named_executive_present === true &&
      executiveAttestationDigestMatches &&
      bindingDigestMatches;
  }

  const readinessConsistent = assertions.binding_readiness === derivedReadiness;

  let packDigestMatches = false;
  if (schemaValid && doc && bindingDigestMatches && executiveAttestationDigestMatches) {
    const preimage = buildExecutiveAttestationBindingPackPreimage({
      organization_id: String(doc.organization_id),
      attestation_period_label: String(doc.attestation_period_label),
      generated_at: String(doc.generated_at || ''),
      accountable_executive_attestation: {
        required: true as const,
        executive_id: att.executive_id != null ? String(att.executive_id) : null,
        executive_display_name:
          att.executive_display_name != null ? String(att.executive_display_name) : null,
        role_title: att.role_title != null ? String(att.role_title) : null,
        attested_at: att.attested_at != null ? String(att.attested_at) : null,
        attestation_statement: String(att.attestation_statement || ''),
        attestation_digest: String(att.attestation_digest || ''),
      },
      attested_evidence_set: {
        evidence_set_digest: String(evidenceSet.evidence_set_digest || ''),
        member_count: members.length,
        members: members.map((m) => ({
          member_schema: String(m?.member_schema || ''),
          member_digest: String(m?.member_digest || ''),
          label: String(m?.label || ''),
          verify_ok: m?.verify_ok === true,
          entry_count: m?.entry_count ?? null,
        })),
      },
      attestation_binding: {
        scope_statement: String(binding.scope_statement || ''),
        attestation_digest: String(binding.attestation_digest || ''),
        evidence_set_digest: String(binding.evidence_set_digest || ''),
        binding_digest: String(binding.binding_digest || ''),
        binding_valid: bindingValid,
      },
      binding_assertions: {
        named_executive_present: assertions.named_executive_present === true,
        evidence_set_complete: assertions.evidence_set_complete === true,
        attestation_fresh: assertions.attestation_fresh === true,
        third_party_verifiable: assertions.third_party_verifiable === true,
        binding_readiness: String(assertions.binding_readiness || derivedReadiness) as BindingReadiness,
        member_count: Number(assertions.member_count) || members.length,
        verified_member_count:
          Number(assertions.verified_member_count) ||
          members.filter((m) => m?.verify_ok === true).length,
      },
    });
    const expected = sha256HexUtf8(stableStringify(preimage));
    packDigestMatches = String(doc.pack_digest || '').toLowerCase() === expected;
  }

  const { member_documents: _hashMemberDocs, ...hashOnlyDoc } = doc || {};
  const hashOnlySurface = !hasForbiddenKeys(hashOnlyDoc);

  const profileComplete =
    schemaValid &&
    organizationIdPresent &&
    periodLabelPresent &&
    executiveNamePresent &&
    executiveAttestationDigestMatches &&
    evidenceSetPresent &&
    memberDigestsValid &&
    bindingDigestsValid &&
    bindingDigestMatches &&
    bindingMatchesExecutive &&
    bindingMatchesEvidenceSet &&
    bindingAssertionsConsistent &&
    packDigestMatches &&
    hashOnlySurface &&
    (!anyVerifyOkAsserted || (memberArtifactsBundled && memberVerifyRecomputed)) &&
    readinessConsistent;

  let note: string | null = null;
  if (!schemaValid) note = `schema must be ${EXECUTIVE_ATTESTATION_BINDING_PACK_SCHEMA}`;
  else if (anyVerifyOkAsserted && !memberArtifactsBundled) {
    note =
      'member_documents.attested_evidence_set required when evidence members assert verify_ok (PC-09)';
  } else if (selfAssertedVerifyIgnored) {
    note =
      'attested_evidence_set.verify_ok is exporter self-asserted; bundle member_documents for offline re-verify';
  } else if (!executiveAttestationDigestMatches) note = 'attestation_digest does not match executive ceremony preimage';
  else if (!bindingMatchesExecutive) note = 'attestation_binding.attestation_digest must match executive attestation';
  else if (!bindingMatchesEvidenceSet) note = 'attestation_binding.evidence_set_digest must match attested_evidence_set';
  else if (!bindingDigestMatches) note = 'attestation_binding.binding_digest does not match scope + digests';
  else if (!packDigestMatches) note = 'pack_digest does not match canonical preimage';
  else if (!bindingAssertionsConsistent) note = 'binding_assertions inconsistent with members or binding';
  else if (!readinessConsistent) note = 'binding_readiness inconsistent with member verification state';

  return {
    schema: EXECUTIVE_ATTESTATION_BINDING_PACK_SCHEMA,
    sku: EXECUTIVE_ATTESTATION_BINDING_PACK_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      organizationIdPresent,
      periodLabelPresent,
      executiveNamePresent,
      executiveAttestationDigestMatches,
      evidenceSetPresent,
      memberDigestsValid,
      bindingDigestsValid,
      bindingDigestMatches,
      bindingMatchesExecutive,
      bindingMatchesEvidenceSet,
      bindingAssertionsConsistent,
      packDigestMatches,
      hashOnlySurface,
      memberArtifactsBundled,
      memberVerifyRecomputed: !anyVerifyOkAsserted || memberVerifyRecomputed,
      attestedEvidenceSetVerifyOk: evidenceSetVerify?.ok === true,
      readinessConsistent,
      profileComplete,
    },
    binding_readiness: derivedReadiness,
    gtmLine:
      'Insurers require a named executive attestation — Aevesa binds the CISO signature to the exact evidence set, verifiable offline.',
    note,
  };
}
