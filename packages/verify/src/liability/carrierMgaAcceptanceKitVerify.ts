import { sha256HexUtf8 } from '../core/sha256.js';
import { CARRIER_MGA_ACCEPTANCE_KIT_SCHEMA, CARRIER_MGA_OPTIONAL_MEMBER_SCHEMAS, CARRIER_MGA_REQUIRED_MEMBER_SCHEMAS, buildCarrierMgaAcceptanceKitPreimage, deriveMgaAcceptanceReadiness } from '../core/carrierMgaAcceptanceKit.js';
import { CARRIER_UNDERWRITING_EVIDENCE_PACK_SCHEMA } from '../core/carrierUnderwritingEvidencePack.js';
import { stableStringify } from '../core/stableStringify.js';
import type { MgaAcceptanceReadiness, SubmissionCadence } from '../core/carrierMgaAcceptanceKit.js';
import { verifyCarrierUnderwritingEvidencePack } from './carrierUnderwritingEvidencePackVerify.js';
import { verifyShutdownDrillBundle } from './shutdownDrillBundleVerify.js';
import { verifyAdversarialTestEvidencePack } from './adversarialTestEvidencePackVerify.js';
import {
  pc09MemberProofNote,
  resolveComposedMemberVerifyState,
} from './composedPackMemberVerify.js';

export const CARRIER_MGA_ACCEPTANCE_KIT_SKU = 'aevesa-carrier-mga-acceptance-kit-v1' as const;

const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|ssn|phone|address|pan|cvv)$/i;
const HEX64 = /^[a-f0-9]{64}$/;
const CADENCES = new Set<SubmissionCadence>(['quarterly', 'annual']);

export interface CarrierMgaAcceptanceKitDocument {
  schema?: string;
  organization_id?: string;
  generated_at?: string;
  mga_partner_ref?: string | null;
  mga_acceptance_assertions?: {
    six_controls_ready?: boolean;
    kill_switch_drill_fresh?: boolean;
    executive_attestation_bound?: boolean;
    broker_submission_ready?: boolean;
    mga_acceptance_readiness?: MgaAcceptanceReadiness;
  };
  composed_members?: Array<{
    member_schema?: string;
    member_digest?: string;
    verify_ok?: boolean;
    label?: string;
    entry_count?: number | null;
  }>;
  chain_composition_disclosure?: {
    chain_enforcement_mode?: string;
    uniformly_enforced?: boolean;
    weakest_link_index?: number | null;
    owasp_asi_gl3_hint?: string;
    owasp_at7_hint?: string;
    carrier_footnote?: string;
    egress_attestation_schema?: string;
  };
  submission_cadence?: {
    cadence?: SubmissionCadence;
    period_label?: string;
    next_resubmission_due?: string;
    kill_switch_drill_max_age_days?: number;
    kill_switch_drill_digest?: string;
    carrier_pack_digest?: string;
    drill_fresh_for_submission?: boolean;
  };
  pack_digest?: string;
}

export interface CarrierMgaAcceptanceKitVerifyChecks {
  schemaValid: boolean;
  organizationIdPresent: boolean;
  composedMembersPresent: boolean;
  memberDigestsValid: boolean;
  submissionCadencePresent: boolean;
  cadenceDigestsBound: boolean;
  mgaAssertionsConsistent: boolean;
  memberSchemasRecognized: boolean;
  optionalAdversarialMemberValid: boolean;
  packDigestMatches: boolean;
  hashOnlySurface: boolean;
  memberArtifactsBundled: boolean;
  memberAttestationsPresent: boolean;
  memberProofPresent: boolean;
  memberVerifyRecomputed: boolean;
  readinessConsistent: boolean;
  chainCompositionDisclosureValid: boolean;
  profileComplete: boolean;
}

export interface CarrierMgaAcceptanceKitVerifyResult {
  schema: typeof CARRIER_MGA_ACCEPTANCE_KIT_SCHEMA;
  sku: typeof CARRIER_MGA_ACCEPTANCE_KIT_SKU;
  ok: boolean;
  checks: CarrierMgaAcceptanceKitVerifyChecks;
  mga_acceptance_readiness: MgaAcceptanceReadiness | null;
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

const SHUTDOWN_DRILL_SCHEMA = 'aevesa.shutdown-drill-bundle/v1' as const;
const ADVERSARIAL_TEST_SCHEMA = 'aevesa.adversarial-test-evidence-pack/v1' as const;

function memberDocumentForSchema(
  memberDocs: Record<string, unknown>,
  schema: string,
): unknown {
  if (schema === CARRIER_UNDERWRITING_EVIDENCE_PACK_SCHEMA) {
    return memberDocs.carrier_underwriting_evidence_pack ?? memberDocs[schema] ?? null;
  }
  if (schema === SHUTDOWN_DRILL_SCHEMA) {
    return memberDocs.shutdown_drill_bundle ?? memberDocs[schema] ?? null;
  }
  if (schema === ADVERSARIAL_TEST_SCHEMA) {
    return memberDocs.adversarial_test_evidence_pack ?? memberDocs[schema] ?? null;
  }
  return memberDocs[schema] ?? null;
}

function recomputeMemberVerifyOk(schema: string, embedded: unknown): boolean {
  if (embedded == null) return false;
  if (schema === CARRIER_UNDERWRITING_EVIDENCE_PACK_SCHEMA) {
    return verifyCarrierUnderwritingEvidencePack(embedded).ok === true;
  }
  if (schema === SHUTDOWN_DRILL_SCHEMA) {
    return verifyShutdownDrillBundle(embedded, { skipSignatureVerification: true }).ok === true;
  }
  if (schema === ADVERSARIAL_TEST_SCHEMA) {
    return verifyAdversarialTestEvidencePack(embedded).ok === true;
  }
  return false;
}

export function verifyCarrierMgaAcceptanceKit(
  docInput: unknown,
): CarrierMgaAcceptanceKitVerifyResult {
  const doc = asRecord(docInput) as CarrierMgaAcceptanceKitDocument | null;
  const schemaValid = doc?.schema === CARRIER_MGA_ACCEPTANCE_KIT_SCHEMA;

  const organization_id = String(doc?.organization_id || '').trim();
  const organizationIdPresent = organization_id.length > 0;

  const members = Array.isArray(doc?.composed_members) ? doc.composed_members : [];
  const composedMembersPresent = members.length >= 2;
  const memberDigestsValid =
    members.length === 0 ||
    members.every((m) => HEX64.test(String(m?.member_digest || '').toLowerCase()));

  const cadence = doc?.submission_cadence || {};
  const cadenceValid = CADENCES.has(cadence.cadence as SubmissionCadence);
  const submissionCadencePresent =
    cadenceValid &&
    String(cadence.period_label || '').trim().length > 0 &&
    String(cadence.next_resubmission_due || '').trim().length > 0 &&
    Number(cadence.kill_switch_drill_max_age_days) > 0;

  const carrierMember = members.find(
    (m) => m?.member_schema === 'aevesa.carrier-underwriting-evidence-pack/v1',
  );
  const drillMember = members.find(
    (m) => m?.member_schema === 'aevesa.shutdown-drill-bundle/v1',
  );

  const cadenceDigestsBound =
    HEX64.test(String(cadence.carrier_pack_digest || '').toLowerCase()) &&
    HEX64.test(String(cadence.kill_switch_drill_digest || '').toLowerCase()) &&
    (!carrierMember ||
      String(cadence.carrier_pack_digest || '').toLowerCase() ===
        String(carrierMember.member_digest || '').toLowerCase()) &&
    (!drillMember ||
      String(cadence.kill_switch_drill_digest || '').toLowerCase() ===
        String(drillMember.member_digest || '').toLowerCase());

  const assertions = doc?.mga_acceptance_assertions || {};
  const drillFresh = cadence.drill_fresh_for_submission === true;

  const docRecord = asRecord(docInput) || {};
  const memberDocs = asRecord(docRecord.member_documents) || {};
  const memberAttestations = asRecord(docRecord.member_verify_attestations) || {};
  const memberResolution = resolveComposedMemberVerifyState({
    members,
    member_documents: memberDocs,
    member_verify_attestations: memberAttestations,
    resolveMemberDocument: memberDocumentForSchema,
    recomputeMemberVerifyOk,
  });
  const membersForReadiness = memberResolution.members;
  const memberArtifactsBundled = memberResolution.memberArtifactsBundled;
  const memberAttestationsPresent = memberResolution.memberAttestationsPresent;
  const memberProofPresent = memberResolution.memberProofPresent;

  const derivedReadiness = deriveMgaAcceptanceReadiness(
    membersForReadiness,
    {
      six_controls_ready: assertions.six_controls_ready === true,
      kill_switch_drill_fresh: assertions.kill_switch_drill_fresh === true,
      executive_attestation_bound: assertions.executive_attestation_bound === true,
      broker_submission_ready: assertions.broker_submission_ready === true,
    },
    drillFresh,
  );

  const carrierMemberOk =
    membersForReadiness.find((m) => m.member_schema === CARRIER_UNDERWRITING_EVIDENCE_PACK_SCHEMA)
      ?.verify_ok === true;
  const drillMemberOk =
    membersForReadiness.find((m) => m.member_schema === SHUTDOWN_DRILL_SCHEMA)?.verify_ok === true;

  const selfAssertedVerifyIgnored = memberResolution.selfAssertedVerifyIgnored;

  const knownMemberSchemaList: string[] = [
    ...CARRIER_MGA_REQUIRED_MEMBER_SCHEMAS,
    ...CARRIER_MGA_OPTIONAL_MEMBER_SCHEMAS,
  ];
  const memberSchemasRecognized =
    members.length === 0 ||
    members.every((m) => knownMemberSchemaList.includes(String(m?.member_schema || '')));
  const adversarialMember = members.find(
    (m) => m?.member_schema === 'aevesa.adversarial-test-evidence-pack/v1',
  );
  const adversarialEmbedded = adversarialMember
    ? memberDocumentForSchema(memberDocs, ADVERSARIAL_TEST_SCHEMA)
    : null;
  const adversarialRecomputed =
    adversarialMember == null ||
    (adversarialEmbedded != null &&
      recomputeMemberVerifyOk(ADVERSARIAL_TEST_SCHEMA, adversarialEmbedded));
  const optionalAdversarialMemberValid =
    adversarialMember == null ||
    (HEX64.test(String(adversarialMember.member_digest || '').toLowerCase()) &&
      adversarialRecomputed === true &&
      (adversarialMember.verify_ok !== true || adversarialEmbedded != null));

  let mgaAssertionsConsistent =
    assertions.broker_submission_ready === true && carrierMemberOk && drillMemberOk;
  if (derivedReadiness === 'ready') {
    mgaAssertionsConsistent =
      mgaAssertionsConsistent &&
      assertions.six_controls_ready === true &&
      assertions.executive_attestation_bound === true &&
      assertions.kill_switch_drill_fresh === true &&
      drillFresh;
  } else if (derivedReadiness === 'partial') {
    mgaAssertionsConsistent = mgaAssertionsConsistent && (carrierMemberOk || drillMemberOk);
  }

  const readinessConsistent = assertions.mga_acceptance_readiness === derivedReadiness;

  const chainDisclosure = doc?.chain_composition_disclosure;
  const chainCompositionDisclosureValid =
    chainDisclosure == null ||
    (String(chainDisclosure.chain_enforcement_mode || '').trim().length > 0 &&
      String(chainDisclosure.owasp_asi_gl3_hint || '').trim().length > 0 &&
      String(chainDisclosure.carrier_footnote || '').trim().length > 0);

  let packDigestMatches = false;
  if (schemaValid && doc && submissionCadencePresent) {
    const preimageInput: Parameters<typeof buildCarrierMgaAcceptanceKitPreimage>[0] = {
      organization_id,
      generated_at: String(doc.generated_at || ''),
      mga_partner_ref: doc.mga_partner_ref ?? null,
      mga_acceptance_assertions: {
        six_controls_ready: assertions.six_controls_ready === true,
        kill_switch_drill_fresh: assertions.kill_switch_drill_fresh === true,
        executive_attestation_bound: assertions.executive_attestation_bound === true,
        broker_submission_ready: assertions.broker_submission_ready === true,
        mga_acceptance_readiness: String(
          assertions.mga_acceptance_readiness || derivedReadiness,
        ) as MgaAcceptanceReadiness,
      },
      composed_members: members.map((m) => ({
        member_schema: String(m?.member_schema || ''),
        member_digest: String(m?.member_digest || ''),
        verify_ok: m?.verify_ok === true,
        label: String(m?.label || ''),
        entry_count: m?.entry_count ?? null,
      })),
      submission_cadence: {
        cadence: cadence.cadence as SubmissionCadence,
        period_label: String(cadence.period_label || ''),
        next_resubmission_due: String(cadence.next_resubmission_due || ''),
        kill_switch_drill_max_age_days: Number(cadence.kill_switch_drill_max_age_days) || 90,
        kill_switch_drill_digest: String(cadence.kill_switch_drill_digest || ''),
        carrier_pack_digest: String(cadence.carrier_pack_digest || ''),
        drill_fresh_for_submission: drillFresh,
      },
    };
    if (chainDisclosure && chainCompositionDisclosureValid) {
      preimageInput.chain_composition_disclosure = {
        chain_enforcement_mode: String(chainDisclosure.chain_enforcement_mode || 'unknown'),
        uniformly_enforced: chainDisclosure.uniformly_enforced === true,
        weakest_link_index:
          chainDisclosure.weakest_link_index != null &&
          Number.isInteger(chainDisclosure.weakest_link_index)
            ? chainDisclosure.weakest_link_index
            : null,
        owasp_asi_gl3_hint: String(chainDisclosure.owasp_asi_gl3_hint || ''),
        owasp_at7_hint: String(chainDisclosure.owasp_at7_hint || ''),
        carrier_footnote: String(chainDisclosure.carrier_footnote || ''),
        egress_attestation_schema: String(
          chainDisclosure.egress_attestation_schema || 'aevesa.egress-attestation/v2',
        ),
      };
    }
    const preimage = buildCarrierMgaAcceptanceKitPreimage(preimageInput);
    const expected = sha256HexUtf8(stableStringify(preimage));
    packDigestMatches = String(doc.pack_digest || '').toLowerCase() === expected;
  }

  const {
    member_documents: _hashMemberDocs,
    member_verify_attestations: _hashMemberAttestations,
    ...hashOnlyDoc
  } = (docInput as Record<string, unknown>) || {};
  const hashOnlySurface = !hasForbiddenKeys(hashOnlyDoc);

  const memberVerifyRecomputed = memberResolution.memberVerifyRecomputed;

  const profileComplete =
    schemaValid &&
    organizationIdPresent &&
    composedMembersPresent &&
    memberDigestsValid &&
    submissionCadencePresent &&
    cadenceDigestsBound &&
    mgaAssertionsConsistent &&
    memberSchemasRecognized &&
    optionalAdversarialMemberValid &&
    packDigestMatches &&
    hashOnlySurface &&
    memberProofPresent &&
    memberVerifyRecomputed &&
    readinessConsistent &&
    chainCompositionDisclosureValid;

  const ok = profileComplete;

  let note: string | null = null;
  if (!schemaValid) note = `schema must be ${CARRIER_MGA_ACCEPTANCE_KIT_SCHEMA}`;
  else if (!memberProofPresent || selfAssertedVerifyIgnored) {
    note = pc09MemberProofNote(memberResolution);
  } else if (!submissionCadencePresent) note = 'submission_cadence incomplete';
  else if (!cadenceDigestsBound) note = 'submission_cadence digests must match composed members';
  else if (!packDigestMatches) note = 'pack_digest does not match canonical preimage';
  else if (!mgaAssertionsConsistent) note = 'mga_acceptance_assertions inconsistent with composed members';
  else if (!readinessConsistent) note = 'mga_acceptance_readiness inconsistent with member verify state';
  else if (!memberDigestsValid) note = 'composed member_digest must be SHA-256 hex';
  else if (!chainCompositionDisclosureValid) note = 'chain_composition_disclosure incomplete';

  return {
    schema: CARRIER_MGA_ACCEPTANCE_KIT_SCHEMA,
    sku: CARRIER_MGA_ACCEPTANCE_KIT_SKU,
    ok,
    checks: {
      schemaValid,
      organizationIdPresent,
      composedMembersPresent,
      memberDigestsValid,
      submissionCadencePresent,
      cadenceDigestsBound,
      mgaAssertionsConsistent,
      memberSchemasRecognized,
      optionalAdversarialMemberValid,
      packDigestMatches,
      hashOnlySurface,
      memberArtifactsBundled,
      memberAttestationsPresent,
      memberProofPresent,
      memberVerifyRecomputed,
      readinessConsistent,
      chainCompositionDisclosureValid,
      profileComplete,
    },
    mga_acceptance_readiness: derivedReadiness,
    gtmLine:
      'Silent AI ended Jan 2026. Aevesa ships the six-control pack with a fresh kill-switch drill bound to quarterly MGA re-submission — offline-verifiable.',
    note,
  };
}
