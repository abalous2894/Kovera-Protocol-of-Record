import { sha256HexUtf8 } from '../core/sha256.js';
import { VERIFIABLE_DENIAL_EVIDENCE_PACK_SCHEMA, buildVerifiableDenialEvidencePackPreimage, deriveDenialReadiness } from '../core/verifiableDenialEvidencePack.js';
import { stableStringify } from '../core/stableStringify.js';
import type { DenialReadiness, EnforcementPlane } from '../core/verifiableDenialEvidencePack.js';
import { verifyReceipt } from './verifyReceipt.js';
import { verifySetCompletenessBundle } from './setCompletenessVerify.js';
import { verifyShutdownDrillBundle } from './shutdownDrillBundleVerify.js';
import {
  extractComposedPackProofLayers,
  hashOnlyComposedPackSurface,
  pc09MemberProofNote,
  resolveComposedMemberVerifyState,
} from './composedPackMemberVerify.js';

export const VERIFIABLE_DENIAL_EVIDENCE_PACK_SKU =
  'aevesa-verifiable-denial-evidence-pack-v1' as const;

const HEX64 = /^[a-f0-9]{64}$/;
const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|ssn|phone|address|pan|cvv)$/i;

const ENFORCEMENT_PLANES = new Set<EnforcementPlane>([
  'ai_agent_gateway',
  'runtime_pep',
  'kill_switch',
  'gateway_attestation',
]);

export interface VerifiableDenialEvidencePackDocument {
  schema?: string;
  organization_id?: string;
  session_id?: string;
  correlation_id?: string | null;
  generated_at?: string;
  enforcement_plane?: EnforcementPlane;
  enforcement_vendor_ref?: string | null;
  denial_assertions?: {
    pre_execution?: boolean;
    execution_occurred?: boolean;
    third_party_verifiable?: boolean;
    completeness_bound?: boolean;
    silence_window_observed?: boolean;
    denial_readiness?: DenialReadiness;
  };
  composed_members?: Array<{
    member_schema?: string;
    member_digest?: string;
    verify_ok?: boolean;
    label?: string;
    entry_count?: number | null;
  }>;
  pack_digest?: string;
}

export interface VerifiableDenialEvidencePackVerifyChecks {
  schemaValid: boolean;
  organizationIdPresent: boolean;
  sessionIdPresent: boolean;
  enforcementPlaneValid: boolean;
  composedMembersPresent: boolean;
  memberDigestsValid: boolean;
  denialAssertionsConsistent: boolean;
  packDigestMatches: boolean;
  hashOnlySurface: boolean;
  memberArtifactsBundled: boolean;
  memberAttestationsPresent: boolean;
  memberProofPresent: boolean;
  memberVerifyRecomputed: boolean;
  readinessConsistent: boolean;
  profileComplete: boolean;
}

export interface VerifiableDenialEvidencePackVerifyResult {
  schema: typeof VERIFIABLE_DENIAL_EVIDENCE_PACK_SCHEMA;
  sku: typeof VERIFIABLE_DENIAL_EVIDENCE_PACK_SKU;
  ok: boolean;
  checks: VerifiableDenialEvidencePackVerifyChecks;
  denial_readiness: DenialReadiness | null;
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

const LIABILITY_RECEIPT_SCHEMA = 'liability-receipt/v1' as const;
const SET_COMPLETENESS_SCHEMA = 'aevesa.set-completeness/v1' as const;
const SHUTDOWN_DRILL_SCHEMA = 'aevesa.shutdown-drill-bundle/v1' as const;

function memberDocumentForSchema(
  memberDocs: Record<string, unknown>,
  schema: string,
): unknown {
  if (schema === LIABILITY_RECEIPT_SCHEMA) {
    return memberDocs.liability_receipt ?? memberDocs.denied_receipt ?? memberDocs[schema] ?? null;
  }
  if (schema === SET_COMPLETENESS_SCHEMA) {
    return memberDocs.set_completeness_manifest ?? memberDocs.set_completeness ?? memberDocs[schema] ?? null;
  }
  if (schema === SHUTDOWN_DRILL_SCHEMA) {
    return memberDocs.shutdown_drill_bundle ?? memberDocs[schema] ?? null;
  }
  return memberDocs[schema] ?? null;
}

function recomputeMemberVerifyOk(schema: string, embedded: unknown): boolean {
  if (embedded == null) return false;
  if (schema === LIABILITY_RECEIPT_SCHEMA) {
    return verifyReceipt(embedded, { skipIntegritySignatureWithoutKey: true }).isValid === true;
  }
  if (schema === SET_COMPLETENESS_SCHEMA) {
    return verifySetCompletenessBundle(embedded).ok === true;
  }
  if (schema === SHUTDOWN_DRILL_SCHEMA) {
    return verifyShutdownDrillBundle(embedded, { skipSignatureVerification: true }).ok === true;
  }
  return false;
}

export function verifyVerifiableDenialEvidencePack(
  docInput: unknown,
): VerifiableDenialEvidencePackVerifyResult {
  const doc = asRecord(docInput) as VerifiableDenialEvidencePackDocument | null;
  const schemaValid = doc?.schema === VERIFIABLE_DENIAL_EVIDENCE_PACK_SCHEMA;

  const organization_id = String(doc?.organization_id || '').trim();
  const organizationIdPresent = organization_id.length > 0;

  const session_id = String(doc?.session_id || '').trim();
  const sessionIdPresent = session_id.length > 0;

  const plane = doc?.enforcement_plane;
  const enforcementPlaneValid = ENFORCEMENT_PLANES.has(plane as EnforcementPlane);

  const members = Array.isArray(doc?.composed_members) ? doc.composed_members : [];
  const composedMembersPresent = members.length >= 1;
  const memberDigestsValid =
    members.length === 0 ||
    members.every((m) => HEX64.test(String(m?.member_digest || '').toLowerCase()));

  const { memberDocs, memberAttestations } = extractComposedPackProofLayers(doc);

  const memberResolution = resolveComposedMemberVerifyState({
    members: members.map((m) => ({
      member_schema: String(m?.member_schema || ''),
      member_digest: String(m?.member_digest || ''),
      verify_ok: m?.verify_ok === true,
      label: String(m?.label || ''),
      entry_count: m?.entry_count ?? null,
    })),
    member_documents: memberDocs,
    member_verify_attestations: memberAttestations,
    resolveMemberDocument: memberDocumentForSchema,
    recomputeMemberVerifyOk,
  });

  const membersForReadiness = memberResolution.members.map((m) => ({
    member_schema: m.member_schema,
    member_digest: m.member_digest,
    verify_ok: m.verify_ok,
    label: m.label,
    entry_count: m.entry_count,
  }));

  const derivedReadiness = deriveDenialReadiness(membersForReadiness);

  const assertions = doc?.denial_assertions || {};
  const deniedMemberOk = membersForReadiness.some(
    (m) => m.member_schema === LIABILITY_RECEIPT_SCHEMA && m.verify_ok === true,
  );
  const completenessMemberOk = membersForReadiness.some(
    (m) => m.member_schema === SET_COMPLETENESS_SCHEMA && m.verify_ok === true,
  );
  const silenceMemberOk = membersForReadiness.some(
    (m) => m.member_schema === SHUTDOWN_DRILL_SCHEMA && m.verify_ok === true,
  );

  const memberArtifactsBundled = memberResolution.memberArtifactsBundled;
  const memberAttestationsPresent = memberResolution.memberAttestationsPresent;
  const memberProofPresent = memberResolution.memberProofPresent;
  const selfAssertedVerifyIgnored = memberResolution.selfAssertedVerifyIgnored;

  let denialAssertionsConsistent =
    assertions.pre_execution === true &&
    assertions.execution_occurred !== true &&
    assertions.third_party_verifiable === true;
  if (derivedReadiness === 'complete' || derivedReadiness === 'partial') {
    denialAssertionsConsistent =
      denialAssertionsConsistent &&
      assertions.completeness_bound === true &&
      deniedMemberOk &&
      completenessMemberOk;
  } else {
    denialAssertionsConsistent = denialAssertionsConsistent && deniedMemberOk;
  }

  const readinessConsistent = assertions.denial_readiness === derivedReadiness;

  let packDigestMatches = false;
  if (schemaValid && doc && enforcementPlaneValid) {
    const preimage = buildVerifiableDenialEvidencePackPreimage({
      organization_id,
      session_id,
      correlation_id: doc.correlation_id ?? null,
      generated_at: String(doc.generated_at || ''),
      enforcement_plane: plane as EnforcementPlane,
      enforcement_vendor_ref: doc.enforcement_vendor_ref ?? null,
      denial_assertions: {
        pre_execution: assertions.pre_execution === true,
        execution_occurred: assertions.execution_occurred === true,
        third_party_verifiable: assertions.third_party_verifiable === true,
        completeness_bound: assertions.completeness_bound === true,
        silence_window_observed: assertions.silence_window_observed === true,
        denial_readiness: String(assertions.denial_readiness || derivedReadiness) as DenialReadiness,
      },
      composed_members: members.map((m) => ({
        member_schema: String(m?.member_schema || ''),
        member_digest: String(m?.member_digest || ''),
        verify_ok: m?.verify_ok === true,
        label: String(m?.label || ''),
        entry_count: m?.entry_count ?? null,
      })),
    });
    const expected = sha256HexUtf8(stableStringify(preimage));
    packDigestMatches = String(doc.pack_digest || '').toLowerCase() === expected;
  }

  const hashOnlySurface = hashOnlyComposedPackSurface(docInput, hasForbiddenKeys);

  const memberVerifyRecomputed =
    deniedMemberOk &&
    completenessMemberOk &&
    (members.some((m) => m?.member_schema === SHUTDOWN_DRILL_SCHEMA)
      ? silenceMemberOk
      : true);

  const profileComplete =
    schemaValid &&
    organizationIdPresent &&
    sessionIdPresent &&
    enforcementPlaneValid &&
    composedMembersPresent &&
    memberDigestsValid &&
    denialAssertionsConsistent &&
    packDigestMatches &&
    hashOnlySurface &&
    memberProofPresent &&
    memberVerifyRecomputed &&
    readinessConsistent;

  const ok = profileComplete;

  let note: string | null = null;
  if (!schemaValid) note = `schema must be ${VERIFIABLE_DENIAL_EVIDENCE_PACK_SCHEMA}`;
  else if (!memberProofPresent || selfAssertedVerifyIgnored) {
    note = pc09MemberProofNote(memberResolution);
  } else if (!enforcementPlaneValid) note = 'enforcement_plane invalid';
  else if (!packDigestMatches) note = 'pack_digest does not match canonical preimage';
  else if (!denialAssertionsConsistent) note = 'denial_assertions inconsistent with composed members';
  else if (!readinessConsistent) note = 'denial_readiness inconsistent with member verify state';
  else if (!memberDigestsValid) note = 'composed member_digest must be SHA-256 hex';

  return {
    schema: VERIFIABLE_DENIAL_EVIDENCE_PACK_SCHEMA,
    sku: VERIFIABLE_DENIAL_EVIDENCE_PACK_SKU,
    ok,
    checks: {
      schemaValid,
      organizationIdPresent,
      sessionIdPresent,
      enforcementPlaneValid,
      composedMembersPresent,
      memberDigestsValid,
      denialAssertionsConsistent,
      packDigestMatches,
      hashOnlySurface,
      memberArtifactsBundled,
      memberAttestationsPresent,
      memberProofPresent,
      memberVerifyRecomputed,
      readinessConsistent,
      profileComplete,
    },
    denial_readiness: derivedReadiness,
    gtmLine:
      'The gateway blocked it in their UI. Aevesa proves the block happened before execution — offline, with set-completeness bound.',
    note,
  };
}
