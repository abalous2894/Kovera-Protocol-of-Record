import { sha256HexUtf8 } from '../core/sha256.js';
import { stableStringify } from '../core/stableStringify.js';
import {
  buildTraceableConductPackagePreimage,
  TRACEABLE_CONDUCT_PACKAGE_SCHEMA,
  TRACEABLE_CONDUCT_REQUIRED_MEMBER_SCHEMAS,
  resolveMemberDocumentDigest,
  type TraceabilityReadiness,
} from '../core/traceableConductPackage.js';
import { TRACEABLE_CONDUCT_MANIFEST_SCHEMA } from '../core/traceableConductManifest.js';
import { CROSS_ORG_DELEGATION_CHAIN_PACK_SCHEMA } from '../core/crossOrgDelegationChainPack.js';
import { HITL_APPROVAL_RECEIPT_SCHEMA } from '../core/hitlApprovalReceipt.js';
import { INTERCEPT_DECISION_ATTESTATION_SCHEMA } from '../core/interceptDecisionAttestation.js';
import { verifyTraceableConductManifest } from './traceableConductManifestVerify.js';
import { verifyCrossOrgDelegationChainPack } from './crossOrgDelegationChainPackVerify.js';
import { verifyHitlApprovalReceipt } from './hitlApprovalReceiptVerify.js';
import { verifyInterceptDecisionAttestation } from './interceptDecisionAttestationVerify.js';
import { verifyVerifiableDenialEvidencePack } from './verifiableDenialEvidencePackVerify.js';
import { verifyIndependentGuardianBundle } from './independentGuardianBundleVerify.js';

export const TRACEABLE_CONDUCT_PACKAGE_SKU = 'aevesa-traceable-conduct-package-v1' as const;

const HEX64 = /^[a-f0-9]{64}$/;
const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|ssn|phone|address|pan|cvv)$/i;

export interface TraceableConductPackageVerifyOptions {
  requireAllMembers?: boolean;
}

export interface TraceableConductPackageVerifyResult {
  schema: typeof TRACEABLE_CONDUCT_PACKAGE_SCHEMA;
  sku: typeof TRACEABLE_CONDUCT_PACKAGE_SKU;
  ok: boolean;
  checks: Record<string, boolean>;
  traceability_readiness: TraceabilityReadiness | null;
  profileComplete: boolean;
  member_results: Record<string, boolean>;
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

function verifyEmbeddedMember(schema: string, doc: unknown): boolean {
  if (schema === TRACEABLE_CONDUCT_MANIFEST_SCHEMA) {
    return verifyTraceableConductManifest(doc).ok === true;
  }
  if (schema === CROSS_ORG_DELEGATION_CHAIN_PACK_SCHEMA) {
    return verifyCrossOrgDelegationChainPack(doc).ok === true;
  }
  if (schema === HITL_APPROVAL_RECEIPT_SCHEMA) {
    return verifyHitlApprovalReceipt(doc, { requireMatch: true }).ok === true;
  }
  if (schema === INTERCEPT_DECISION_ATTESTATION_SCHEMA) {
    return verifyInterceptDecisionAttestation(doc).ok === true;
  }
  if (schema === 'aevesa.verifiable-denial-evidence-pack/v1') {
    return verifyVerifiableDenialEvidencePack(doc).ok === true;
  }
  if (schema === 'aevesa.independent-guardian-bundle/v1') {
    return verifyIndependentGuardianBundle(doc).ok === true;
  }
  return false;
}

function memberDocumentForSchema(
  docs: Record<string, unknown>,
  schema: string,
): Record<string, unknown> | null {
  if (schema === TRACEABLE_CONDUCT_MANIFEST_SCHEMA) {
    return asRecord(docs.conduct_manifest);
  }
  if (schema === CROSS_ORG_DELEGATION_CHAIN_PACK_SCHEMA) {
    return asRecord(docs.delegation_chain_pack);
  }
  if (schema === HITL_APPROVAL_RECEIPT_SCHEMA) {
    return asRecord(docs.hitl_approval_receipt);
  }
  if (schema === INTERCEPT_DECISION_ATTESTATION_SCHEMA) {
    return asRecord(docs.intercept_decision_attestation);
  }
  if (schema === 'aevesa.verifiable-denial-evidence-pack/v1') {
    return asRecord(docs.verifiable_denial_evidence_pack);
  }
  if (schema === 'aevesa.independent-guardian-bundle/v1') {
    return asRecord(docs.independent_guardian_bundle);
  }
  return null;
}

export function verifyTraceableConductPackage(
  docInput: unknown,
  options: TraceableConductPackageVerifyOptions = {},
): TraceableConductPackageVerifyResult {
  const doc = asRecord(docInput);
  const schemaValid = doc?.schema === TRACEABLE_CONDUCT_PACKAGE_SCHEMA;
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;
  const sessionIdPresent = String(doc?.session_id || '').trim().length > 0;

  const ordered = Array.isArray(doc?.ordered_entry_hashes) ? doc.ordered_entry_hashes : [];
  const orderedEntriesPresent = ordered.length >= 2;
  const orderedDigestsValid =
    ordered.length === 0 || ordered.every((h) => HEX64.test(String(h).toLowerCase()));

  const memberDocs = asRecord(doc?.member_documents) || {};
  const members = Array.isArray(doc?.composed_members) ? doc.composed_members : [];

  const member_results: Record<string, boolean> = {};
  let allRequiredMembersPresent = true;
  let allRequiredMembersVerifyOk = true;

  for (const schema of TRACEABLE_CONDUCT_REQUIRED_MEMBER_SCHEMAS) {
    const embedded = memberDocumentForSchema(memberDocs, schema);
    const present = embedded != null;
    member_results[`${schema}_present`] = present;
    if (!present) {
      allRequiredMembersPresent = false;
      allRequiredMembersVerifyOk = false;
      member_results[`${schema}_verify_ok`] = false;
      continue;
    }
    const verifyOk = verifyEmbeddedMember(schema, embedded);
    member_results[`${schema}_verify_ok`] = verifyOk;
    if (!verifyOk) allRequiredMembersVerifyOk = false;
  }

  const composedRefsValid =
    members.length === 0 ||
    members.every((m) => HEX64.test(String(m?.member_digest || '').toLowerCase()));

  let composedMembersMatchDocuments = true;
  for (const ref of members) {
    const schema = String(ref?.member_schema || '');
    const embedded = memberDocumentForSchema(memberDocs, schema);
    const expected = resolveMemberDocumentDigest(schema, embedded);
    if (
      expected != null
      && String(ref?.member_digest || '').toLowerCase() !== String(expected).toLowerCase()
    ) {
      composedMembersMatchDocuments = false;
    }
    if (ref?.verify_ok === true && embedded != null && !verifyEmbeddedMember(schema, embedded)) {
      composedMembersMatchDocuments = false;
    }
  }

  const manifest = asRecord(memberDocs.conduct_manifest);
  const denialHashes = Array.isArray(manifest?.denial_entry_hashes)
    ? manifest.denial_entry_hashes
    : [];
  const denialSurfacePresent =
    denialHashes.length > 0 || memberDocs.verifiable_denial_evidence_pack != null;

  const binding = asRecord(doc?.reconstruction_session_binding) || {};
  const normalizationBound = binding.normalization_bound === true;
  const bindingManifestDigestValid = HEX64.test(
    String(binding.conduct_manifest_digest || '').toLowerCase(),
  );
  const manifestDigest = resolveMemberDocumentDigest(
    TRACEABLE_CONDUCT_MANIFEST_SCHEMA,
    manifest,
  );
  const bindingMatchesManifest =
    manifestDigest != null
    && String(binding.conduct_manifest_digest || '').toLowerCase() === manifestDigest.toLowerCase();

  const bindingMatchesCounts =
    Number(binding.ordered_entry_count) === ordered.length
    && Number(binding.denial_entry_count) === denialHashes.length;

  const assertions = asRecord(doc?.reconstruction_assertions) || {};
  const derivedReadiness = String(
    assertions.traceability_readiness || '',
  ) as TraceabilityReadiness;

  let reconstructionAssertionsConsistent =
    assertions.third_party_verifiable === true && sessionIdPresent;

  if (derivedReadiness === 'reconstruction_ready') {
    reconstructionAssertionsConsistent =
      reconstructionAssertionsConsistent
      && assertions.all_required_members_present === true
      && assertions.ordered_reconstruction_complete === true
      && assertions.denial_surface_present === true
      && allRequiredMembersPresent
      && allRequiredMembersVerifyOk
      && denialSurfacePresent
      && orderedEntriesPresent
      && normalizationBound;
  } else if (derivedReadiness === 'partial') {
    reconstructionAssertionsConsistent =
      reconstructionAssertionsConsistent
      && assertions.all_required_members_present === true
      && allRequiredMembersPresent
      && orderedEntriesPresent;
  }

  const readinessConsistent = assertions.traceability_readiness === derivedReadiness;

  let packageDigestMatches = false;
  if (schemaValid && doc && bindingManifestDigestValid) {
    const window = asRecord(doc.reconstruction_window) || {};
    const preimage = buildTraceableConductPackagePreimage({
      organization_id: String(doc.organization_id),
      session_id: String(doc.session_id),
      generated_at: String(doc.generated_at || ''),
      reconstruction_window: {
        started_at: String(window.started_at || ''),
        ended_at: String(window.ended_at || ''),
      },
      ordered_entry_hashes: ordered.map(String),
      composed_members: members.map((m) => ({
        member_schema: String(m?.member_schema || ''),
        member_digest: String(m?.member_digest || ''),
        verify_ok: m?.verify_ok === true,
        label: String(m?.label || ''),
        sequence_index: Number(m?.sequence_index) || 0,
        entry_count: m?.entry_count ?? null,
      })),
      reconstruction_session_binding: {
        session_id: String(binding.session_id || ''),
        conduct_manifest_digest: String(binding.conduct_manifest_digest || ''),
        ordered_entry_count: Number(binding.ordered_entry_count) || 0,
        denial_entry_count: Number(binding.denial_entry_count) || 0,
        normalization_bound: normalizationBound,
      },
      reconstruction_assertions: {
        third_party_verifiable: assertions.third_party_verifiable === true,
        all_required_members_present: assertions.all_required_members_present === true,
        ordered_reconstruction_complete: assertions.ordered_reconstruction_complete === true,
        denial_surface_present: assertions.denial_surface_present === true,
        traceability_readiness: derivedReadiness,
      },
    });
    packageDigestMatches =
      sha256HexUtf8(stableStringify(preimage)) ===
      String(doc.package_digest || '').toLowerCase();
  }

  const hashOnlySurface = doc != null && !hasForbiddenKeys(doc);
  const requireAll = options.requireAllMembers === true;
  const membersRequirementOk =
    !requireAll || (allRequiredMembersPresent && allRequiredMembersVerifyOk);

  const profileComplete =
    schemaValid
    && organizationIdPresent
    && sessionIdPresent
    && orderedEntriesPresent
    && orderedDigestsValid
    && allRequiredMembersPresent
    && allRequiredMembersVerifyOk
    && composedRefsValid
    && composedMembersMatchDocuments
    && denialSurfacePresent
    && bindingMatchesManifest
    && bindingMatchesCounts
    && normalizationBound
    && packageDigestMatches
    && hashOnlySurface
    && reconstructionAssertionsConsistent
    && readinessConsistent
    && membersRequirementOk;

  const ok = profileComplete;

  let note: string | null = null;
  if (!allRequiredMembersPresent) {
    note = 'missing required member document — fails closed';
  } else if (!allRequiredMembersVerifyOk) {
    note = 'required member verification failed';
  } else if (!packageDigestMatches) {
    note = 'package_digest does not match preimage';
  } else if (!denialSurfacePresent) {
    note = 'denial surface required for reconstruction_ready profile';
  } else if (!bindingMatchesManifest) {
    note = 'reconstruction_session_binding inconsistent with conduct manifest';
  } else if (!reconstructionAssertionsConsistent) {
    note = 'reconstruction_assertions inconsistent with derived checks';
  }

  return {
    schema: TRACEABLE_CONDUCT_PACKAGE_SCHEMA,
    sku: TRACEABLE_CONDUCT_PACKAGE_SKU,
    ok,
    checks: {
      schemaValid: schemaValid === true,
      organizationIdPresent: organizationIdPresent === true,
      sessionIdPresent: sessionIdPresent === true,
      orderedEntriesPresent: orderedEntriesPresent === true,
      allRequiredMembersPresent: allRequiredMembersPresent === true,
      allRequiredMembersVerifyOk: allRequiredMembersVerifyOk === true,
      composedMembersMatchDocuments: composedMembersMatchDocuments === true,
      denialSurfacePresent: denialSurfacePresent === true,
      bindingMatchesManifest: bindingMatchesManifest === true,
      bindingMatchesCounts: bindingMatchesCounts === true,
      normalizationBound: normalizationBound === true,
      packageDigestMatches: packageDigestMatches === true,
      hashOnlySurface: hashOnlySurface === true,
      reconstructionAssertionsConsistent: reconstructionAssertionsConsistent === true,
      readinessConsistent: readinessConsistent === true,
      profileComplete: profileComplete === true,
    },
    traceability_readiness: derivedReadiness || null,
    profileComplete,
    member_results,
    gtmLine:
      'Attributable is where logs stop. Traceable is where Aevesa starts.',
    note,
  };
}

export default { verifyTraceableConductPackage, TRACEABLE_CONDUCT_PACKAGE_SKU };
