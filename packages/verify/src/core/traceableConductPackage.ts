import { sha256HexUtf8 } from './sha256.js';
import { stableStringify } from './stableStringify.js';
import { TRACEABLE_CONDUCT_MANIFEST_SCHEMA } from './traceableConductManifest.js';
import { CROSS_ORG_DELEGATION_CHAIN_PACK_SCHEMA } from './crossOrgDelegationChainPack.js';
import { HITL_APPROVAL_RECEIPT_SCHEMA } from './hitlApprovalReceipt.js';
import { INTERCEPT_DECISION_ATTESTATION_SCHEMA } from './interceptDecisionAttestation.js';

/** Wave 14 Track D — full traceable conduct reconstruction package (GAP-11). */

export const TRACEABLE_CONDUCT_PACKAGE_SCHEMA = 'aevesa.traceable-conduct-package/v1' as const;

export const TRACEABLE_CONDUCT_REQUIRED_MEMBER_SCHEMAS = [
  TRACEABLE_CONDUCT_MANIFEST_SCHEMA,
  CROSS_ORG_DELEGATION_CHAIN_PACK_SCHEMA,
  HITL_APPROVAL_RECEIPT_SCHEMA,
  INTERCEPT_DECISION_ATTESTATION_SCHEMA,
] as const;

export const TRACEABLE_CONDUCT_OPTIONAL_MEMBER_SCHEMAS = [
  'aevesa.verifiable-denial-evidence-pack/v1',
  'aevesa.independent-guardian-bundle/v1',
] as const;

export type TraceabilityReadiness = 'reconstruction_ready' | 'partial' | 'incomplete';

export interface TraceableConductComposedMemberRef {
  member_schema: string;
  member_digest: string;
  verify_ok: boolean;
  label: string;
  sequence_index: number;
  entry_count?: number | null;
}

export interface ReconstructionWindow {
  started_at: string;
  ended_at: string;
}

export interface ReconstructionSessionBinding {
  session_id: string;
  conduct_manifest_digest: string;
  ordered_entry_count: number;
  denial_entry_count: number;
  normalization_bound: boolean;
}

export interface ReconstructionAssertionsInput {
  third_party_verifiable: boolean;
}

export interface TraceableConductMemberDocuments {
  conduct_manifest: Record<string, unknown>;
  delegation_chain_pack?: Record<string, unknown>;
  hitl_approval_receipt?: Record<string, unknown>;
  intercept_decision_attestation?: Record<string, unknown>;
  verifiable_denial_evidence_pack?: Record<string, unknown>;
  independent_guardian_bundle?: Record<string, unknown>;
}

export interface TraceableConductPackageInput {
  organization_id: string;
  session_id: string;
  generated_at?: string;
  reconstruction_window: ReconstructionWindow;
  ordered_entry_hashes: string[];
  member_documents: TraceableConductMemberDocuments;
  composed_members: TraceableConductComposedMemberRef[];
  reconstruction_session_binding: ReconstructionSessionBinding;
  reconstruction_assertions: ReconstructionAssertionsInput;
  disclaimer?: string;
}

export function resolveMemberDocumentDigest(
  memberSchema: string,
  doc: Record<string, unknown> | null | undefined,
): string | null {
  if (!doc || typeof doc !== 'object') return null;
  switch (memberSchema) {
    case TRACEABLE_CONDUCT_MANIFEST_SCHEMA:
      return typeof doc.manifest_digest === 'string' ? doc.manifest_digest : null;
    case CROSS_ORG_DELEGATION_CHAIN_PACK_SCHEMA:
      return typeof doc.pack_digest === 'string' ? doc.pack_digest : null;
    case HITL_APPROVAL_RECEIPT_SCHEMA:
      return typeof doc.approval_digest === 'string' ? doc.approval_digest : null;
    case INTERCEPT_DECISION_ATTESTATION_SCHEMA:
      return typeof doc.attestation_digest === 'string' ? doc.attestation_digest : null;
    case 'aevesa.verifiable-denial-evidence-pack/v1':
      return typeof doc.pack_digest === 'string' ? doc.pack_digest : null;
    case 'aevesa.independent-guardian-bundle/v1':
      return typeof doc.bundle_digest === 'string' ? doc.bundle_digest : null;
    default:
      return null;
  }
}

function sortHex64(values: string[]): string[] {
  return [...values]
    .map((v) => String(v || '').trim().toLowerCase())
    .filter((v) => /^[a-f0-9]{64}$/.test(v))
    .sort();
}

export function deriveTraceabilityReadiness(
  allRequiredMembersPresent: boolean,
  allRequiredMembersVerifyOk: boolean,
  denialSurfacePresent: boolean,
  orderedEntriesPresent: boolean,
  normalizationBound: boolean,
  thirdPartyVerifiable: boolean,
): TraceabilityReadiness {
  if (
    allRequiredMembersPresent
    && allRequiredMembersVerifyOk
    && denialSurfacePresent
    && orderedEntriesPresent
    && normalizationBound
    && thirdPartyVerifiable
  ) {
    return 'reconstruction_ready';
  }
  if (orderedEntriesPresent && allRequiredMembersPresent && normalizationBound) {
    return 'partial';
  }
  return 'incomplete';
}

export function buildReconstructionAssertionsBlock(
  input: ReconstructionAssertionsInput,
  allRequiredMembersPresent: boolean,
  allRequiredMembersVerifyOk: boolean,
  denialSurfacePresent: boolean,
  orderedEntriesPresent: boolean,
  normalizationBound: boolean,
) {
  const traceability_readiness = deriveTraceabilityReadiness(
    allRequiredMembersPresent,
    allRequiredMembersVerifyOk,
    denialSurfacePresent,
    orderedEntriesPresent,
    normalizationBound,
    input.third_party_verifiable === true,
  );

  return {
    third_party_verifiable: input.third_party_verifiable === true,
    all_required_members_present: allRequiredMembersPresent,
    ordered_reconstruction_complete: orderedEntriesPresent && allRequiredMembersVerifyOk,
    denial_surface_present: denialSurfacePresent,
    traceability_readiness,
  };
}

export function buildTraceableConductPackagePreimage(
  input: Omit<
    TraceableConductPackageInput,
    'disclaimer' | 'reconstruction_assertions' | 'member_documents'
  > & {
    generated_at: string;
    reconstruction_assertions: ReturnType<typeof buildReconstructionAssertionsBlock>;
  },
): Record<string, unknown> {
  const ordered_entry_hashes = sortHex64(input.ordered_entry_hashes || []);
  const composed_members = [...input.composed_members]
    .map((m) => ({
      member_schema: String(m.member_schema || '').trim(),
      member_digest: String(m.member_digest || '').trim().toLowerCase(),
      verify_ok: m.verify_ok === true,
      label: String(m.label || '').trim(),
      sequence_index: Number(m.sequence_index) || 0,
      entry_count: m.entry_count != null ? Number(m.entry_count) : null,
    }))
    .sort((a, b) => a.sequence_index - b.sequence_index);

  const binding = input.reconstruction_session_binding;

  return {
    schema: TRACEABLE_CONDUCT_PACKAGE_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    session_id: String(input.session_id || '').trim(),
    generated_at: input.generated_at,
    reconstruction_window: {
      started_at: String(input.reconstruction_window.started_at || '').trim(),
      ended_at: String(input.reconstruction_window.ended_at || '').trim(),
    },
    ordered_entry_hashes,
    composed_members,
    reconstruction_session_binding: {
      session_id: String(binding.session_id || '').trim(),
      conduct_manifest_digest: String(binding.conduct_manifest_digest || '').toLowerCase(),
      ordered_entry_count: Number(binding.ordered_entry_count) || 0,
      denial_entry_count: Number(binding.denial_entry_count) || 0,
      normalization_bound: binding.normalization_bound === true,
    },
    reconstruction_assertions: input.reconstruction_assertions,
  };
}

export interface TraceableConductPackageDocument {
  schema: typeof TRACEABLE_CONDUCT_PACKAGE_SCHEMA;
  organization_id: string;
  session_id: string;
  generated_at: string;
  reconstruction_window: ReconstructionWindow;
  ordered_entry_hashes: string[];
  member_documents: TraceableConductMemberDocuments;
  composed_members: TraceableConductComposedMemberRef[];
  reconstruction_session_binding: ReconstructionSessionBinding;
  reconstruction_assertions: ReturnType<typeof buildReconstructionAssertionsBlock>;
  package_digest: string;
  disclaimer: string;
}

export function buildTraceableConductPackageDocument(
  input: TraceableConductPackageInput,
): TraceableConductPackageDocument {
  const generated_at = input.generated_at || new Date().toISOString();
  const docs = input.member_documents;

  const requiredPresent = TRACEABLE_CONDUCT_REQUIRED_MEMBER_SCHEMAS.every((schema) => {
    if (schema === TRACEABLE_CONDUCT_MANIFEST_SCHEMA) return docs.conduct_manifest != null;
    if (schema === CROSS_ORG_DELEGATION_CHAIN_PACK_SCHEMA) return docs.delegation_chain_pack != null;
    if (schema === HITL_APPROVAL_RECEIPT_SCHEMA) return docs.hitl_approval_receipt != null;
    if (schema === INTERCEPT_DECISION_ATTESTATION_SCHEMA) {
      return docs.intercept_decision_attestation != null;
    }
    return false;
  });

  const requiredVerifyOk = input.composed_members
    .filter((m) =>
      TRACEABLE_CONDUCT_REQUIRED_MEMBER_SCHEMAS.includes(
        m.member_schema as (typeof TRACEABLE_CONDUCT_REQUIRED_MEMBER_SCHEMAS)[number],
      ),
    )
    .every((m) => m.verify_ok === true);

  const manifest = docs.conduct_manifest || {};
  const denialHashes = Array.isArray(manifest.denial_entry_hashes) ? manifest.denial_entry_hashes : [];
  const denialSurfacePresent =
    denialHashes.length > 0 || docs.verifiable_denial_evidence_pack != null;
  const orderedEntriesPresent = (input.ordered_entry_hashes || []).length >= 2;

  const reconstruction_assertions = buildReconstructionAssertionsBlock(
    input.reconstruction_assertions,
    requiredPresent,
    requiredVerifyOk,
    denialSurfacePresent,
    orderedEntriesPresent,
    input.reconstruction_session_binding.normalization_bound === true,
  );

  const { member_documents: _memberDocuments, ...preimageFields } = input;
  const preimage = buildTraceableConductPackagePreimage({
    ...preimageFields,
    generated_at,
    reconstruction_assertions,
  });
  const package_digest = sha256HexUtf8(stableStringify(preimage));

  return {
    ...(preimage as Omit<TraceableConductPackageDocument, 'member_documents' | 'package_digest' | 'disclaimer'>),
    member_documents: input.member_documents,
    package_digest,
    disclaimer:
      input.disclaimer ??
      'Traceable conduct reconstruction package — Rule 707 / Art. 12 shaped; not legal advice.',
  };
}

export default {
  TRACEABLE_CONDUCT_PACKAGE_SCHEMA,
  TRACEABLE_CONDUCT_REQUIRED_MEMBER_SCHEMAS,
  buildTraceableConductPackageDocument,
  buildTraceableConductPackagePreimage,
  resolveMemberDocumentDigest,
  deriveTraceabilityReadiness,
};
