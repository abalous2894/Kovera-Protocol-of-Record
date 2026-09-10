import { sha256HexUtf8 } from './sha256.js';
import { stableStringify } from './stableStringify.js';
import {
  buildHostConformanceReportDigest,
  type HostConformanceAdapterId,
  type HostConformanceReportEnvelope,
} from './hostConformanceAdapter.js';
import { AGT_CONDUCT_RECEIPT_SCHEMA } from './agtConductReceipt.js';
import { INDEPENDENT_GUARDIAN_BUNDLE_SCHEMA } from './independentGuardianBundle.js';

/** Wave 14 Track E — host conformance bind (GAP-12). */

export const HOST_CONFORMANCE_BIND_SCHEMA = 'aevesa.host-conformance-bind/v1' as const;

export type ConformanceReadiness = 'hooks_conformance_ready' | 'partial' | 'unverified';

export interface HostConformanceComposedMemberRef {
  member_schema: string;
  member_digest: string;
  verify_ok: boolean;
  label: string;
  sequence_index: number;
}

export interface ConformanceAssertionsInput {
  third_party_verifiable: boolean;
}

export interface HostSessionBinding {
  session_id: string;
  report_digest: string;
  agt_receipt_digest: string | null;
  guardian_bundle_digest: string | null;
  normalization_bound: boolean;
}

export interface HostConformanceMemberDocuments {
  agt_conduct_receipt: Record<string, unknown>;
  independent_guardian_bundle?: Record<string, unknown> | null;
}

export interface HostConformanceBindInput {
  organization_id: string;
  session_id: string;
  generated_at?: string;
  host_adapter_id: HostConformanceAdapterId;
  report_id: string;
  report_digest: string;
  evaluated_at: string;
  host_version_digest: string;
  scenario_count: number;
  scenarios_passed: number;
  scenarios_failed: number;
  enforcement_profile_digest: string;
  member_documents: HostConformanceMemberDocuments;
  composed_members: HostConformanceComposedMemberRef[];
  host_session_binding: HostSessionBinding;
  conformance_assertions: ConformanceAssertionsInput;
  /** Optional prove-bundle contexts for embedded guardian members (excluded from bind_digest). */
  member_verify_contexts?: Record<string, Record<string, unknown>>;
  disclaimer?: string;
}

export function deriveConformanceReadiness(
  allScenariosPassed: boolean,
  agtConductLinked: boolean,
  agtConductVerifyOk: boolean,
  guardianLinked: boolean,
  guardianVerifyOk: boolean,
  thirdPartyVerifiable: boolean,
  normalizationBound: boolean,
): ConformanceReadiness {
  if (
    allScenariosPassed
    && agtConductLinked
    && agtConductVerifyOk
    && guardianLinked
    && guardianVerifyOk
    && thirdPartyVerifiable
    && normalizationBound
  ) {
    return 'hooks_conformance_ready';
  }
  if (agtConductLinked && agtConductVerifyOk && normalizationBound) {
    return 'partial';
  }
  return 'unverified';
}

export function buildConformanceAssertionsBlock(
  input: ConformanceAssertionsInput,
  allScenariosPassed: boolean,
  agtConductLinked: boolean,
  agtConductVerifyOk: boolean,
  guardianLinked: boolean,
  guardianVerifyOk: boolean,
  normalizationBound: boolean,
) {
  const conformance_readiness = deriveConformanceReadiness(
    allScenariosPassed,
    agtConductLinked,
    agtConductVerifyOk,
    guardianLinked,
    guardianVerifyOk,
    input.third_party_verifiable === true,
    normalizationBound,
  );

  return {
    third_party_verifiable: input.third_party_verifiable === true,
    all_scenarios_passed: allScenariosPassed,
    agt_conduct_linked: agtConductLinked && agtConductVerifyOk,
    guardian_linked: guardianLinked && guardianVerifyOk,
    conformance_readiness,
  };
}

export function resolveHostMemberDocumentDigest(
  memberSchema: string,
  doc: Record<string, unknown> | null | undefined,
): string | null {
  if (!doc || typeof doc !== 'object') return null;
  if (memberSchema === AGT_CONDUCT_RECEIPT_SCHEMA) {
    return typeof doc.receipt_digest === 'string' ? doc.receipt_digest : null;
  }
  if (memberSchema === INDEPENDENT_GUARDIAN_BUNDLE_SCHEMA) {
    return typeof doc.bundle_digest === 'string' ? doc.bundle_digest : null;
  }
  return null;
}

export function buildHostConformanceBindPreimage(
  input: Omit<HostConformanceBindInput, 'disclaimer' | 'conformance_assertions' | 'member_documents'> & {
    generated_at: string;
    conformance_assertions: ReturnType<typeof buildConformanceAssertionsBlock>;
  },
): Record<string, unknown> {
  const composed_members = [...input.composed_members]
    .map((m) => ({
      member_schema: String(m.member_schema || '').trim(),
      member_digest: String(m.member_digest || '').trim().toLowerCase(),
      verify_ok: m.verify_ok === true,
      label: String(m.label || '').trim(),
      sequence_index: Number(m.sequence_index) || 0,
    }))
    .sort((a, b) => a.sequence_index - b.sequence_index);

  const binding = input.host_session_binding;

  return {
    schema: HOST_CONFORMANCE_BIND_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    session_id: String(input.session_id || '').trim(),
    generated_at: input.generated_at,
    host_adapter_id: input.host_adapter_id,
    report_id: String(input.report_id || '').trim(),
    report_digest: String(input.report_digest || '').trim().toLowerCase(),
    evaluated_at: String(input.evaluated_at || '').trim(),
    host_version_digest: String(input.host_version_digest || '').trim().toLowerCase(),
    scenario_count: Number(input.scenario_count) || 0,
    scenarios_passed: Number(input.scenarios_passed) || 0,
    scenarios_failed: Number(input.scenarios_failed) || 0,
    enforcement_profile_digest: String(input.enforcement_profile_digest || '')
      .trim()
      .toLowerCase(),
    composed_members,
    host_session_binding: {
      session_id: String(binding.session_id || '').trim(),
      report_digest: String(binding.report_digest || '').trim().toLowerCase(),
      agt_receipt_digest: binding.agt_receipt_digest
        ? String(binding.agt_receipt_digest).trim().toLowerCase()
        : null,
      guardian_bundle_digest: binding.guardian_bundle_digest
        ? String(binding.guardian_bundle_digest).trim().toLowerCase()
        : null,
      normalization_bound: binding.normalization_bound === true,
    },
    conformance_assertions: input.conformance_assertions,
  };
}

export interface HostConformanceBindDocument {
  schema: typeof HOST_CONFORMANCE_BIND_SCHEMA;
  organization_id: string;
  session_id: string;
  generated_at: string;
  host_adapter_id: HostConformanceAdapterId;
  report_id: string;
  report_digest: string;
  evaluated_at: string;
  host_version_digest: string;
  scenario_count: number;
  scenarios_passed: number;
  scenarios_failed: number;
  enforcement_profile_digest: string;
  member_documents: HostConformanceMemberDocuments;
  composed_members: HostConformanceComposedMemberRef[];
  host_session_binding: HostSessionBinding;
  conformance_assertions: ReturnType<typeof buildConformanceAssertionsBlock>;
  bind_digest: string;
  disclaimer: string;
  member_verify_contexts?: Record<string, Record<string, unknown>>;
}

export function buildHostConformanceBindDocument(
  input: HostConformanceBindInput,
): HostConformanceBindDocument {
  const generated_at = input.generated_at || new Date().toISOString();
  const docs = input.member_documents;

  const agtDoc = docs.agt_conduct_receipt;
  const guardianDoc = docs.independent_guardian_bundle ?? null;

  const agtDigest = resolveHostMemberDocumentDigest(AGT_CONDUCT_RECEIPT_SCHEMA, agtDoc);
  const guardianDigest = resolveHostMemberDocumentDigest(
    INDEPENDENT_GUARDIAN_BUNDLE_SCHEMA,
    guardianDoc,
  );

  const agtMember = input.composed_members.find((m) => m.member_schema === AGT_CONDUCT_RECEIPT_SCHEMA);
  const guardianMember = input.composed_members.find(
    (m) => m.member_schema === INDEPENDENT_GUARDIAN_BUNDLE_SCHEMA,
  );

  const agtConductLinked = agtDoc != null && agtDigest != null;
  const agtConductVerifyOk = agtMember?.verify_ok === true;
  const guardianLinked = guardianDoc != null && guardianDigest != null;
  const guardianVerifyOk = guardianMember?.verify_ok === true;

  const allScenariosPassed =
    Number(input.scenarios_failed) === 0
    && Number(input.scenarios_passed) === Number(input.scenario_count)
    && Number(input.scenario_count) > 0;

  const conformance_assertions = buildConformanceAssertionsBlock(
    input.conformance_assertions,
    allScenariosPassed,
    agtConductLinked,
    agtConductVerifyOk,
    guardianLinked,
    guardianVerifyOk,
    input.host_session_binding.normalization_bound === true,
  );

  const { member_documents: _docs, disclaimer: _disclaimer, conformance_assertions: _a, member_verify_contexts, ...fields } =
    input;

  const preimage = buildHostConformanceBindPreimage({
    ...fields,
    generated_at,
    conformance_assertions,
  });
  const bind_digest = sha256HexUtf8(stableStringify(preimage));

  const document: HostConformanceBindDocument = {
    ...(preimage as Omit<
      HostConformanceBindDocument,
      'member_documents' | 'bind_digest' | 'disclaimer' | 'member_verify_contexts'
    >),
    member_documents: input.member_documents,
    bind_digest,
    disclaimer:
      input.disclaimer ??
      'Host conformance bind — Agent Hooks / AGT enforcement report bound to conduct + guardian members; not legal advice.',
  };
  if (member_verify_contexts && Object.keys(member_verify_contexts).length > 0) {
    document.member_verify_contexts = member_verify_contexts;
  }
  return document;
}

export function buildHostConformanceBindFromReport(
  envelope: HostConformanceReportEnvelope,
  input: {
    organization_id: string;
    session_id: string;
    generated_at?: string;
    member_documents: HostConformanceMemberDocuments;
    composed_members: HostConformanceComposedMemberRef[];
    conformance_assertions?: ConformanceAssertionsInput;
    member_verify_contexts?: Record<string, Record<string, unknown>>;
    disclaimer?: string;
  },
): HostConformanceBindDocument {
  const report_digest = buildHostConformanceReportDigest(envelope);
  const generated_at = input.generated_at || new Date().toISOString();

  const agtDigest = resolveHostMemberDocumentDigest(
    AGT_CONDUCT_RECEIPT_SCHEMA,
    input.member_documents.agt_conduct_receipt,
  );
  const guardianDigest = resolveHostMemberDocumentDigest(
    INDEPENDENT_GUARDIAN_BUNDLE_SCHEMA,
    input.member_documents.independent_guardian_bundle,
  );

  const host_session_binding: HostSessionBinding = {
    session_id: String(input.session_id || '').trim(),
    report_digest,
    agt_receipt_digest: agtDigest,
    guardian_bundle_digest: guardianDigest,
    normalization_bound: true,
  };

  return buildHostConformanceBindDocument({
    organization_id: input.organization_id,
    session_id: input.session_id,
    generated_at,
    host_adapter_id: envelope.host_adapter_id,
    report_id: envelope.report_id,
    report_digest,
    evaluated_at: envelope.evaluated_at,
    host_version_digest: envelope.host_version_digest,
    scenario_count: envelope.scenario_count,
    scenarios_passed: envelope.scenarios_passed,
    scenarios_failed: envelope.scenarios_failed,
    enforcement_profile_digest: envelope.enforcement_profile_digest,
    member_documents: input.member_documents,
    composed_members: input.composed_members,
    host_session_binding,
    conformance_assertions: input.conformance_assertions ?? { third_party_verifiable: true },
    member_verify_contexts: input.member_verify_contexts,
    disclaimer: input.disclaimer,
  });
}

export function recomputeHostConformanceReportDigestFromBind(
  doc: Pick<
    HostConformanceBindInput,
    | 'host_adapter_id'
    | 'report_id'
    | 'evaluated_at'
    | 'host_version_digest'
    | 'scenario_count'
    | 'scenarios_passed'
    | 'scenarios_failed'
    | 'enforcement_profile_digest'
  >,
): string {
  return buildHostConformanceReportDigest({
    host_adapter_id: doc.host_adapter_id,
    report_id: doc.report_id,
    evaluated_at: doc.evaluated_at,
    host_version_digest: doc.host_version_digest,
    scenario_count: doc.scenario_count,
    scenarios_passed: doc.scenarios_passed,
    scenarios_failed: doc.scenarios_failed,
    enforcement_profile_digest: doc.enforcement_profile_digest,
  });
}

export default {
  HOST_CONFORMANCE_BIND_SCHEMA,
  buildHostConformanceBindDocument,
  buildHostConformanceBindFromReport,
  buildHostConformanceBindPreimage,
  buildConformanceAssertionsBlock,
  deriveConformanceReadiness,
  resolveHostMemberDocumentDigest,
  recomputeHostConformanceReportDigestFromBind,
};
