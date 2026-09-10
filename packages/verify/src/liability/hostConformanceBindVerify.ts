import { sha256HexUtf8 } from '../core/sha256.js';
import { stableStringify } from '../core/stableStringify.js';
import {
  buildHostConformanceBindPreimage,
  HOST_CONFORMANCE_BIND_SCHEMA,
  recomputeHostConformanceReportDigestFromBind,
  resolveHostMemberDocumentDigest,
  type ConformanceReadiness,
} from '../core/hostConformanceBind.js';
import { HOST_CONFORMANCE_ADAPTER_IDS } from '../core/hostConformanceAdapter.js';
import { AGT_CONDUCT_RECEIPT_SCHEMA } from '../core/agtConductReceipt.js';
import { INDEPENDENT_GUARDIAN_BUNDLE_SCHEMA } from '../core/independentGuardianBundle.js';
import { verifyAgtConductReceipt } from './agtConductReceiptVerify.js';
import {
  verifyIndependentGuardianBundle,
  type IndependentGuardianMemberVerifyContext,
} from './independentGuardianBundleVerify.js';

export const HOST_CONFORMANCE_BIND_SKU = 'aevesa-host-conformance-bind-v1' as const;

const HEX64 = /^[a-f0-9]{64}$/;
const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|ssn|phone|address|pan|cvv)$/i;

export interface HostConformanceBindVerifyOptions {
  requireHooksConformanceReady?: boolean;
  /** Override embedded member_verify_contexts on the bind document. */
  memberVerifyContexts?: Record<string, IndependentGuardianMemberVerifyContext>;
}

export interface HostConformanceBindVerifyResult {
  schema: typeof HOST_CONFORMANCE_BIND_SCHEMA;
  sku: typeof HOST_CONFORMANCE_BIND_SKU;
  ok: boolean;
  checks: Record<string, boolean>;
  conformance_readiness: ConformanceReadiness | null;
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

function memberDocumentForSchema(
  docs: Record<string, unknown>,
  schema: string,
): Record<string, unknown> | null {
  if (schema === AGT_CONDUCT_RECEIPT_SCHEMA) {
    return asRecord(docs.agt_conduct_receipt);
  }
  if (schema === INDEPENDENT_GUARDIAN_BUNDLE_SCHEMA) {
    return asRecord(docs.independent_guardian_bundle);
  }
  return null;
}

function verifyEmbeddedMember(
  schema: string,
  doc: unknown,
  memberVerifyContexts?: Record<string, IndependentGuardianMemberVerifyContext>,
): boolean {
  if (schema === AGT_CONDUCT_RECEIPT_SCHEMA) {
    return verifyAgtConductReceipt(doc).ok === true;
  }
  if (schema === INDEPENDENT_GUARDIAN_BUNDLE_SCHEMA) {
    return verifyIndependentGuardianBundle(doc, {
      memberContexts: memberVerifyContexts,
      requireDualProfile: false,
      requireCustodianWitness: false,
    }).ok === true;
  }
  return false;
}

export function verifyHostConformanceBind(
  docInput: unknown,
  options: HostConformanceBindVerifyOptions = {},
): HostConformanceBindVerifyResult {
  const doc = asRecord(docInput);
  const schemaValid = doc?.schema === HOST_CONFORMANCE_BIND_SCHEMA;
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;
  const sessionIdPresent = String(doc?.session_id || '').trim().length > 0;
  const hostAdapterValid = HOST_CONFORMANCE_ADAPTER_IDS.includes(
    String(doc?.host_adapter_id || '') as (typeof HOST_CONFORMANCE_ADAPTER_IDS)[number],
  );
  const reportIdPresent = String(doc?.report_id || '').trim().length > 0;
  const evaluatedAtPresent = String(doc?.evaluated_at || '').trim().length > 0;
  const generatedAtPresent = String(doc?.generated_at || '').trim().length > 0;

  const reportDigestValid = HEX64.test(String(doc?.report_digest || '').toLowerCase());
  const bindDigestValid = HEX64.test(String(doc?.bind_digest || '').toLowerCase());
  const hostVersionDigestValid = HEX64.test(String(doc?.host_version_digest || '').toLowerCase());
  const enforcementDigestValid = HEX64.test(
    String(doc?.enforcement_profile_digest || '').toLowerCase(),
  );

  const memberDocs = asRecord(doc?.member_documents) || {};
  const members = Array.isArray(doc?.composed_members) ? doc.composed_members : [];
  const embeddedMemberContexts =
    options.memberVerifyContexts
    ?? (asRecord(doc?.member_verify_contexts) as
      | Record<string, IndependentGuardianMemberVerifyContext>
      | undefined);

  const member_results: Record<string, boolean> = {};
  let agtPresent = false;
  let agtVerifyOk = false;
  let guardianPresent = false;
  let guardianVerifyOk = false;

  for (const schema of [AGT_CONDUCT_RECEIPT_SCHEMA, INDEPENDENT_GUARDIAN_BUNDLE_SCHEMA]) {
    const embedded = memberDocumentForSchema(memberDocs, schema);
    const present = embedded != null;
    member_results[`${schema}_present`] = present;
    if (schema === AGT_CONDUCT_RECEIPT_SCHEMA) agtPresent = present;
    if (schema === INDEPENDENT_GUARDIAN_BUNDLE_SCHEMA) guardianPresent = present;
    if (!present) {
      member_results[`${schema}_verify_ok`] = false;
      continue;
    }
    const verifyOk = verifyEmbeddedMember(schema, embedded, embeddedMemberContexts);
    member_results[`${schema}_verify_ok`] = verifyOk;
    if (schema === AGT_CONDUCT_RECEIPT_SCHEMA) agtVerifyOk = verifyOk;
    if (schema === INDEPENDENT_GUARDIAN_BUNDLE_SCHEMA) guardianVerifyOk = verifyOk;
  }

  let composedMembersMatchDocuments = true;
  for (const ref of members) {
    const schema = String(ref?.member_schema || '');
    const embedded = memberDocumentForSchema(memberDocs, schema);
    const expected = resolveHostMemberDocumentDigest(schema, embedded);
    if (
      expected != null
      && String(ref?.member_digest || '').toLowerCase() !== String(expected).toLowerCase()
    ) {
      composedMembersMatchDocuments = false;
    }
    if (
      ref?.verify_ok === true
      && embedded != null
      && !verifyEmbeddedMember(schema, embedded, embeddedMemberContexts)
    ) {
      composedMembersMatchDocuments = false;
    }
  }

  const recomputedReportDigest = doc
    ? recomputeHostConformanceReportDigestFromBind({
        host_adapter_id: String(doc.host_adapter_id) as never,
        report_id: String(doc.report_id),
        evaluated_at: String(doc.evaluated_at),
        host_version_digest: String(doc.host_version_digest),
        scenario_count: Number(doc.scenario_count) || 0,
        scenarios_passed: Number(doc.scenarios_passed) || 0,
        scenarios_failed: Number(doc.scenarios_failed) || 0,
        enforcement_profile_digest: String(doc.enforcement_profile_digest),
      })
    : '';

  const reportDigestMatches =
    reportDigestValid
    && recomputedReportDigest === String(doc?.report_digest || '').toLowerCase();

  const binding = asRecord(doc?.host_session_binding) || {};
  const normalizationBound = binding.normalization_bound === true;
  const bindingReportDigestValid = HEX64.test(String(binding.report_digest || '').toLowerCase());

  const bindingMatchesReport =
    bindingReportDigestValid
    && String(binding.report_digest || '').toLowerCase()
      === String(doc?.report_digest || '').toLowerCase();

  const agtDigest = resolveHostMemberDocumentDigest(
    AGT_CONDUCT_RECEIPT_SCHEMA,
    memberDocumentForSchema(memberDocs, AGT_CONDUCT_RECEIPT_SCHEMA),
  );
  const guardianDigest = resolveHostMemberDocumentDigest(
    INDEPENDENT_GUARDIAN_BUNDLE_SCHEMA,
    memberDocumentForSchema(memberDocs, INDEPENDENT_GUARDIAN_BUNDLE_SCHEMA),
  );

  const agtBindingOk =
    (agtDigest == null && binding.agt_receipt_digest == null)
    || String(binding.agt_receipt_digest || '').toLowerCase() === String(agtDigest || '').toLowerCase();
  const guardianBindingOk =
    (guardianDigest == null && binding.guardian_bundle_digest == null)
    || String(binding.guardian_bundle_digest || '').toLowerCase()
      === String(guardianDigest || '').toLowerCase();
  const bindingMatchesMembers = agtBindingOk && guardianBindingOk;

  const scenarioCount = Number(doc?.scenario_count) || 0;
  const scenariosPassed = Number(doc?.scenarios_passed) || 0;
  const scenariosFailed = Number(doc?.scenarios_failed) || 0;
  const allScenariosPassed =
    scenarioCount > 0 && scenariosFailed === 0 && scenariosPassed === scenarioCount;

  const assertions = asRecord(doc?.conformance_assertions) || {};
  const derivedReadiness = String(
    assertions.conformance_readiness || '',
  ) as ConformanceReadiness;

  let conformanceAssertionsConsistent =
    assertions.third_party_verifiable === true && sessionIdPresent;

  if (derivedReadiness === 'hooks_conformance_ready') {
    conformanceAssertionsConsistent =
      conformanceAssertionsConsistent
      && assertions.all_scenarios_passed === true
      && assertions.agt_conduct_linked === true
      && assertions.guardian_linked === true
      && allScenariosPassed
      && agtPresent
      && agtVerifyOk
      && guardianPresent
      && guardianVerifyOk
      && normalizationBound;
  } else if (derivedReadiness === 'partial') {
    conformanceAssertionsConsistent =
      conformanceAssertionsConsistent
      && agtPresent
      && agtVerifyOk
      && normalizationBound;
  }

  const readinessConsistent = assertions.conformance_readiness === derivedReadiness;

  let bindDigestMatches = false;
  if (schemaValid && doc && bindingReportDigestValid) {
    const preimage = buildHostConformanceBindPreimage({
      organization_id: String(doc.organization_id),
      session_id: String(doc.session_id),
      generated_at: String(doc.generated_at || ''),
      host_adapter_id: String(doc.host_adapter_id) as never,
      report_id: String(doc.report_id),
      report_digest: String(doc.report_digest),
      evaluated_at: String(doc.evaluated_at),
      host_version_digest: String(doc.host_version_digest),
      scenario_count: scenarioCount,
      scenarios_passed: scenariosPassed,
      scenarios_failed: scenariosFailed,
      enforcement_profile_digest: String(doc.enforcement_profile_digest),
      composed_members: members.map((m) => ({
        member_schema: String(m?.member_schema || ''),
        member_digest: String(m?.member_digest || ''),
        verify_ok: m?.verify_ok === true,
        label: String(m?.label || ''),
        sequence_index: Number(m?.sequence_index) || 0,
      })),
      host_session_binding: {
        session_id: String(binding.session_id || ''),
        report_digest: String(binding.report_digest || ''),
        agt_receipt_digest:
          binding.agt_receipt_digest != null ? String(binding.agt_receipt_digest) : null,
        guardian_bundle_digest:
          binding.guardian_bundle_digest != null
            ? String(binding.guardian_bundle_digest)
            : null,
        normalization_bound: normalizationBound,
      },
      conformance_assertions: {
        third_party_verifiable: assertions.third_party_verifiable === true,
        all_scenarios_passed: assertions.all_scenarios_passed === true,
        agt_conduct_linked: assertions.agt_conduct_linked === true,
        guardian_linked: assertions.guardian_linked === true,
        conformance_readiness: derivedReadiness,
      },
    });
    bindDigestMatches =
      sha256HexUtf8(stableStringify(preimage)) === String(doc.bind_digest || '').toLowerCase();
  }

  const hashOnlySurface =
    doc != null
    && !hasForbiddenKeys({
      ...doc,
      member_documents: undefined,
      member_verify_contexts: undefined,
    });
  const requireReady = options.requireHooksConformanceReady === true;

  const profileComplete =
    schemaValid
    && organizationIdPresent
    && sessionIdPresent
    && hostAdapterValid
    && reportIdPresent
    && evaluatedAtPresent
    && generatedAtPresent
    && reportDigestMatches
    && bindDigestMatches
    && agtPresent
    && agtVerifyOk
    && guardianPresent
    && guardianVerifyOk
    && composedMembersMatchDocuments
    && bindingMatchesReport
    && bindingMatchesMembers
    && normalizationBound
    && hashOnlySurface
    && conformanceAssertionsConsistent
    && readinessConsistent
    && enforcementDigestValid
    && hostVersionDigestValid
    && derivedReadiness === 'hooks_conformance_ready'
    && (!requireReady || derivedReadiness === 'hooks_conformance_ready');

  const ok = profileComplete;

  let note: string | null = null;
  if (!agtPresent) {
    note = 'missing required agt_conduct_receipt member — fails closed';
  } else if (!agtVerifyOk) {
    note = 'agt_conduct_receipt verification failed';
  } else if (!guardianPresent) {
    note = 'missing independent_guardian_bundle member — fails closed';
  } else if (!guardianVerifyOk) {
    note = 'independent_guardian_bundle verification failed';
  } else if (!reportDigestMatches) {
    note = 'report_digest does not match canonical envelope';
  } else if (!bindDigestMatches) {
    note = 'bind_digest does not match preimage';
  } else if (!bindingMatchesMembers) {
    note = 'host_session_binding inconsistent with member digests';
  } else if (!conformanceAssertionsConsistent) {
    note = 'conformance_assertions inconsistent with derived checks';
  }

  return {
    schema: HOST_CONFORMANCE_BIND_SCHEMA,
    sku: HOST_CONFORMANCE_BIND_SKU,
    ok,
    checks: {
      schemaValid: schemaValid === true,
      organizationIdPresent: organizationIdPresent === true,
      sessionIdPresent: sessionIdPresent === true,
      reportDigestMatches: reportDigestMatches === true,
      bindDigestMatches: bindDigestMatches === true,
      agtConductPresent: agtPresent === true,
      agtConductVerifyOk: agtVerifyOk === true,
      guardianPresent: guardianPresent === true,
      guardianVerifyOk: guardianVerifyOk === true,
      composedMembersMatchDocuments: composedMembersMatchDocuments === true,
      bindingMatchesReport: bindingMatchesReport === true,
      bindingMatchesMembers: bindingMatchesMembers === true,
      normalizationBound: normalizationBound === true,
      hashOnlySurface: hashOnlySurface === true,
      conformanceAssertionsConsistent: conformanceAssertionsConsistent === true,
      readinessConsistent: readinessConsistent === true,
      profileComplete: profileComplete === true,
    },
    conformance_readiness: derivedReadiness || null,
    profileComplete,
    member_results,
    gtmLine:
      'Hooks enforces on every path. Aevesa proves a third party can verify that — without your admin login.',
    note,
  };
}

export default { verifyHostConformanceBind, HOST_CONFORMANCE_BIND_SKU };
