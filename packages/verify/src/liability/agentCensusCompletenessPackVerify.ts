import { sha256HexUtf8 } from '../core/sha256.js';
import {
  AGENT_CENSUS_COMPLETENESS_PACK_SCHEMA,
  buildAgentCensusCompletenessPackPreimage,
  buildDeltaDigest,
  deriveCensusReadiness,
} from '../core/agentCensusCompletenessPack.js';
import { DECLARED_AGENT_ROSTER_SCHEMA } from '../core/declaredAgentRoster.js';
import { OBSERVED_AGENT_CONDUCT_SET_SCHEMA } from '../core/observedAgentConductSet.js';
import { TRACEABLE_CONDUCT_MANIFEST_SCHEMA } from '../core/traceableConductManifest.js';
import { stableStringify } from '../core/stableStringify.js';
import type { CensusReadiness } from '../core/agentCensusCompletenessPack.js';
import { verifyDeclaredAgentRoster } from './declaredAgentRosterVerify.js';
import { verifyObservedAgentConductSet } from './observedAgentConductSetVerify.js';
import { verifyTraceableConductManifest } from './traceableConductManifestVerify.js';
import {
  extractComposedPackProofLayers,
  hashOnlyComposedPackSurface,
  pc09MemberProofNote,
  resolveComposedMemberVerifyState,
} from './composedPackMemberVerify.js';

export const AGENT_CENSUS_COMPLETENESS_PACK_SKU = 'aevesa-agent-census-completeness-pack-v1' as const;

const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|ssn|phone|address|pan|cvv)$/i;
const HEX64 = /^[a-f0-9]{64}$/;

export interface AgentCensusCompletenessPackVerifyResult {
  schema: typeof AGENT_CENSUS_COMPLETENESS_PACK_SCHEMA;
  sku: typeof AGENT_CENSUS_COMPLETENESS_PACK_SKU;
  ok: boolean;
  checks: Record<string, boolean>;
  census_readiness: CensusReadiness | null;
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
  memberDocs: Record<string, unknown>,
  schema: string,
): unknown {
  if (schema === DECLARED_AGENT_ROSTER_SCHEMA) {
    return memberDocs.declared_agent_roster ?? memberDocs[schema] ?? null;
  }
  if (schema === OBSERVED_AGENT_CONDUCT_SET_SCHEMA) {
    return memberDocs.observed_agent_conduct_set ?? memberDocs[schema] ?? null;
  }
  if (schema === TRACEABLE_CONDUCT_MANIFEST_SCHEMA) {
    return memberDocs.conduct_manifest ?? memberDocs.traceable_conduct_manifest ?? memberDocs[schema] ?? null;
  }
  return memberDocs[schema] ?? null;
}

function recomputeMemberVerifyOk(schema: string, embedded: unknown): boolean {
  if (embedded == null) return false;
  if (schema === DECLARED_AGENT_ROSTER_SCHEMA) {
    return verifyDeclaredAgentRoster(embedded).ok === true;
  }
  if (schema === OBSERVED_AGENT_CONDUCT_SET_SCHEMA) {
    return verifyObservedAgentConductSet(embedded).ok === true;
  }
  if (schema === TRACEABLE_CONDUCT_MANIFEST_SCHEMA) {
    return verifyTraceableConductManifest(embedded).ok === true;
  }
  return false;
}

export function verifyAgentCensusCompletenessPack(
  docInput: unknown,
): AgentCensusCompletenessPackVerifyResult {
  const doc = asRecord(docInput);
  const schemaValid = doc?.schema === AGENT_CENSUS_COMPLETENESS_PACK_SCHEMA;
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;
  const periodLabelPresent = String(doc?.period_label || '').trim().length > 0;

  const members = Array.isArray(doc?.composed_members) ? doc.composed_members : [];
  const composedMembersPresent = members.length >= 2;
  const memberDigestsValid =
    members.length === 0 ||
    members.every((m) => HEX64.test(String(m?.member_digest || '').toLowerCase()));

  const binding = asRecord(doc?.census_session_binding) || {};
  const normalizationBound = binding.normalization_bound === true;
  const bindingDigestsValid =
    HEX64.test(String(binding.declared_roster_digest || '').toLowerCase()) &&
    HEX64.test(String(binding.observed_set_digest || '').toLowerCase()) &&
    HEX64.test(String(binding.delta_digest || '').toLowerCase());

  const rosterMember = members.find((m) => m?.member_schema === 'aevesa.declared-agent-roster/v1');
  const observedMember = members.find(
    (m) => m?.member_schema === 'aevesa.observed-agent-conduct-set/v1',
  );
  const conductMember = members.find(
    (m) => m?.member_schema === 'aevesa.traceable-conduct-manifest/v1',
  );

  const bindingMatchesMembers =
    (!rosterMember ||
      String(binding.declared_roster_digest || '').toLowerCase() ===
        String(rosterMember.member_digest || '').toLowerCase()) &&
    (!observedMember ||
      String(binding.observed_set_digest || '').toLowerCase() ===
        String(observedMember.member_digest || '').toLowerCase());

  const delta = asRecord(doc?.census_delta) || {};
  const deltaDigestValid =
    HEX64.test(String(delta.delta_digest || '').toLowerCase()) &&
    String(binding.delta_digest || '').toLowerCase() === String(delta.delta_digest || '').toLowerCase();

  const deltaCore = {
    shadow_agent_ids: Array.isArray(delta.shadow_agent_ids) ? delta.shadow_agent_ids.map(String) : [],
    dormant_roster_ids: Array.isArray(delta.dormant_roster_ids)
      ? delta.dormant_roster_ids.map(String)
      : [],
    matched_agent_ids: Array.isArray(delta.matched_agent_ids)
      ? delta.matched_agent_ids.map(String)
      : [],
    shadow_count: Number(delta.shadow_count) || 0,
    dormant_count: Number(delta.dormant_count) || 0,
    matched_count: Number(delta.matched_count) || 0,
  };

  const expectedDeltaDigest = buildDeltaDigest(deltaCore);
  const deltaDigestMatches =
    String(delta.delta_digest || '').toLowerCase() === expectedDeltaDigest.toLowerCase();

  const { memberDocs, memberAttestations } = extractComposedPackProofLayers(doc);
  const anyVerifyOkAsserted = members.some((m) => m?.verify_ok === true);

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

  const memberArtifactsBundled = memberResolution.memberArtifactsBundled;
  const memberAttestationsPresent = memberResolution.memberAttestationsPresent;
  const memberProofPresent = memberResolution.memberProofPresent;
  const memberVerifyRecomputed = memberResolution.memberVerifyRecomputed;
  const selfAssertedVerifyIgnored = memberResolution.selfAssertedVerifyIgnored;

  const derivedReadiness = deriveCensusReadiness(deltaCore, membersForReadiness);

  const assertions = asRecord(doc?.census_assertions) || {};
  const rosterOk = membersForReadiness.some(
    (m) => m.member_schema === DECLARED_AGENT_ROSTER_SCHEMA && m.verify_ok === true,
  );
  const observedOk = membersForReadiness.some(
    (m) => m.member_schema === OBSERVED_AGENT_CONDUCT_SET_SCHEMA && m.verify_ok === true,
  );
  const hasShadow = deltaCore.shadow_count > 0;

  let censusAssertionsConsistent =
    assertions.third_party_verifiable === true && String(binding.period_label || '').trim().length > 0;

  if (derivedReadiness === 'complete') {
    censusAssertionsConsistent =
      censusAssertionsConsistent &&
      assertions.roster_observed_delta_bound === true &&
      assertions.shadow_agents_detected === false &&
      !hasShadow &&
      rosterOk &&
      observedOk &&
      normalizationBound &&
      deltaDigestMatches;
  } else if (derivedReadiness === 'shadow_gap') {
    censusAssertionsConsistent =
      censusAssertionsConsistent &&
      assertions.roster_observed_delta_bound === true &&
      assertions.shadow_agents_detected === true &&
      hasShadow &&
      rosterOk &&
      observedOk &&
      normalizationBound &&
      deltaDigestMatches;
  } else if (derivedReadiness === 'partial') {
    censusAssertionsConsistent =
      censusAssertionsConsistent && (rosterOk || observedOk) && deltaDigestMatches;
  }

  const readinessConsistent = assertions.census_readiness === derivedReadiness;

  let packDigestMatches = false;
  if (schemaValid && doc && bindingDigestsValid && deltaDigestMatches) {
    const preimage = buildAgentCensusCompletenessPackPreimage({
      organization_id: String(doc.organization_id),
      period_label: String(doc.period_label),
      generated_at: String(doc.generated_at || ''),
      census_assertions: {
        roster_observed_delta_bound: assertions.roster_observed_delta_bound === true,
        shadow_agents_detected: assertions.shadow_agents_detected === true,
        third_party_verifiable: assertions.third_party_verifiable === true,
        census_readiness: String(assertions.census_readiness || derivedReadiness) as CensusReadiness,
        shadow_count: deltaCore.shadow_count,
        dormant_count: deltaCore.dormant_count,
        matched_count: deltaCore.matched_count,
      },
      census_delta: {
        shadow_agent_ids: deltaCore.shadow_agent_ids,
        dormant_roster_ids: deltaCore.dormant_roster_ids,
        matched_agent_ids: deltaCore.matched_agent_ids,
        shadow_count: deltaCore.shadow_count,
        dormant_count: deltaCore.dormant_count,
        matched_count: deltaCore.matched_count,
        delta_digest: expectedDeltaDigest,
      },
      composed_members: members.map((m) => ({
        member_schema: String(m?.member_schema || ''),
        member_digest: String(m?.member_digest || ''),
        verify_ok: m?.verify_ok === true,
        label: String(m?.label || ''),
        entry_count: m?.entry_count ?? null,
      })),
      census_session_binding: {
        period_label: String(binding.period_label || ''),
        declared_roster_digest: String(binding.declared_roster_digest || ''),
        observed_set_digest: String(binding.observed_set_digest || ''),
        delta_digest: expectedDeltaDigest,
        normalization_bound: normalizationBound,
      },
    });
    const expected = sha256HexUtf8(stableStringify(preimage));
    packDigestMatches = String(doc.pack_digest || '').toLowerCase() === expected;
  }

  const hashOnlySurface = hashOnlyComposedPackSurface(docInput, hasForbiddenKeys);

  const profileComplete =
    schemaValid &&
    organizationIdPresent &&
    periodLabelPresent &&
    composedMembersPresent &&
    memberDigestsValid &&
    bindingDigestsValid &&
    bindingMatchesMembers &&
    deltaDigestValid &&
    deltaDigestMatches &&
    censusAssertionsConsistent &&
    packDigestMatches &&
    hashOnlySurface &&
    (!anyVerifyOkAsserted || (memberProofPresent && memberVerifyRecomputed)) &&
    readinessConsistent;

  let note: string | null = null;
  if (!schemaValid) note = `schema must be ${AGENT_CENSUS_COMPLETENESS_PACK_SCHEMA}`;
  else if (anyVerifyOkAsserted && (!memberProofPresent || selfAssertedVerifyIgnored)) {
    note = pc09MemberProofNote(memberResolution);
  } else if (!bindingMatchesMembers) note = 'census_session_binding digests must match composed members';
  else if (!deltaDigestMatches) note = 'census_delta.delta_digest does not match shadow/dormant/matched sets';
  else if (!packDigestMatches) note = 'pack_digest does not match canonical preimage';
  else if (!censusAssertionsConsistent) note = 'census_assertions inconsistent with delta or members';
  else if (!readinessConsistent) note = 'census_readiness inconsistent with delta state';

  return {
    schema: AGENT_CENSUS_COMPLETENESS_PACK_SCHEMA,
    sku: AGENT_CENSUS_COMPLETENESS_PACK_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      organizationIdPresent,
      periodLabelPresent,
      composedMembersPresent,
      memberDigestsValid,
      bindingDigestsValid,
      bindingMatchesMembers,
      deltaDigestMatches,
      censusAssertionsConsistent,
      packDigestMatches,
      hashOnlySurface,
      memberArtifactsBundled,
      memberAttestationsPresent,
      memberProofPresent,
      memberVerifyRecomputed: !anyVerifyOkAsserted || memberVerifyRecomputed,
      readinessConsistent,
      profileComplete,
      conductMemberPresent: Boolean(conductMember),
    },
    census_readiness: derivedReadiness,
    gtmLine:
      '94% of security teams cannot enumerate their agents. Aevesa proves roster vs observed conduct delta — shadow agents verifiable offline.',
    note,
  };
}
