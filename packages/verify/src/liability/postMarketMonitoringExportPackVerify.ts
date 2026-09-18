import { sha256HexUtf8 } from '../core/sha256.js';
import { POST_MARKET_MONITORING_EXPORT_PACK_SCHEMA, buildPostMarketMonitoringExportPackPreimage } from '../core/postMarketMonitoringExportPack.js';
import { POST_MARKET_MONITORING_SNAPSHOT_SCHEMA } from '../core/postMarketMonitoringSnapshot.js';
import { AGENT_CENSUS_COMPLETENESS_PACK_SCHEMA } from '../core/agentCensusCompletenessPack.js';
import { TRACEABLE_CONDUCT_MANIFEST_SCHEMA } from '../core/traceableConductManifest.js';
import { stableStringify } from '../core/stableStringify.js';
import type { MonitoringReadiness } from '../core/postMarketMonitoringSnapshot.js';
import { verifyPostMarketMonitoringSnapshot } from './postMarketMonitoringSnapshotVerify.js';
import { verifyAgentCensusCompletenessPack } from './agentCensusCompletenessPackVerify.js';
import { verifyTraceableConductManifest } from './traceableConductManifestVerify.js';
import {
  extractComposedPackProofLayers,
  hashOnlyComposedPackSurface,
  pc09MemberProofNote,
  resolveComposedMemberVerifyState,
} from './composedPackMemberVerify.js';

export const POST_MARKET_MONITORING_EXPORT_PACK_SKU =
  'aevesa-post-market-monitoring-export-pack-v1' as const;

const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|ssn|phone|address|pan|cvv)$/i;
const HEX64 = /^[a-f0-9]{64}$/;

export interface PostMarketMonitoringExportPackVerifyResult {
  schema: typeof POST_MARKET_MONITORING_EXPORT_PACK_SCHEMA;
  sku: typeof POST_MARKET_MONITORING_EXPORT_PACK_SKU;
  ok: boolean;
  checks: Record<string, boolean>;
  monitoring_readiness: MonitoringReadiness | null;
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
  if (schema === POST_MARKET_MONITORING_SNAPSHOT_SCHEMA) {
    return memberDocs.post_market_monitoring_snapshot ?? memberDocs[schema] ?? null;
  }
  if (schema === AGENT_CENSUS_COMPLETENESS_PACK_SCHEMA) {
    return memberDocs.agent_census_completeness_pack ?? memberDocs[schema] ?? null;
  }
  if (schema === TRACEABLE_CONDUCT_MANIFEST_SCHEMA) {
    return memberDocs.conduct_manifest ?? memberDocs.traceable_conduct_manifest ?? memberDocs[schema] ?? null;
  }
  return memberDocs[schema] ?? null;
}

function recomputeMemberVerifyOk(schema: string, embedded: unknown): boolean {
  if (embedded == null) return false;
  if (schema === POST_MARKET_MONITORING_SNAPSHOT_SCHEMA) {
    return verifyPostMarketMonitoringSnapshot(embedded).ok === true;
  }
  if (schema === AGENT_CENSUS_COMPLETENESS_PACK_SCHEMA) {
    return verifyAgentCensusCompletenessPack(embedded).ok === true;
  }
  if (schema === TRACEABLE_CONDUCT_MANIFEST_SCHEMA) {
    return verifyTraceableConductManifest(embedded).ok === true;
  }
  return false;
}

export function verifyPostMarketMonitoringExportPack(
  docInput: unknown,
): PostMarketMonitoringExportPackVerifyResult {
  const doc = asRecord(docInput);
  const schemaValid = doc?.schema === POST_MARKET_MONITORING_EXPORT_PACK_SCHEMA;
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;
  const periodLabelPresent = String(doc?.period_label || '').trim().length > 0;

  const members = Array.isArray(doc?.composed_members) ? doc.composed_members : [];
  const composedMembersPresent = members.length >= 3;
  const memberDigestsValid =
    members.length === 0 ||
    members.every((m) => HEX64.test(String(m?.member_digest || '').toLowerCase()));

  const snapshotMember = members.find(
    (m) => m?.member_schema === 'aevesa.post-market-monitoring-snapshot/v1',
  );
  const censusMember = members.find(
    (m) => m?.member_schema === 'aevesa.agent-census-completeness-pack/v1',
  );
  const conductMember = members.find(
    (m) => m?.member_schema === 'aevesa.traceable-conduct-manifest/v1',
  );

  const binding = asRecord(doc?.monitoring_session_binding) || {};
  const normalizationBound = binding.normalization_bound === true;
  const bindingDigestsValid =
    HEX64.test(String(binding.snapshot_digest || '').toLowerCase()) &&
    HEX64.test(String(binding.census_pack_digest || '').toLowerCase()) &&
    HEX64.test(String(binding.conduct_manifest_digest || '').toLowerCase());

  const bindingMatchesMembers =
    (!snapshotMember ||
      String(binding.snapshot_digest || '').toLowerCase() ===
        String(snapshotMember.member_digest || '').toLowerCase()) &&
    (!censusMember ||
      String(binding.census_pack_digest || '').toLowerCase() ===
        String(censusMember.member_digest || '').toLowerCase()) &&
    (!conductMember ||
      String(binding.conduct_manifest_digest || '').toLowerCase() ===
        String(conductMember.member_digest || '').toLowerCase()) &&
    String(binding.period_label || '') === String(doc?.period_label || '');

  const snapshotSummary = asRecord(doc?.post_market_monitoring_snapshot) || {};
  const snapshotSummaryValid =
    HEX64.test(String(snapshotSummary.snapshot_digest || '').toLowerCase()) &&
    String(binding.snapshot_digest || '').toLowerCase() ===
      String(snapshotSummary.snapshot_digest || '').toLowerCase();

  const assertions = asRecord(doc?.monitoring_assertions) || {};
  const derivedReadiness = String(assertions.monitoring_readiness || '') as MonitoringReadiness;

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

  const snapshotOk =
    memberResolution.members.find((m) => m.member_schema === POST_MARKET_MONITORING_SNAPSHOT_SCHEMA)
      ?.verify_ok === true;
  const censusOk =
    memberResolution.members.find((m) => m.member_schema === AGENT_CENSUS_COMPLETENESS_PACK_SCHEMA)
      ?.verify_ok === true;
  const conductOk =
    memberResolution.members.find((m) => m.member_schema === TRACEABLE_CONDUCT_MANIFEST_SCHEMA)
      ?.verify_ok === true;

  const memberArtifactsBundled = memberResolution.memberArtifactsBundled;
  const memberAttestationsPresent = memberResolution.memberAttestationsPresent;
  const memberProofPresent = memberResolution.memberProofPresent;
  const selfAssertedVerifyIgnored = memberResolution.selfAssertedVerifyIgnored;
  const gapCount = Number(assertions.obligation_gap_count) || 0;

  let monitoringAssertionsConsistent =
    assertions.third_party_verifiable === true && periodLabelPresent;

  if (derivedReadiness === 'export_ready') {
    monitoringAssertionsConsistent =
      monitoringAssertionsConsistent &&
      assertions.period_complete === true &&
      assertions.conduct_evidence_bound === true &&
      assertions.census_inventory_bound === true &&
      assertions.iso42001_shape_valid === true &&
      snapshotOk &&
      censusOk &&
      conductOk &&
      gapCount === 0 &&
      normalizationBound &&
      bindingMatchesMembers;
  } else if (derivedReadiness === 'partial') {
    monitoringAssertionsConsistent =
      monitoringAssertionsConsistent &&
      snapshotOk &&
      (censusOk || conductOk) &&
      bindingMatchesMembers;
  }

  const readinessConsistent = assertions.monitoring_readiness === derivedReadiness;

  let packDigestMatches = false;
  if (schemaValid && doc && bindingDigestsValid && bindingMatchesMembers) {
    const preimage = buildPostMarketMonitoringExportPackPreimage({
      organization_id: String(doc.organization_id),
      period_label: String(doc.period_label),
      generated_at: String(doc.generated_at || ''),
      monitoring_assertions: {
        period_complete: assertions.period_complete === true,
        conduct_evidence_bound: assertions.conduct_evidence_bound === true,
        census_inventory_bound: assertions.census_inventory_bound === true,
        iso42001_shape_valid: assertions.iso42001_shape_valid === true,
        third_party_verifiable: assertions.third_party_verifiable === true,
        monitoring_readiness: derivedReadiness,
        obligation_gap_count: gapCount,
        obligation_partial_count: Number(assertions.obligation_partial_count) || 0,
      },
      post_market_monitoring_snapshot: {
        snapshot_digest: String(snapshotSummary.snapshot_digest || ''),
        period_start: String(snapshotSummary.period_start || ''),
        period_end: String(snapshotSummary.period_end || ''),
        obligation_count: Number(snapshotSummary.obligation_count) || 0,
        obligations_met_count: Number(snapshotSummary.obligations_met_count) || 0,
        obligations_partial_count: Number(snapshotSummary.obligations_partial_count) || 0,
      },
      composed_members: members.map((m) => ({
        member_schema: String(m?.member_schema || ''),
        member_digest: String(m?.member_digest || ''),
        verify_ok: m?.verify_ok === true,
        label: String(m?.label || ''),
        entry_count: m?.entry_count ?? null,
      })),
      monitoring_session_binding: {
        period_label: String(binding.period_label || ''),
        snapshot_digest: String(binding.snapshot_digest || ''),
        census_pack_digest: String(binding.census_pack_digest || ''),
        conduct_manifest_digest: String(binding.conduct_manifest_digest || ''),
        normalization_bound: normalizationBound,
      },
    });
    const expected = sha256HexUtf8(stableStringify(preimage));
    packDigestMatches = String(doc.pack_digest || '').toLowerCase() === expected;
  }

  const hashOnlySurface = hashOnlyComposedPackSurface(docInput, hasForbiddenKeys);

  const memberVerifyRecomputed = snapshotOk && censusOk && conductOk;

  const profileComplete =
    schemaValid &&
    organizationIdPresent &&
    periodLabelPresent &&
    composedMembersPresent &&
    memberDigestsValid &&
    bindingDigestsValid &&
    bindingMatchesMembers &&
    snapshotSummaryValid &&
    monitoringAssertionsConsistent &&
    packDigestMatches &&
    hashOnlySurface &&
    memberProofPresent &&
    memberVerifyRecomputed &&
    readinessConsistent;

  let note: string | null = null;
  if (!schemaValid) note = `schema must be ${POST_MARKET_MONITORING_EXPORT_PACK_SCHEMA}`;
  else if (!memberProofPresent || selfAssertedVerifyIgnored) {
    note = pc09MemberProofNote(memberResolution);
  } else if (!bindingMatchesMembers) note = 'monitoring_session_binding digests must match composed members';
  else if (!packDigestMatches) note = 'pack_digest does not match canonical preimage';
  else if (!monitoringAssertionsConsistent) note = 'monitoring_assertions inconsistent with members or binding';
  else if (!readinessConsistent) note = 'monitoring_readiness inconsistent with obligation state';

  return {
    schema: POST_MARKET_MONITORING_EXPORT_PACK_SCHEMA,
    sku: POST_MARKET_MONITORING_EXPORT_PACK_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      organizationIdPresent,
      periodLabelPresent,
      composedMembersPresent,
      memberDigestsValid,
      bindingDigestsValid,
      bindingMatchesMembers,
      snapshotSummaryValid,
      monitoringAssertionsConsistent,
      packDigestMatches,
      hashOnlySurface,
      memberArtifactsBundled,
      memberAttestationsPresent,
      memberProofPresent,
      memberVerifyRecomputed,
      readinessConsistent,
      profileComplete,
    },
    monitoring_readiness: derivedReadiness,
    gtmLine:
      'Art. 72 post-market monitoring needs an export shape auditors accept. Aevesa binds metrics to census + conduct — offline.',
    note,
  };
}
