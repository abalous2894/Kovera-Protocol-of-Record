import {
  deriveTimelineReadiness,
} from '../core/incidentNotificationTimeline.js';
import { sha256HexUtf8 } from '../core/sha256.js';
import { INCIDENT_NOTIFICATION_TIMELINE_PACK_SCHEMA, buildIncidentNotificationTimelinePackPreimage } from '../core/incidentNotificationTimelinePack.js';
import { stableStringify } from '../core/stableStringify.js';
import type { TimelineCompliance } from '../core/incidentNotificationTimeline.js';
import type { IncidentNotificationMilestone } from '../core/incidentNotificationTimeline.js';

export const INCIDENT_NOTIFICATION_TIMELINE_PACK_SKU =
  'aevesa-incident-notification-timeline-pack-v1' as const;

const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|ssn|phone|address|pan|cvv)$/i;
const HEX64 = /^[a-f0-9]{64}$/;

export interface IncidentNotificationTimelinePackVerifyResult {
  schema: typeof INCIDENT_NOTIFICATION_TIMELINE_PACK_SCHEMA;
  sku: typeof INCIDENT_NOTIFICATION_TIMELINE_PACK_SKU;
  ok: boolean;
  checks: Record<string, boolean>;
  timeline_readiness: TimelineCompliance | null;
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

export function verifyIncidentNotificationTimelinePack(
  docInput: unknown,
): IncidentNotificationTimelinePackVerifyResult {
  const doc = asRecord(docInput);
  const schemaValid = doc?.schema === INCIDENT_NOTIFICATION_TIMELINE_PACK_SCHEMA;
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;
  const incidentIdPresent = String(doc?.incident_id || '').trim().length > 0;

  const members = Array.isArray(doc?.composed_members) ? doc.composed_members : [];
  const composedMembersPresent = members.length >= 2;
  const memberDigestsValid =
    members.length === 0 ||
    members.every((m) => HEX64.test(String(m?.member_digest || '').toLowerCase()));

  const timelineMember = members.find(
    (m) => m?.member_schema === 'aevesa.incident-notification-timeline/v1',
  );
  const custodyMember = members.find((m) => m?.member_schema === 'kovera-incident-custody-pack/1');
  const conductMember = members.find(
    (m) => m?.member_schema === 'aevesa.traceable-conduct-manifest/v1',
  );

  const binding = asRecord(doc?.timeline_session_binding) || {};
  const normalizationBound = binding.normalization_bound === true;
  const bindingDigestsValid =
    HEX64.test(String(binding.timeline_digest || '').toLowerCase()) &&
    HEX64.test(String(binding.custody_manifest_digest || '').toLowerCase()) &&
    HEX64.test(String(binding.conduct_manifest_digest || '').toLowerCase());

  const bindingMatchesMembers =
    (!timelineMember ||
      String(binding.timeline_digest || '').toLowerCase() ===
        String(timelineMember.member_digest || '').toLowerCase()) &&
    (!custodyMember ||
      String(binding.custody_manifest_digest || '').toLowerCase() ===
        String(custodyMember.member_digest || '').toLowerCase()) &&
    (!conductMember ||
      String(binding.conduct_manifest_digest || '').toLowerCase() ===
        String(conductMember.member_digest || '').toLowerCase()) &&
    String(binding.incident_id || '') === String(doc?.incident_id || '');

  const notificationTimeline = asRecord(doc?.notification_timeline) || {};
  const milestonesDigestValid =
    HEX64.test(String(notificationTimeline.milestones_digest || '').toLowerCase()) &&
    String(binding.timeline_digest || '').toLowerCase() ===
      String(notificationTimeline.timeline_digest || '').toLowerCase();

  const assertions = asRecord(doc?.timeline_assertions) || {};
  const compliance = {
    nca_deadline_met: assertions.nca_deadline_met === true,
    milestones_chronological: assertions.milestones_chronological === true,
    nca_notification_at:
      assertions.nca_notification_at != null ? String(assertions.nca_notification_at) : null,
    hours_to_nca_notification:
      assertions.hours_to_nca_notification != null
        ? Number(assertions.hours_to_nca_notification)
        : null,
  };

  const derivedReadiness = deriveTimelineReadiness(
    compliance,
    custodyMember?.verify_ok === true,
  );

  const timelineOk = timelineMember?.verify_ok === true;
  const custodyOk = custodyMember?.verify_ok === true;
  const conductOk = conductMember?.verify_ok === true;

  let timelineAssertionsConsistent =
    assertions.third_party_verifiable === true && String(doc?.incident_id || '').trim().length > 0;

  if (derivedReadiness === 'nca_compliant') {
    timelineAssertionsConsistent =
      timelineAssertionsConsistent &&
      assertions.nca_deadline_met === true &&
      assertions.milestones_chronological === true &&
      assertions.custody_evidence_bound === true &&
      timelineOk &&
      custodyOk &&
      normalizationBound &&
      bindingMatchesMembers;
  } else if (derivedReadiness === 'deadline_missed') {
    timelineAssertionsConsistent =
      timelineAssertionsConsistent &&
      assertions.nca_deadline_met === false &&
      timelineOk &&
      bindingMatchesMembers;
  } else {
    timelineAssertionsConsistent =
      timelineAssertionsConsistent && (timelineOk || custodyOk) && bindingMatchesMembers;
  }

  const readinessConsistent = assertions.timeline_readiness === derivedReadiness;

  let packDigestMatches = false;
  if (schemaValid && doc && bindingDigestsValid && bindingMatchesMembers) {
    const preimage = buildIncidentNotificationTimelinePackPreimage({
      organization_id: String(doc.organization_id),
      incident_id: String(doc.incident_id),
      generated_at: String(doc.generated_at || ''),
      timeline_assertions: {
        nca_deadline_met: assertions.nca_deadline_met === true,
        milestones_chronological: assertions.milestones_chronological === true,
        custody_evidence_bound: assertions.custody_evidence_bound === true,
        third_party_verifiable: assertions.third_party_verifiable === true,
        timeline_readiness: String(assertions.timeline_readiness || derivedReadiness) as TimelineCompliance,
        nca_notification_at: compliance.nca_notification_at,
        hours_to_nca_notification: compliance.hours_to_nca_notification,
      },
      notification_timeline: {
        timeline_digest: String(notificationTimeline.timeline_digest || ''),
        serious_incident_awareness_at: String(notificationTimeline.serious_incident_awareness_at || ''),
        nca_notification_deadline_at: String(notificationTimeline.nca_notification_deadline_at || ''),
        milestone_count: Number(notificationTimeline.milestone_count) || 0,
        milestones_digest: String(notificationTimeline.milestones_digest || ''),
      },
      composed_members: members.map((m) => ({
        member_schema: String(m?.member_schema || ''),
        member_digest: String(m?.member_digest || ''),
        verify_ok: m?.verify_ok === true,
        label: String(m?.label || ''),
        entry_count: m?.entry_count ?? null,
      })),
      timeline_session_binding: {
        incident_id: String(binding.incident_id || ''),
        timeline_digest: String(binding.timeline_digest || ''),
        custody_manifest_digest: String(binding.custody_manifest_digest || ''),
        conduct_manifest_digest: String(binding.conduct_manifest_digest || ''),
        normalization_bound: normalizationBound,
      },
    });
    const expected = sha256HexUtf8(stableStringify(preimage));
    packDigestMatches = String(doc.pack_digest || '').toLowerCase() === expected;
  }

  const hashOnlySurface = !hasForbiddenKeys(doc);

  const profileComplete =
    schemaValid &&
    organizationIdPresent &&
    incidentIdPresent &&
    composedMembersPresent &&
    memberDigestsValid &&
    bindingDigestsValid &&
    bindingMatchesMembers &&
    milestonesDigestValid &&
    timelineAssertionsConsistent &&
    packDigestMatches &&
    hashOnlySurface &&
    readinessConsistent;

  let note: string | null = null;
  if (!schemaValid) note = `schema must be ${INCIDENT_NOTIFICATION_TIMELINE_PACK_SCHEMA}`;
  else if (!bindingMatchesMembers) note = 'timeline_session_binding digests must match composed members';
  else if (!packDigestMatches) note = 'pack_digest does not match canonical preimage';
  else if (!timelineAssertionsConsistent) note = 'timeline_assertions inconsistent with members or binding';
  else if (!readinessConsistent) note = 'timeline_readiness inconsistent with NCA deadline state';

  return {
    schema: INCIDENT_NOTIFICATION_TIMELINE_PACK_SCHEMA,
    sku: INCIDENT_NOTIFICATION_TIMELINE_PACK_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      organizationIdPresent,
      incidentIdPresent,
      composedMembersPresent,
      memberDigestsValid,
      bindingDigestsValid,
      bindingMatchesMembers,
      milestonesDigestValid,
      timelineAssertionsConsistent,
      packDigestMatches,
      hashOnlySurface,
      readinessConsistent,
      profileComplete,
      conductMemberPresent: Boolean(conductMember),
      conductMemberVerified: conductOk,
    },
    timeline_readiness: derivedReadiness,
    gtmLine:
      'Art. 73 requires NCA notification within 15 days. Aevesa proves milestone timestamps bound to custody evidence — offline.',
    note,
  };
}
