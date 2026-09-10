import { sha256HexUtf8 } from '../core/sha256.js';
import { INCIDENT_NOTIFICATION_TIMELINE_SCHEMA, buildIncidentNotificationTimelinePreimage, buildMilestonesDigest, computeNcaNotificationDeadline, evaluateTimelineCompliance } from '../core/incidentNotificationTimeline.js';
import { stableStringify } from '../core/stableStringify.js';
import type { IncidentNotificationMilestone } from '../core/incidentNotificationTimeline.js';

export const INCIDENT_NOTIFICATION_TIMELINE_SKU =
  'aevesa-incident-notification-timeline-v1' as const;

const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|ssn|phone|address|pan|cvv)$/i;
const HEX64 = /^[a-f0-9]{64}$/;

export interface IncidentNotificationTimelineVerifyResult {
  schema: typeof INCIDENT_NOTIFICATION_TIMELINE_SCHEMA;
  sku: typeof INCIDENT_NOTIFICATION_TIMELINE_SKU;
  ok: boolean;
  checks: Record<string, boolean>;
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

export function verifyIncidentNotificationTimeline(
  docInput: unknown,
): IncidentNotificationTimelineVerifyResult {
  const doc = asRecord(docInput);
  const schemaValid = doc?.schema === INCIDENT_NOTIFICATION_TIMELINE_SCHEMA;
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;
  const incidentIdPresent = String(doc?.incident_id || '').trim().length > 0;
  const awarenessPresent = String(doc?.serious_incident_awareness_at || '').trim().length > 0;

  const milestones = Array.isArray(doc?.milestones)
    ? (doc.milestones as IncidentNotificationMilestone[])
    : [];
  const milestonesPresent = milestones.length >= 2;

  const expectedDeadline = computeNcaNotificationDeadline(String(doc?.serious_incident_awareness_at || ''));
  const deadlineMatches =
    String(doc?.nca_notification_deadline_at || '') === expectedDeadline && expectedDeadline.length > 0;

  const expectedMilestonesDigest = buildMilestonesDigest(milestones);
  const milestonesDigestMatches =
    String(doc?.milestones_digest || '').toLowerCase() === expectedMilestonesDigest.toLowerCase();

  const compliance = evaluateTimelineCompliance(
    milestones,
    String(doc?.serious_incident_awareness_at || ''),
    String(doc?.nca_notification_deadline_at || ''),
  );

  let timelineDigestMatches = false;
  if (schemaValid && doc && milestonesDigestMatches && deadlineMatches) {
    const preimage = buildIncidentNotificationTimelinePreimage({
      organization_id: String(doc.organization_id),
      incident_id: String(doc.incident_id),
      regulatory_framework: String(doc.regulatory_framework || 'eu-ai-act-art73'),
      generated_at: String(doc.generated_at || ''),
      serious_incident_awareness_at: String(doc.serious_incident_awareness_at),
      nca_authority_ref: doc.nca_authority_ref != null ? String(doc.nca_authority_ref) : null,
      milestones,
      nca_notification_deadline_at: expectedDeadline,
      milestones_digest: expectedMilestonesDigest,
    });
    const expected = sha256HexUtf8(stableStringify(preimage));
    timelineDigestMatches = String(doc.timeline_digest || '').toLowerCase() === expected;
  }

  const hashOnlySurface = !hasForbiddenKeys(doc);
  const milestoneCountConsistent = Number(doc?.milestone_count) === milestones.length;

  const profileComplete =
    schemaValid &&
    organizationIdPresent &&
    incidentIdPresent &&
    awarenessPresent &&
    milestonesPresent &&
    deadlineMatches &&
    milestonesDigestMatches &&
    timelineDigestMatches &&
    milestoneCountConsistent &&
    compliance.milestones_chronological &&
    hashOnlySurface;

  let note: string | null = null;
  if (!schemaValid) note = `schema must be ${INCIDENT_NOTIFICATION_TIMELINE_SCHEMA}`;
  else if (!deadlineMatches) note = 'nca_notification_deadline_at must be awareness + 15 days';
  else if (!milestonesDigestMatches) note = 'milestones_digest does not match milestones array';
  else if (!timelineDigestMatches) note = 'timeline_digest does not match canonical preimage';
  else if (!compliance.milestones_chronological) note = 'milestones must be chronological';

  return {
    schema: INCIDENT_NOTIFICATION_TIMELINE_SCHEMA,
    sku: INCIDENT_NOTIFICATION_TIMELINE_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      organizationIdPresent,
      incidentIdPresent,
      awarenessPresent,
      milestonesPresent,
      deadlineMatches,
      milestonesDigestMatches,
      timelineDigestMatches,
      milestonesChronological: compliance.milestones_chronological,
      milestoneCountConsistent,
      hashOnlySurface,
      profileComplete,
    },
    note,
  };
}
