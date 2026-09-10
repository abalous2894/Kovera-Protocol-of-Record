import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';
import {
  deriveTimelineReadiness,
  evaluateTimelineCompliance,
} from './incidentNotificationTimeline.js';
import type { TimelineCompliance } from './incidentNotificationTimeline.js';

/** Wave 12 Track B — Art. 73 NCA notification timeline bound to custody evidence. */

export const INCIDENT_NOTIFICATION_TIMELINE_PACK_SCHEMA =
  'aevesa.incident-notification-timeline-pack/v1' as const;

export interface ComposedTimelineMemberRef {
  member_schema: string;
  member_digest: string;
  verify_ok: boolean;
  label: string;
  entry_count?: number | null;
}

export interface TimelineAssertionsInput {
  nca_deadline_met: boolean;
  milestones_chronological: boolean;
  custody_evidence_bound: boolean;
  third_party_verifiable: boolean;
  nca_notification_at?: string | null;
  hours_to_nca_notification?: number | null;
}

export interface TimelineSessionBinding {
  incident_id: string;
  timeline_digest: string;
  custody_manifest_digest: string;
  conduct_manifest_digest: string;
  normalization_bound: boolean;
}

export interface IncidentNotificationTimelinePackInput {
  organization_id: string;
  incident_id: string;
  generated_at?: string;
  timeline_assertions: TimelineAssertionsInput;
  composed_members: ComposedTimelineMemberRef[];
  timeline_session_binding: TimelineSessionBinding;
  notification_timeline: {
    timeline_digest: string;
    serious_incident_awareness_at: string;
    nca_notification_deadline_at: string;
    milestone_count: number;
    milestones_digest: string;
  };
  disclaimer?: string;
}



export function buildTimelineAssertionsBlock(
  input: TimelineAssertionsInput,
  members: ComposedTimelineMemberRef[],
) {
  const hasCustody = members.some(
    (m) => m.member_schema === 'kovera-incident-custody-pack/1' && m.verify_ok === true,
  );
  const compliance = {
    nca_deadline_met: input.nca_deadline_met === true,
    milestones_chronological: input.milestones_chronological === true,
    nca_notification_at: input.nca_notification_at ?? null,
    hours_to_nca_notification: input.hours_to_nca_notification ?? null,
  };
  const readiness = deriveTimelineReadiness(compliance, hasCustody);
  return {
    nca_deadline_met: input.nca_deadline_met === true,
    milestones_chronological: input.milestones_chronological === true,
    custody_evidence_bound: hasCustody || input.custody_evidence_bound === true,
    third_party_verifiable: input.third_party_verifiable === true,
    timeline_readiness: readiness,
    nca_notification_at: input.nca_notification_at ?? null,
    hours_to_nca_notification: input.hours_to_nca_notification ?? null,
  };
}

export function buildIncidentNotificationTimelinePackPreimage(
  input: Omit<IncidentNotificationTimelinePackInput, 'disclaimer'> & {
    generated_at: string;
    timeline_assertions: ReturnType<typeof buildTimelineAssertionsBlock>;
    composed_members: ComposedTimelineMemberRef[];
  },
): Record<string, unknown> {
  const members = [...(input.composed_members || [])]
    .map((m) => ({
      member_schema: String(m.member_schema || '').trim(),
      member_digest: String(m.member_digest || '').trim().toLowerCase(),
      verify_ok: m.verify_ok === true,
      label: String(m.label || '').trim(),
      entry_count: m.entry_count != null ? Number(m.entry_count) : null,
    }))
    .sort((a, b) => a.member_schema.localeCompare(b.member_schema));

  const binding = input.timeline_session_binding;
  const timeline = input.notification_timeline;

  return {
    schema: INCIDENT_NOTIFICATION_TIMELINE_PACK_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    incident_id: String(input.incident_id || '').trim(),
    generated_at: input.generated_at,
    timeline_assertions: input.timeline_assertions,
    notification_timeline: {
      timeline_digest: String(timeline.timeline_digest || '').trim().toLowerCase(),
      serious_incident_awareness_at: String(timeline.serious_incident_awareness_at || '').trim(),
      nca_notification_deadline_at: String(timeline.nca_notification_deadline_at || '').trim(),
      milestone_count: Number(timeline.milestone_count) || 0,
      milestones_digest: String(timeline.milestones_digest || '').trim().toLowerCase(),
    },
    composed_members: members,
    timeline_session_binding: {
      incident_id: String(binding.incident_id || '').trim(),
      timeline_digest: String(binding.timeline_digest || '').trim().toLowerCase(),
      custody_manifest_digest: String(binding.custody_manifest_digest || '').trim().toLowerCase(),
      conduct_manifest_digest: String(binding.conduct_manifest_digest || '').trim().toLowerCase(),
      normalization_bound: binding.normalization_bound === true,
    },
  };
}

export function buildIncidentNotificationTimelinePackDocument(
  input: IncidentNotificationTimelinePackInput,
) {
  const generated_at = input.generated_at || new Date().toISOString();
  const timeline_assertions = buildTimelineAssertionsBlock(
    input.timeline_assertions,
    input.composed_members,
  );

  const preimage = buildIncidentNotificationTimelinePackPreimage({
    ...input,
    generated_at,
    timeline_assertions,
    composed_members: input.composed_members,
  });
  const pack_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    pack_digest,
    disclaimer:
      input.disclaimer ||
      'Art. 73 notification timeline evidence — not legal advice or regulatory submission.',
  };
}

export type { TimelineCompliance };

export default {
  INCIDENT_NOTIFICATION_TIMELINE_PACK_SCHEMA,
  buildTimelineAssertionsBlock,
  buildIncidentNotificationTimelinePackDocument,
};
