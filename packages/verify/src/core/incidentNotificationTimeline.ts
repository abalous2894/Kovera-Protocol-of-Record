import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';

/** Wave 12 Track B — Art. 73 serious-incident NCA notification timeline (hash-only milestones). */

export const INCIDENT_NOTIFICATION_TIMELINE_SCHEMA =
  'aevesa.incident-notification-timeline/v1' as const;

export const NCA_NOTIFICATION_DEADLINE_DAYS = 15;

export type IncidentMilestoneType =
  | 'detection'
  | 'serious_incident_classification'
  | 'internal_escalation'
  | 'custody_freeze'
  | 'nca_notification'
  | 'follow_up_report';

export interface IncidentNotificationMilestone {
  milestone_id: string;
  milestone_type: IncidentMilestoneType;
  occurred_at: string;
  entry_hash?: string | null;
  label: string;
}

export interface IncidentNotificationTimelineInput {
  organization_id: string;
  incident_id: string;
  regulatory_framework?: string;
  generated_at?: string;
  serious_incident_awareness_at: string;
  nca_authority_ref?: string | null;
  milestones: IncidentNotificationMilestone[];
}



export function computeNcaNotificationDeadline(awarenessAt: string): string {
  const ms = Date.parse(String(awarenessAt || ''));
  if (!Number.isFinite(ms)) return '';
  return new Date(ms + NCA_NOTIFICATION_DEADLINE_DAYS * 86400000).toISOString();
}

export function buildMilestonesDigest(milestones: IncidentNotificationMilestone[]): string {
  const normalized = [...(milestones || [])]
    .map((m) => ({
      milestone_id: String(m.milestone_id || '').trim(),
      milestone_type: m.milestone_type,
      occurred_at: String(m.occurred_at || '').trim(),
      entry_hash: m.entry_hash ? String(m.entry_hash).trim().toLowerCase() : null,
      label: String(m.label || '').trim(),
    }))
    .sort((a, b) => a.occurred_at.localeCompare(b.occurred_at));
  return sha256HexUtf8(stableStringify(normalized));
}

export function areMilestonesChronological(milestones: IncidentNotificationMilestone[]): boolean {
  const sorted = [...(milestones || [])].sort((a, b) =>
    String(a.occurred_at).localeCompare(String(b.occurred_at)),
  );
  for (let i = 1; i < sorted.length; i += 1) {
    if (Date.parse(sorted[i].occurred_at) < Date.parse(sorted[i - 1].occurred_at)) {
      return false;
    }
  }
  return milestones.length >= 2;
}

export function findMilestoneAtOrBefore(
  milestones: IncidentNotificationMilestone[],
  type: IncidentMilestoneType,
): IncidentNotificationMilestone | null {
  const match = (milestones || []).find((m) => m.milestone_type === type);
  return match || null;
}

export type TimelineCompliance = 'nca_compliant' | 'deadline_missed' | 'partial';

export function evaluateTimelineCompliance(
  milestones: IncidentNotificationMilestone[],
  awarenessAt: string,
  ncaDeadlineAt: string,
): {
  nca_deadline_met: boolean;
  milestones_chronological: boolean;
  nca_notification_at: string | null;
  hours_to_nca_notification: number | null;
} {
  const chronological = areMilestonesChronological(milestones);
  const ncaMilestone = findMilestoneAtOrBefore(milestones, 'nca_notification');
  const ncaAt = ncaMilestone?.occurred_at ? String(ncaMilestone.occurred_at) : null;
  const deadlineMs = Date.parse(ncaDeadlineAt);
  const ncaMs = ncaAt ? Date.parse(ncaAt) : NaN;
  const awarenessMs = Date.parse(awarenessAt);

  let nca_deadline_met = false;
  let hours_to_nca_notification: number | null = null;
  if (Number.isFinite(ncaMs) && Number.isFinite(deadlineMs)) {
    nca_deadline_met = ncaMs <= deadlineMs;
  }
  if (Number.isFinite(ncaMs) && Number.isFinite(awarenessMs)) {
    hours_to_nca_notification = Math.round((ncaMs - awarenessMs) / 3600000);
  }

  return {
    nca_deadline_met,
    milestones_chronological: chronological,
    nca_notification_at: ncaAt,
    hours_to_nca_notification,
  };
}

export function deriveTimelineReadiness(
  compliance: ReturnType<typeof evaluateTimelineCompliance>,
  hasCustody: boolean,
): TimelineCompliance {
  if (compliance.nca_deadline_met && compliance.milestones_chronological && hasCustody) {
    return 'nca_compliant';
  }
  if (compliance.nca_notification_at && !compliance.nca_deadline_met) {
    return 'deadline_missed';
  }
  return 'partial';
}

export function buildIncidentNotificationTimelinePreimage(
  input: IncidentNotificationTimelineInput & {
    generated_at: string;
    nca_notification_deadline_at: string;
    milestones_digest: string;
  },
): Record<string, unknown> {
  const milestones = [...(input.milestones || [])]
    .map((m) => ({
      milestone_id: String(m.milestone_id || '').trim(),
      milestone_type: m.milestone_type,
      occurred_at: String(m.occurred_at || '').trim(),
      entry_hash: m.entry_hash ? String(m.entry_hash).trim().toLowerCase() : null,
      label: String(m.label || '').trim(),
    }))
    .sort((a, b) => a.occurred_at.localeCompare(b.occurred_at));

  return {
    schema: INCIDENT_NOTIFICATION_TIMELINE_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    incident_id: String(input.incident_id || '').trim(),
    regulatory_framework: input.regulatory_framework || 'eu-ai-act-art73',
    generated_at: input.generated_at,
    serious_incident_awareness_at: String(input.serious_incident_awareness_at || '').trim(),
    nca_notification_deadline_at: String(input.nca_notification_deadline_at || '').trim(),
    nca_authority_ref: input.nca_authority_ref ? String(input.nca_authority_ref).trim() : null,
    milestones,
    milestone_count: milestones.length,
    milestones_digest: String(input.milestones_digest || '').trim().toLowerCase(),
  };
}

export function buildIncidentNotificationTimelineDocument(input: IncidentNotificationTimelineInput) {
  const generated_at = input.generated_at || new Date().toISOString();
  const milestones_digest = buildMilestonesDigest(input.milestones || []);
  const nca_notification_deadline_at = computeNcaNotificationDeadline(
    input.serious_incident_awareness_at,
  );
  const preimage = buildIncidentNotificationTimelinePreimage({
    ...input,
    generated_at,
    nca_notification_deadline_at,
    milestones_digest,
  });
  const timeline_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    timeline_digest,
  };
}

/** Digest for kovera-incident-custody-pack/1 manifest binding (hash-only subset). */
export function buildIncidentCustodyManifestDigest(manifest: {
  schema?: string;
  incident_ref?: string | null;
  freeze_anchor_entry_hash?: string | null;
  file_integrity?: Record<string, string>;
}): string {
  const integrity = manifest.file_integrity || {};
  const integrityKeys = Object.keys(integrity).sort();
  const integritySubset: Record<string, string> = {};
  for (const key of integrityKeys) {
    integritySubset[key] = String(integrity[key] || '').toLowerCase();
  }
  return sha256HexUtf8(
    stableStringify({
      schema: String(manifest.schema || 'kovera-incident-custody-pack/1'),
      incident_ref: manifest.incident_ref ? String(manifest.incident_ref).trim() : null,
      freeze_anchor_entry_hash: manifest.freeze_anchor_entry_hash
        ? String(manifest.freeze_anchor_entry_hash).trim().toLowerCase()
        : null,
      file_integrity: integritySubset,
    }),
  );
}

export default {
  INCIDENT_NOTIFICATION_TIMELINE_SCHEMA,
  NCA_NOTIFICATION_DEADLINE_DAYS,
  computeNcaNotificationDeadline,
  buildMilestonesDigest,
  evaluateTimelineCompliance,
  deriveTimelineReadiness,
  buildIncidentNotificationTimelineDocument,
  buildIncidentCustodyManifestDigest,
};
