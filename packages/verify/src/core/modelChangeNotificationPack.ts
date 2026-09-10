import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';
import {
  computeLeadTimeHours,
  MIN_VENDOR_NOTIFICATION_LEAD_HOURS,
} from './vendorModelChange.js';

/** Wave 12 Track E — vendor model/guardrail change notification bound to change + policy evidence. */

export const MODEL_CHANGE_NOTIFICATION_PACK_SCHEMA =
  'aevesa.model-change-notification-pack/v1' as const;

export type NotificationReadiness = 'procurement_ready' | 'partial' | 'unverified';

export interface VendorNotificationInput {
  vendor_id: string;
  vendor_display_name?: string | null;
  notified_at: string;
  notification_channel: 'vendor_portal' | 'webhook' | 'email_attestation' | 'contractual_feed';
  notification_statement: string;
}

export interface NotificationAssertionsInput {
  vendor_notified: boolean;
  lead_time_met: boolean;
  fingerprints_bound: boolean;
  third_party_verifiable: boolean;
}

export interface ChangeSessionBinding {
  change_id: string;
  change_digest: string;
  notification_digest: string;
  policy_at_change_digest: string;
  normalization_bound: boolean;
}

export interface ComposedChangeMemberRef {
  member_schema: string;
  member_digest: string;
  verify_ok: boolean;
  label: string;
  entry_count?: number | null;
}

export interface ModelChangeNotificationPackInput {
  organization_id: string;
  change_id: string;
  generated_at?: string;
  vendor_model_change: {
    change_digest: string;
    effective_at: string;
    change_type: string;
    model_fingerprint_before: string;
    model_fingerprint_after: string;
  };
  vendor_notification: VendorNotificationInput & {
    change_digest: string;
    effective_at: string;
  };
  notification_assertions: NotificationAssertionsInput;
  composed_members: ComposedChangeMemberRef[];
  change_session_binding: ChangeSessionBinding;
  disclaimer?: string;
}



export function buildVendorNotificationDigest(
  input: VendorNotificationInput & { organization_id: string; change_digest: string },
): string {
  return sha256HexUtf8(
    stableStringify({
      schema: 'aevesa.vendor-change-notification/v1',
      organization_id: String(input.organization_id || '').trim(),
      vendor_id: String(input.vendor_id || '').trim(),
      change_digest: String(input.change_digest || '').trim().toLowerCase(),
      notified_at: String(input.notified_at || '').trim(),
      notification_channel: input.notification_channel,
      notification_statement: String(input.notification_statement || '').trim(),
    }),
  );
}

export function deriveNotificationReadiness(
  leadTimeMet: boolean,
  vendorNotified: boolean,
  membersVerified: boolean,
  fingerprintsBound: boolean,
): NotificationReadiness {
  if (vendorNotified && leadTimeMet && membersVerified && fingerprintsBound) {
    return 'procurement_ready';
  }
  if (vendorNotified && (membersVerified || fingerprintsBound)) {
    return 'partial';
  }
  return 'unverified';
}

export function buildNotificationAssertionsBlock(
  input: NotificationAssertionsInput,
  notifiedAt: string,
  effectiveAt: string,
  members: ComposedChangeMemberRef[],
  fingerprintsBound: boolean,
) {
  const leadTimeHours = computeLeadTimeHours(notifiedAt, effectiveAt);
  const leadTimeMet =
    leadTimeHours != null && leadTimeHours >= MIN_VENDOR_NOTIFICATION_LEAD_HOURS;
  const changeMember = members.find((m) => m.member_schema === 'aevesa.vendor-model-change/v1');
  const policyMember = members.find(
    (m) => m.member_schema === 'aevesa.policy-at-change-snapshot/v1',
  );
  const conductMember = members.find(
    (m) => m.member_schema === 'aevesa.traceable-conduct-manifest/v1',
  );
  const membersVerified =
    changeMember?.verify_ok === true &&
    policyMember?.verify_ok === true &&
    conductMember?.verify_ok === true;

  const readiness = deriveNotificationReadiness(
    leadTimeMet || input.lead_time_met === true,
    input.vendor_notified === true,
    membersVerified,
    fingerprintsBound || input.fingerprints_bound === true,
  );

  return {
    vendor_notified: input.vendor_notified === true,
    lead_time_met: leadTimeMet || input.lead_time_met === true,
    fingerprints_bound: fingerprintsBound || input.fingerprints_bound === true,
    third_party_verifiable: input.third_party_verifiable === true,
    notification_readiness: readiness,
    lead_time_hours: leadTimeHours,
    min_lead_time_hours: MIN_VENDOR_NOTIFICATION_LEAD_HOURS,
  };
}

export function buildVendorNotificationBlock(
  input: VendorNotificationInput & {
    organization_id: string;
    change_digest: string;
    effective_at: string;
  },
) {
  const notification_digest = buildVendorNotificationDigest(input);
  const lead_time_hours = computeLeadTimeHours(input.notified_at, input.effective_at);
  return {
    required: true as const,
    vendor_id: String(input.vendor_id || '').trim(),
    vendor_display_name: input.vendor_display_name ?? null,
    notified_at: String(input.notified_at || '').trim(),
    notification_channel: input.notification_channel,
    notification_statement: String(input.notification_statement || '').trim(),
    notification_digest,
    lead_time_hours,
  };
}

export function buildModelChangeNotificationPackPreimage(
  input: Omit<
    ModelChangeNotificationPackInput,
    'disclaimer' | 'vendor_notification' | 'notification_assertions'
  > & {
    generated_at: string;
    vendor_notification: ReturnType<typeof buildVendorNotificationBlock>;
    notification_assertions: ReturnType<typeof buildNotificationAssertionsBlock>;
    composed_members: ComposedChangeMemberRef[];
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

  const binding = input.change_session_binding;
  const change = input.vendor_model_change;

  return {
    schema: MODEL_CHANGE_NOTIFICATION_PACK_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    change_id: String(input.change_id || '').trim(),
    generated_at: input.generated_at,
    vendor_model_change: {
      change_digest: String(change.change_digest || '').trim().toLowerCase(),
      effective_at: String(change.effective_at || '').trim(),
      change_type: String(change.change_type || '').trim(),
      model_fingerprint_before: String(change.model_fingerprint_before || '').trim(),
      model_fingerprint_after: String(change.model_fingerprint_after || '').trim(),
    },
    vendor_notification: input.vendor_notification,
    notification_assertions: input.notification_assertions,
    composed_members: members,
    change_session_binding: {
      change_id: String(binding.change_id || '').trim(),
      change_digest: String(binding.change_digest || '').trim().toLowerCase(),
      notification_digest: String(binding.notification_digest || '').trim().toLowerCase(),
      policy_at_change_digest: String(binding.policy_at_change_digest || '').trim().toLowerCase(),
      normalization_bound: binding.normalization_bound === true,
    },
  };
}

export function buildModelChangeNotificationPackDocument(input: ModelChangeNotificationPackInput) {
  const generated_at = input.generated_at || new Date().toISOString();
  const vendor_notification = buildVendorNotificationBlock({
    ...input.vendor_notification,
    organization_id: input.organization_id,
    change_digest: input.vendor_model_change.change_digest,
    effective_at: input.vendor_model_change.effective_at,
  });

  const bindingMatches =
    String(input.change_session_binding.notification_digest || '').toLowerCase() ===
    String(vendor_notification.notification_digest || '').toLowerCase();

  const notification_assertions = buildNotificationAssertionsBlock(
    input.notification_assertions,
    vendor_notification.notified_at,
    input.vendor_model_change.effective_at,
    input.composed_members,
    bindingMatches &&
      String(input.change_session_binding.change_digest || '').toLowerCase() ===
        String(input.vendor_model_change.change_digest || '').toLowerCase(),
  );

  const preimage = buildModelChangeNotificationPackPreimage({
    organization_id: input.organization_id,
    change_id: input.change_id,
    generated_at,
    vendor_model_change: input.vendor_model_change,
    vendor_notification,
    notification_assertions,
    composed_members: input.composed_members,
    change_session_binding: input.change_session_binding,
  });
  const pack_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    pack_digest,
    disclaimer:
      input.disclaimer ||
      'Vendor model change notification evidence — not legal advice or contractual warranty.',
  };
}

export default {
  MODEL_CHANGE_NOTIFICATION_PACK_SCHEMA,
  buildModelChangeNotificationPackDocument,
  buildNotificationAssertionsBlock,
  buildVendorNotificationBlock,
};
