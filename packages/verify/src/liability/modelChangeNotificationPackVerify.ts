import { sha256HexUtf8 } from '../core/sha256.js';
import { buildVendorNotificationDigest, MODEL_CHANGE_NOTIFICATION_PACK_SCHEMA, buildModelChangeNotificationPackPreimage } from '../core/modelChangeNotificationPack.js';
import {
  computeLeadTimeHours,
  MIN_VENDOR_NOTIFICATION_LEAD_HOURS,
  VENDOR_MODEL_CHANGE_SCHEMA,
  POLICY_AT_CHANGE_SNAPSHOT_SCHEMA,
} from '../core/vendorModelChange.js';
import { TRACEABLE_CONDUCT_MANIFEST_SCHEMA } from '../core/traceableConductManifest.js';
import { stableStringify } from '../core/stableStringify.js';
import type { NotificationReadiness } from '../core/modelChangeNotificationPack.js';
import { verifyVendorModelChange } from './vendorModelChangeVerify.js';
import { verifyPolicyAtChangeSnapshot } from './policyAtChangeSnapshotVerify.js';
import { verifyTraceableConductManifest } from './traceableConductManifestVerify.js';
import {
  extractComposedPackProofLayers,
  hashOnlyComposedPackSurface,
  pc09MemberProofNote,
  resolveComposedMemberVerifyState,
} from './composedPackMemberVerify.js';

export const MODEL_CHANGE_NOTIFICATION_PACK_SKU =
  'aevesa-model-change-notification-pack-v1' as const;

const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|ssn|phone|address|pan|cvv)$/i;
const HEX64 = /^[a-f0-9]{64}$/;

export interface ModelChangeNotificationPackVerifyResult {
  schema: typeof MODEL_CHANGE_NOTIFICATION_PACK_SCHEMA;
  sku: typeof MODEL_CHANGE_NOTIFICATION_PACK_SKU;
  ok: boolean;
  checks: Record<string, boolean>;
  notification_readiness: NotificationReadiness | null;
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
  if (schema === VENDOR_MODEL_CHANGE_SCHEMA) {
    return memberDocs.vendor_model_change ?? memberDocs[schema] ?? null;
  }
  if (schema === POLICY_AT_CHANGE_SNAPSHOT_SCHEMA) {
    return memberDocs.policy_at_change_snapshot ?? memberDocs[schema] ?? null;
  }
  if (schema === TRACEABLE_CONDUCT_MANIFEST_SCHEMA) {
    return memberDocs.conduct_manifest ?? memberDocs.traceable_conduct_manifest ?? memberDocs[schema] ?? null;
  }
  return memberDocs[schema] ?? null;
}

function recomputeMemberVerifyOk(schema: string, embedded: unknown): boolean {
  if (embedded == null) return false;
  if (schema === VENDOR_MODEL_CHANGE_SCHEMA) {
    return verifyVendorModelChange(embedded).ok === true;
  }
  if (schema === POLICY_AT_CHANGE_SNAPSHOT_SCHEMA) {
    return verifyPolicyAtChangeSnapshot(embedded).ok === true;
  }
  if (schema === TRACEABLE_CONDUCT_MANIFEST_SCHEMA) {
    return verifyTraceableConductManifest(embedded).ok === true;
  }
  return false;
}

export function verifyModelChangeNotificationPack(
  docInput: unknown,
): ModelChangeNotificationPackVerifyResult {
  const doc = asRecord(docInput);
  const schemaValid = doc?.schema === MODEL_CHANGE_NOTIFICATION_PACK_SCHEMA;
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;
  const changeIdPresent = String(doc?.change_id || '').trim().length > 0;

  const members = Array.isArray(doc?.composed_members) ? doc.composed_members : [];
  const composedMembersPresent = members.length >= 3;
  const memberDigestsValid =
    members.length === 0 ||
    members.every((m) => HEX64.test(String(m?.member_digest || '').toLowerCase()));

  const changeMember = members.find((m) => m?.member_schema === 'aevesa.vendor-model-change/v1');
  const policyMember = members.find(
    (m) => m?.member_schema === 'aevesa.policy-at-change-snapshot/v1',
  );
  const conductMember = members.find(
    (m) => m?.member_schema === 'aevesa.traceable-conduct-manifest/v1',
  );

  const binding = asRecord(doc?.change_session_binding) || {};
  const normalizationBound = binding.normalization_bound === true;
  const bindingDigestsValid =
    HEX64.test(String(binding.change_digest || '').toLowerCase()) &&
    HEX64.test(String(binding.notification_digest || '').toLowerCase()) &&
    HEX64.test(String(binding.policy_at_change_digest || '').toLowerCase());

  const vendorChange = asRecord(doc?.vendor_model_change) || {};
  const notification = asRecord(doc?.vendor_notification) || {};

  const bindingMatchesChange =
    String(binding.change_digest || '').toLowerCase() ===
      String(vendorChange.change_digest || '').toLowerCase() &&
    (!changeMember ||
      String(binding.change_digest || '').toLowerCase() ===
        String(changeMember.member_digest || '').toLowerCase());

  const bindingMatchesPolicy =
    (!policyMember ||
      String(binding.policy_at_change_digest || '').toLowerCase() ===
        String(policyMember.member_digest || '').toLowerCase());

  const bindingMatchesNotification =
    String(binding.notification_digest || '').toLowerCase() ===
    String(notification.notification_digest || '').toLowerCase();

  const bindingMatchesMembers =
    bindingMatchesChange &&
    bindingMatchesPolicy &&
    bindingMatchesNotification &&
    String(binding.change_id || '') === String(doc?.change_id || '');

  let notificationDigestMatches = false;
  if (doc?.organization_id && vendorChange.change_digest) {
    const expected = buildVendorNotificationDigest({
      organization_id: String(doc.organization_id),
      vendor_id: String(notification.vendor_id || ''),
      vendor_display_name:
        notification.vendor_display_name != null
          ? String(notification.vendor_display_name)
          : null,
      notified_at: String(notification.notified_at || ''),
      notification_channel: String(
        notification.notification_channel || 'vendor_portal',
      ) as 'vendor_portal',
      notification_statement: String(notification.notification_statement || ''),
      change_digest: String(vendorChange.change_digest || ''),
    });
    notificationDigestMatches =
      String(notification.notification_digest || '').toLowerCase() === expected.toLowerCase();
  }

  const leadTimeHours = computeLeadTimeHours(
    String(notification.notified_at || ''),
    String(vendorChange.effective_at || ''),
  );
  const leadTimeMet =
    leadTimeHours != null && leadTimeHours >= MIN_VENDOR_NOTIFICATION_LEAD_HOURS;

  const assertions = asRecord(doc?.notification_assertions) || {};
  const derivedReadiness = String(
    assertions.notification_readiness || '',
  ) as NotificationReadiness;

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

  const changeOk =
    memberResolution.members.find((m) => m.member_schema === VENDOR_MODEL_CHANGE_SCHEMA)
      ?.verify_ok === true;
  const policyOk =
    memberResolution.members.find((m) => m.member_schema === POLICY_AT_CHANGE_SNAPSHOT_SCHEMA)
      ?.verify_ok === true;
  const conductOk =
    memberResolution.members.find((m) => m.member_schema === TRACEABLE_CONDUCT_MANIFEST_SCHEMA)
      ?.verify_ok === true;

  const memberArtifactsBundled = memberResolution.memberArtifactsBundled;
  const memberAttestationsPresent = memberResolution.memberAttestationsPresent;
  const memberProofPresent = memberResolution.memberProofPresent;
  const selfAssertedVerifyIgnored = memberResolution.selfAssertedVerifyIgnored;

  let notificationAssertionsConsistent =
    assertions.third_party_verifiable === true && changeIdPresent;

  if (derivedReadiness === 'procurement_ready') {
    notificationAssertionsConsistent =
      notificationAssertionsConsistent &&
      assertions.vendor_notified === true &&
      assertions.lead_time_met === true &&
      assertions.fingerprints_bound === true &&
      changeOk &&
      policyOk &&
      conductOk &&
      leadTimeMet &&
      notificationDigestMatches &&
      normalizationBound &&
      bindingMatchesMembers;
  } else if (derivedReadiness === 'partial') {
    notificationAssertionsConsistent =
      notificationAssertionsConsistent &&
      assertions.vendor_notified === true &&
      notificationDigestMatches &&
      bindingMatchesMembers;
  }

  const readinessConsistent = assertions.notification_readiness === derivedReadiness;

  let packDigestMatches = false;
  if (schemaValid && doc && bindingDigestsValid && notificationDigestMatches) {
    const preimage = buildModelChangeNotificationPackPreimage({
      organization_id: String(doc.organization_id),
      change_id: String(doc.change_id),
      generated_at: String(doc.generated_at || ''),
      vendor_model_change: {
        change_digest: String(vendorChange.change_digest || ''),
        effective_at: String(vendorChange.effective_at || ''),
        change_type: String(vendorChange.change_type || ''),
        model_fingerprint_before: String(vendorChange.model_fingerprint_before || ''),
        model_fingerprint_after: String(vendorChange.model_fingerprint_after || ''),
      },
      vendor_notification: {
        required: true as const,
        vendor_id: String(notification.vendor_id || ''),
        vendor_display_name:
          notification.vendor_display_name != null
            ? String(notification.vendor_display_name)
            : null,
        notified_at: String(notification.notified_at || ''),
        notification_channel: String(notification.notification_channel || 'vendor_portal') as
          | 'vendor_portal'
          | 'webhook'
          | 'email_attestation'
          | 'contractual_feed',
        notification_statement: String(notification.notification_statement || ''),
        notification_digest: String(notification.notification_digest || ''),
        lead_time_hours: leadTimeHours,
      },
      notification_assertions: {
        vendor_notified: assertions.vendor_notified === true,
        lead_time_met: assertions.lead_time_met === true,
        fingerprints_bound: assertions.fingerprints_bound === true,
        third_party_verifiable: assertions.third_party_verifiable === true,
        notification_readiness: derivedReadiness,
        lead_time_hours: leadTimeHours,
        min_lead_time_hours: MIN_VENDOR_NOTIFICATION_LEAD_HOURS,
      },
      composed_members: members.map((m) => ({
        member_schema: String(m?.member_schema || ''),
        member_digest: String(m?.member_digest || ''),
        verify_ok: m?.verify_ok === true,
        label: String(m?.label || ''),
        entry_count: m?.entry_count ?? null,
      })),
      change_session_binding: {
        change_id: String(binding.change_id || ''),
        change_digest: String(binding.change_digest || ''),
        notification_digest: String(binding.notification_digest || ''),
        policy_at_change_digest: String(binding.policy_at_change_digest || ''),
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
    changeIdPresent &&
    composedMembersPresent &&
    memberDigestsValid &&
    bindingDigestsValid &&
    bindingMatchesMembers &&
    notificationDigestMatches &&
    notificationAssertionsConsistent &&
    packDigestMatches &&
    hashOnlySurface &&
    memberProofPresent &&
    changeOk &&
    policyOk &&
    conductOk &&
    readinessConsistent;

  let note: string | null = null;
  if (!schemaValid) note = `schema must be ${MODEL_CHANGE_NOTIFICATION_PACK_SCHEMA}`;
  else if (!memberProofPresent || selfAssertedVerifyIgnored) {
    note = pc09MemberProofNote(memberResolution);
  } else if (!notificationDigestMatches) note = 'vendor notification_digest does not match ceremony preimage';
  else if (!bindingMatchesMembers) note = 'change_session_binding digests must match composed members';
  else if (!packDigestMatches) note = 'pack_digest does not match canonical preimage';
  else if (!notificationAssertionsConsistent) note = 'notification_assertions inconsistent with members or binding';
  else if (!readinessConsistent) note = 'notification_readiness inconsistent with lead time state';

  return {
    schema: MODEL_CHANGE_NOTIFICATION_PACK_SCHEMA,
    sku: MODEL_CHANGE_NOTIFICATION_PACK_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      organizationIdPresent,
      changeIdPresent,
      composedMembersPresent,
      memberDigestsValid,
      bindingDigestsValid,
      bindingMatchesMembers,
      notificationDigestMatches,
      leadTimeMet,
      notificationAssertionsConsistent,
      packDigestMatches,
      hashOnlySurface,
      memberArtifactsBundled,
      memberAttestationsPresent,
      memberProofPresent,
      memberVerifyRecomputed: changeOk && policyOk && conductOk,
      readinessConsistent,
      profileComplete,
    },
    notification_readiness: derivedReadiness,
    gtmLine:
      'Vendor RFPs require model change notice. Aevesa proves 72-hour lead time with fingerprint binding — offline.',
    note,
  };
}
