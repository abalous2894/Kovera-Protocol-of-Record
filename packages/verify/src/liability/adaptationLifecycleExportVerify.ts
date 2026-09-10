import { sha256HexUtf8 } from '../core/sha256.js';
import { stableStringify } from '../core/stableStringify.js';
import {
  ADAPTATION_LIFECYCLE_EXPORT_SCHEMA,
  ADAPTATION_LIFECYCLE_EXPORT_SKU,
  ADAPTATION_DRIFT_WITNESS_TIMELINE_SCHEMA,
  ADAPTATION_LIFECYCLE_REQUIRED_MEMBER_SCHEMAS,
  ADAPTATION_LIFECYCLE_OPTIONAL_MEMBER_SCHEMAS,
  buildAdaptationLifecycleExportPreimage,
  buildAdaptationDriftWitnessTimelineDigest,
  buildLifecycleAssertionsBlock,
  normalizeAdaptationDriftWitnessTimeline,
  type LifecycleReadiness,
  type AdaptationDriftWitnessTimelineEntry,
} from '../core/adaptationLifecycleExport.js';

type LifecycleAssertionsBlock = ReturnType<typeof buildLifecycleAssertionsBlock>;
import {
  DECLARED_ADAPTATION_ENVELOPE_SCHEMA,
} from '../core/declaredAdaptationEnvelope.js';
import {
  SUBSTANTIAL_MODIFICATION_SIGNAL_SCHEMA,
} from '../core/substantialModificationSignal.js';
import { verifyDeclaredAdaptationEnvelopeBundle } from './declaredAdaptationEnvelopeVerify.js';
import { verifySubstantialModificationSignalBundle } from './substantialModificationSignalVerify.js';

const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|ssn|phone|address|pan|cvv)$/i;
const HEX64 = /^[a-f0-9]{64}$/;

export interface AdaptationLifecycleExportVerifyOptions {
  requireBreachSignalWhenBreach?: boolean;
}

export interface AdaptationLifecycleExportVerifyResult {
  schema: typeof ADAPTATION_LIFECYCLE_EXPORT_SCHEMA;
  sku: typeof ADAPTATION_LIFECYCLE_EXPORT_SKU;
  ok: boolean;
  checks: {
    schemaValid: boolean;
    organizationIdPresent: boolean;
    systemIdPresent: boolean;
    lifecycleWindowValid: boolean;
    envelopeMemberVerified: boolean;
    timelineDigestMatches: boolean;
    composedMembersComplete: boolean;
    exportDigestMatches: boolean;
    hashOnlySurface: boolean;
    lifecycleReadinessConsistent: boolean;
    profileComplete: boolean;
  };
  lifecycle_readiness: LifecycleReadiness | null;
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
  if (depth > 10 || value == null) return false;
  if (Array.isArray(value)) return value.some((v) => hasForbiddenKeys(v, depth + 1));
  if (typeof value !== 'object') return false;
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (FORBIDDEN_KEYS.test(key)) return true;
    if (hasForbiddenKeys(child, depth + 1)) return true;
  }
  return false;
}

export function verifyAdaptationLifecycleExportBundle(
  input: unknown,
  options: AdaptationLifecycleExportVerifyOptions = {},
): AdaptationLifecycleExportVerifyResult {
  const doc = asRecord(input);
  const schemaValid = doc?.schema === ADAPTATION_LIFECYCLE_EXPORT_SCHEMA;
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;
  const systemIdPresent = String(doc?.system_id || '').trim().length > 0;

  const window = asRecord(doc?.lifecycle_window);
  const lifecycleWindowValid =
    window != null
    && String(window.started_at || '').trim().length > 0
    && String(window.ended_at || '').trim().length > 0;

  const memberDocs = asRecord(doc?.member_documents);
  const envelopeDoc = asRecord(memberDocs?.declared_adaptation_envelope);
  const signalDoc = asRecord(memberDocs?.substantial_modification_signal);

  const envelopeVerify = envelopeDoc
    ? verifyDeclaredAdaptationEnvelopeBundle(envelopeDoc)
    : null;
  const envelopeMemberVerified = envelopeVerify?.ok === true;

  const timelineRaw = Array.isArray(doc?.drift_witness_timeline)
    ? (doc!.drift_witness_timeline as AdaptationDriftWitnessTimelineEntry[])
    : [];
  const expectedTimelineDigest = buildAdaptationDriftWitnessTimelineDigest(timelineRaw);
  const timelineDigestMatches =
    typeof doc?.drift_witness_timeline_digest === 'string'
    && doc.drift_witness_timeline_digest === expectedTimelineDigest;

  const signalVerify = signalDoc ? verifySubstantialModificationSignalBundle(signalDoc) : null;
  const signalVerifyOk = signalDoc ? signalVerify?.ok === true : true;

  const member_results: Record<string, boolean> = {};
  member_results[DECLARED_ADAPTATION_ENVELOPE_SCHEMA] = envelopeMemberVerified;
  member_results[ADAPTATION_DRIFT_WITNESS_TIMELINE_SCHEMA] =
    timelineDigestMatches && timelineRaw.length > 0;
  if (signalDoc) {
    member_results[SUBSTANTIAL_MODIFICATION_SIGNAL_SCHEMA] = signalVerifyOk;
  }

  const composed = Array.isArray(doc?.composed_members) ? doc!.composed_members : [];
  const requiredPresent = ADAPTATION_LIFECYCLE_REQUIRED_MEMBER_SCHEMAS.every((schema) =>
    composed.some((m) => asRecord(m)?.member_schema === schema),
  );
  const requiredVerifyOk = ADAPTATION_LIFECYCLE_REQUIRED_MEMBER_SCHEMAS.every((schema) => {
    const member = composed.find((m) => asRecord(m)?.member_schema === schema);
    return asRecord(member)?.verify_ok === true;
  });

  const normalizedTimeline = normalizeAdaptationDriftWitnessTimeline(timelineRaw);
  const finalStatus =
    normalizedTimeline.length > 0
      ? String(normalizedTimeline[normalizedTimeline.length - 1].drift_status)
      : null;
  const breachArc = finalStatus === 'breach';
  const breachSignalOk =
    !breachArc
    || !options.requireBreachSignalWhenBreach
    || (signalDoc != null && signalVerifyOk);

  const composedMembersComplete = requiredPresent && requiredVerifyOk && breachSignalOk;

  let exportDigestMatches = false;
  if (
    schemaValid
    && organizationIdPresent
    && systemIdPresent
    && lifecycleWindowValid
    && doc?.lifecycle_assertions
    && typeof doc.lifecycle_export_digest === 'string'
  ) {
    const preimage = buildAdaptationLifecycleExportPreimage({
      organization_id: String(doc!.organization_id),
      system_id: String(doc!.system_id),
      operator_role: doc!.operator_role as 'provider' | 'deployer',
      generated_at: String(doc!.generated_at || ''),
      lifecycle_window: {
        started_at: String(window!.started_at),
        ended_at: String(window!.ended_at),
      },
      drift_witness_timeline: timelineRaw,
      drift_witness_timeline_digest: expectedTimelineDigest,
      composed_members: composed.map((m) => {
        const row = asRecord(m) || {};
        return {
          member_schema: String(row.member_schema || ''),
          member_digest: String(row.member_digest || ''),
          verify_ok: row.verify_ok === true,
          label: String(row.label || ''),
          entry_count: row.entry_count != null ? Number(row.entry_count) : null,
        };
      }),
      ordered_witness_entry_hashes: Array.isArray(doc!.ordered_witness_entry_hashes)
        ? doc!.ordered_witness_entry_hashes.map(String)
        : [],
      lifecycle_assertions: doc!.lifecycle_assertions as LifecycleAssertionsBlock,
    });
    const expectedDigest = sha256HexUtf8(stableStringify(preimage));
    exportDigestMatches = doc.lifecycle_export_digest === expectedDigest;
  }

  const hashOnlySurface = !hasForbiddenKeys(doc);

  const readiness = doc?.lifecycle_assertions
    ? String(asRecord(doc.lifecycle_assertions)?.lifecycle_readiness || '')
    : '';
  const lifecycleReadinessConsistent =
    readiness === 'export_ready'
    || readiness === 'partial'
    || readiness === 'incomplete';

  const profileComplete =
    schemaValid
    && organizationIdPresent
    && systemIdPresent
    && lifecycleWindowValid
    && envelopeMemberVerified
    && timelineDigestMatches
    && composedMembersComplete
    && exportDigestMatches
    && hashOnlySurface
    && lifecycleReadinessConsistent;

  const ok = profileComplete;

  let note: string | null = null;
  if (!schemaValid) note = 'Invalid or missing schema.';
  else if (!envelopeMemberVerified) note = 'Declared adaptation envelope member failed verify.';
  else if (!timelineDigestMatches) note = 'Drift witness timeline digest mismatch.';
  else if (!exportDigestMatches) note = 'Lifecycle export digest mismatch — tamper or serialization drift.';
  else if (breachArc && options.requireBreachSignalWhenBreach && !signalDoc) {
    note = 'Breach arc requires substantial_modification_signal member.';
  } else if (!hashOnlySurface) note = 'Forbidden raw-data keys detected on export surface.';

  const lifecycle_readiness = lifecycleReadinessConsistent
    ? (readiness as LifecycleReadiness)
    : null;

  const gtmLine = ok
    ? 'Adaptation lifecycle export verified offline — envelope, drift timeline, and breach signal compose a third-party-readable arc.'
    : 'Adaptation lifecycle export verification failed — lifecycle not independently verifiable.';

  return {
    schema: ADAPTATION_LIFECYCLE_EXPORT_SCHEMA,
    sku: ADAPTATION_LIFECYCLE_EXPORT_SKU,
    ok,
    checks: {
      schemaValid,
      organizationIdPresent,
      systemIdPresent,
      lifecycleWindowValid,
      envelopeMemberVerified,
      timelineDigestMatches,
      composedMembersComplete,
      exportDigestMatches,
      hashOnlySurface,
      lifecycleReadinessConsistent,
      profileComplete,
    },
    lifecycle_readiness,
    member_results,
    gtmLine,
    note,
  };
}

export default { verifyAdaptationLifecycleExportBundle, ADAPTATION_LIFECYCLE_EXPORT_SKU };
