import { sha256HexUtf8 } from '../core/sha256.js';
import { FLIGHT_RECORDER_EXPORT_SCHEMA, FLIGHT_RECORDER_EXPORT_SKU, FLIGHT_RECORDER_EXPORT_PROFILES, FLIGHT_RECORDER_FORBIDDEN_CONTENT_KEYS, ISO24970_CROSSWALK_VERSION, SCITT_AIR_PROFILE_REF, buildFlightRecorderExportPreimage, type FlightRecorderExportProfile, type FlightRecorderVerifyManifest } from '../core/flightRecorderExport.js';
import { stableStringify } from '../core/stableStringify.js';

export { FLIGHT_RECORDER_EXPORT_SKU };

const HEX64 = /^[a-f0-9]{64}$/;
const ISO_MS = (value: unknown) => {
  const ms = Date.parse(String(value || ''));
  return Number.isFinite(ms) ? ms : null;
};
const QUARTER_RE = /^\d{4}-Q[1-4]$/;
const EVENT_CATEGORIES = new Set([
  'agent_action',
  'policy_decision',
  'human_oversight',
  'refusal',
  'governance',
]);

export interface FlightRecorderExportVerifyChecks {
  schemaValid: boolean;
  organizationIdPresent: boolean;
  sessionIdPresent: boolean;
  exportDigestMatches: boolean;
  exportProfileValid: boolean;
  crosswalkVersionPresent: boolean;
  eventsPresent: boolean;
  eventsOrdered: boolean;
  eventsIso24970Complete: boolean;
  hashOnlyProfileClean: boolean;
  crosswalkGapsDocumented: boolean;
  quarterlyHookValid: boolean;
  verifyManifestPresent: boolean;
  profileComplete: boolean;
}

export interface FlightRecorderExportVerifyResult {
  schema: typeof FLIGHT_RECORDER_EXPORT_SCHEMA;
  sku: typeof FLIGHT_RECORDER_EXPORT_SKU;
  ok: boolean;
  checks: FlightRecorderExportVerifyChecks;
  eventCount: number;
  crosswalkGapCount: number;
  gtmLine: string;
  note: string | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function parseVerifyManifest(raw: unknown): FlightRecorderVerifyManifest {
  const m = asRecord(raw);
  return {
    offline_cli: String(m?.offline_cli || 'npx @aevesa/verify'),
    portal_base: String(m?.portal_base || 'https://verify.aevesa.com'),
    export_schema: String(m?.export_schema || FLIGHT_RECORDER_EXPORT_SCHEMA),
    iso24970_crosswalk_doc: String(
      m?.iso24970_crosswalk_doc || 'docs/standards/ISO_IEC_24970_CROSSWALK.md',
    ),
    scitt_air_profile_doc: String(
      m?.scitt_air_profile_doc || 'docs/standards/SCITT_AIR_PROFILE_ALIGNMENT.md',
    ),
    quarterly_review_schema: String(
      m?.quarterly_review_schema || 'aevesa.quarterly-review-export/v1',
    ),
  };
}

function collectForbiddenKeys(value: unknown, path = '', found: string[] = []): string[] {
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i += 1) {
      collectForbiddenKeys(value[i], `${path}[${i}]`, found);
    }
    return found;
  }
  if (value != null && typeof value === 'object') {
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      const nextPath = path ? `${path}.${key}` : key;
      if (FLIGHT_RECORDER_FORBIDDEN_CONTENT_KEYS.includes(key as (typeof FLIGHT_RECORDER_FORBIDDEN_CONTENT_KEYS)[number])) {
        found.push(nextPath);
      }
      collectForbiddenKeys(child, nextPath, found);
    }
  }
  return found;
}

function verifyEventsIso24970(events: unknown[], sessionId: string): boolean {
  if (!events.length) return false;
  return events.every((raw, idx) => {
    const row = asRecord(raw);
    const iso = asRecord(row?.iso24970);
    if (!row || !iso) return false;
    const seq = Number(row.sequence);
    const entry = String(row.entry_hash || '').trim().toLowerCase();
    const category = String(iso.event_category || '');
    const sessionBinding = String(iso.session_binding || '').trim();
    return (
      Number.isFinite(seq) &&
      seq === idx + 1 &&
      HEX64.test(entry) &&
      ISO_MS(iso.timestamp) != null &&
      ISO_MS(row.issued_at) != null &&
      EVENT_CATEGORIES.has(category) &&
      String(iso.action || '').trim().length > 0 &&
      String(iso.authorization_decision || '').trim().length > 0 &&
      sessionBinding.length > 0 &&
      sessionBinding === sessionId
    );
  });
}

/**
 * Verify flight-recorder export — ISO 24970 crosswalk self-check + hash-only profile guard.
 */
export function verifyFlightRecorderExport(input: unknown): FlightRecorderExportVerifyResult {
  const doc = asRecord(input);
  const schemaValid = doc?.schema === FLIGHT_RECORDER_EXPORT_SCHEMA;

  const organization_id = String(doc?.organization_id || '').trim();
  const organizationIdPresent = organization_id.length > 0;

  const session_id = String(doc?.session_id || '').trim();
  const sessionIdPresent = session_id.length > 0;

  const export_profile = String(doc?.export_profile || 'hash_only') as FlightRecorderExportProfile;
  const exportProfileValid = (FLIGHT_RECORDER_EXPORT_PROFILES as readonly string[]).includes(
    export_profile,
  );

  const crosswalkVersionPresent =
    String(doc?.iso24970_crosswalk_version || '').trim() === ISO24970_CROSSWALK_VERSION;

  const events = Array.isArray(doc?.events) ? doc.events : [];
  const eventsPresent = events.length > 0;
  const eventsOrdered = eventsPresent && verifyEventsIso24970(events, session_id);
  const eventsIso24970Complete = eventsOrdered;

  const forbidden = export_profile === 'hash_only' ? collectForbiddenKeys(doc) : [];
  const hashOnlyProfileClean = forbidden.length === 0;

  const gaps = Array.isArray(doc?.crosswalk_gaps) ? doc.crosswalk_gaps : [];
  const crosswalkGapsDocumented = gaps.every((g) => String(g || '').trim().length > 0);

  const hook = asRecord(doc?.quarterly_review_hook);
  const quarter = hook?.quarter != null ? String(hook.quarter).trim() : null;
  const qDigest =
    hook?.quarterly_export_digest != null
      ? String(hook.quarterly_export_digest).trim().toLowerCase()
      : null;
  const quarterlyHookValid =
    hook != null &&
    (quarter == null || QUARTER_RE.test(quarter)) &&
    (qDigest == null || HEX64.test(qDigest));

  const manifest = parseVerifyManifest(doc?.verify_manifest);
  const verifyManifestPresent =
    manifest.export_schema === FLIGHT_RECORDER_EXPORT_SCHEMA &&
    manifest.quarterly_review_schema === 'aevesa.quarterly-review-export/v1';

  let exportDigestMatches = false;
  if (schemaValid && organizationIdPresent && sessionIdPresent) {
    const expected = buildFlightRecorderExportPreimage({
      organization_id,
      session_id,
      exported_at: String(doc?.exported_at || ''),
      export_profile,
      iso24970_crosswalk_version: String(doc?.iso24970_crosswalk_version || ISO24970_CROSSWALK_VERSION),
      scitt_air_profile: String(doc?.scitt_air_profile || SCITT_AIR_PROFILE_REF),
      events: events as never[],
      quarterly_review_hook: hook as never,
      crosswalk_gaps: gaps.map((g) => String(g)),
      verify_manifest: manifest,
      non_goals: Array.isArray(doc?.non_goals) ? doc.non_goals.map(String) : [],
    });
    const digest = String(doc?.export_digest || '').trim().toLowerCase();
    exportDigestMatches = HEX64.test(digest) && digest === sha256HexUtf8(stableStringify(expected));
  }

  const checks: FlightRecorderExportVerifyChecks = {
    schemaValid,
    organizationIdPresent,
    sessionIdPresent,
    exportDigestMatches,
    exportProfileValid,
    crosswalkVersionPresent,
    eventsPresent,
    eventsOrdered,
    eventsIso24970Complete,
    hashOnlyProfileClean,
    crosswalkGapsDocumented,
    quarterlyHookValid,
    verifyManifestPresent,
    profileComplete:
      schemaValid &&
      organizationIdPresent &&
      sessionIdPresent &&
      exportDigestMatches &&
      exportProfileValid &&
      crosswalkVersionPresent &&
      eventsPresent &&
      eventsIso24970Complete &&
      hashOnlyProfileClean &&
      crosswalkGapsDocumented &&
      quarterlyHookValid &&
      verifyManifestPresent,
  };

  const ok = checks.profileComplete;
  let note: string | null = null;
  if (!schemaValid) note = 'schema must be aevesa.flight-recorder-export/v1';
  else if (!exportDigestMatches) note = 'export_digest does not match canonical preimage';
  else if (!hashOnlyProfileClean) note = `hash_only profile forbids content keys: ${forbidden.join(', ')}`;
  else if (!eventsIso24970Complete) note = 'events must be sequence-ordered with complete iso24970 fields';
  else if (!crosswalkVersionPresent) note = `iso24970_crosswalk_version must be ${ISO24970_CROSSWALK_VERSION}`;

  return {
    schema: FLIGHT_RECORDER_EXPORT_SCHEMA,
    sku: FLIGHT_RECORDER_EXPORT_SKU,
    ok,
    checks,
    eventCount: events.length,
    crosswalkGapCount: gaps.length,
    gtmLine:
      'Art. 12 asks for logs. Aevesa exports a flight recorder your examiner verifies without your SaaS login.',
    note,
  };
}
