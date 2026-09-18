import { sha256HexUtf8 } from '../core/sha256.js';
import { SHUTDOWN_DRILL_BUNDLE_SCHEMA, SHUTDOWN_DRILL_LAST_PERMIT_PROFILES, buildShutdownDrillBundlePreimage, type ShutdownDrillLastPermitProfile, type ShutdownDrillVerifyManifest } from '../core/shutdownDrillBundle.js';
import { stableStringify } from '../core/stableStringify.js';
import {
  verifyKillSwitchAttestationBundle,
  type KillSwitchAttestationVerifyOptions,
} from './killSwitchAttestationVerify.js';
import { validateShutdownDrillEnforcementDecay } from './shutdownDrillEnforcementDecay.js';

export const SHUTDOWN_DRILL_BUNDLE_SKU = 'aevesa-shutdown-drill-bundle-v1' as const;

const HEX64 = /^[a-f0-9]{64}$/;
const LAST_PERMIT_PROFILES = new Set<string>(SHUTDOWN_DRILL_LAST_PERMIT_PROFILES);

export interface ShutdownDrillBundleVerifyOptions extends KillSwitchAttestationVerifyOptions {
  /** When true (default), silence window must contain zero permit receipts */
  requireSilenceWindow?: boolean;
  /** When true (default), enforce temporal ordering last_permit → kill → silence start */
  requireTemporalOrdering?: boolean;
}

export interface ShutdownDrillBundleVerifyChecks {
  schemaValid: boolean;
  organizationIdPresent: boolean;
  targetAgentPresent: boolean;
  bundleDigestMatches: boolean;
  lastPermitValid: boolean;
  killSwitchAttestationValid: boolean;
  killSwitchAgentMatches: boolean;
  silenceWindowValid: boolean;
  silenceWindowProven: boolean;
  witnessValid: boolean;
  temporalOrderingValid: boolean;
  enforcementDecayValid: boolean;
  profileComplete: boolean;
}

export interface ShutdownDrillBundleVerifyResult {
  schema: typeof SHUTDOWN_DRILL_BUNDLE_SCHEMA;
  sku: typeof SHUTDOWN_DRILL_BUNDLE_SKU;
  ok: boolean;
  checks: ShutdownDrillBundleVerifyChecks;
  kill_switch: ReturnType<typeof verifyKillSwitchAttestationBundle> | null;
  gtmLine: string;
  note: string | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function parseVerifyManifest(raw: unknown): ShutdownDrillVerifyManifest {
  const m = asRecord(raw);
  return {
    offline_cli: String(m?.offline_cli || 'npx @aevesa/verify'),
    portal_base: String(m?.portal_base || 'https://verify.aevesa.com'),
    kill_switch_schema: String(m?.kill_switch_schema || 'aevesa.kill-switch-attestation/v1'),
    bundle_schema: SHUTDOWN_DRILL_BUNDLE_SCHEMA,
  };
}

function parseIsoMs(value: unknown): number | null {
  const ms = Date.parse(String(value || ''));
  return Number.isFinite(ms) ? ms : null;
}

/**
 * Verify shutdown-drill bundle — kill-switch attestation + receipt silence window (+ optional witness).
 */
export function verifyShutdownDrillBundle(
  input: unknown,
  options: ShutdownDrillBundleVerifyOptions = {},
): ShutdownDrillBundleVerifyResult {
  const doc = asRecord(input);
  const schemaValid = doc?.schema === SHUTDOWN_DRILL_BUNDLE_SCHEMA;

  const organization_id = String(doc?.organization_id || '').trim();
  const organizationIdPresent = organization_id.length > 0;

  const target_agent_id = String(doc?.target_agent_id || '').trim();
  const targetAgentPresent = target_agent_id.length > 0;

  const lastPermitRaw = asRecord(doc?.last_permit);
  const lastEntry = String(lastPermitRaw?.entry_hash || '').trim().toLowerCase();
  const lastProfile = String(lastPermitRaw?.receipt_profile || '').trim();
  const lastPermitValid =
    HEX64.test(lastEntry) &&
    LAST_PERMIT_PROFILES.has(lastProfile) &&
    parseIsoMs(lastPermitRaw?.observed_at) != null;

  const killSwitchDoc = asRecord(doc?.kill_switch_attestation);
  const killSwitchVerify = killSwitchDoc
    ? verifyKillSwitchAttestationBundle(killSwitchDoc, options)
    : null;
  const killSwitchAttestationValid = killSwitchVerify?.ok === true;

  const killPayload = asRecord(killSwitchDoc?.payload);
  const killAgent = String(killPayload?.targetAgentId || killSwitchDoc?.agent_id || '').trim();
  const killSwitchAgentMatches =
    !targetAgentPresent || !killAgent || killAgent === target_agent_id;

  const silenceRaw = asRecord(doc?.silence_window);
  const startedMs = parseIsoMs(silenceRaw?.started_at);
  const endedMs = parseIsoMs(silenceRaw?.ended_at);
  const durationMs = Number(silenceRaw?.duration_ms);
  const permitCount = Number(silenceRaw?.permit_receipt_count);
  const observedHashes = Array.isArray(silenceRaw?.permit_entry_hashes_observed)
    ? silenceRaw.permit_entry_hashes_observed.map(String)
    : null;

  const durationMatches =
    startedMs != null &&
    endedMs != null &&
    endedMs > startedMs &&
    (Math.abs(endedMs - startedMs - durationMs) <= 1000 || durationMs === endedMs - startedMs);

  const observedHashesValid =
    observedHashes == null || observedHashes.every((h) => HEX64.test(String(h).trim().toLowerCase()));

  const requireSilence = options.requireSilenceWindow !== false;
  const silenceWindowProven =
    !requireSilence ||
    (permitCount === 0 &&
      (observedHashes == null || observedHashes.length === 0) &&
      observedHashesValid === true);

  const silenceWindowValid =
    startedMs != null && endedMs != null && endedMs > startedMs && durationMatches && observedHashesValid;

  const witnessRaw = asRecord(doc?.witness);
  const witnessRequired = witnessRaw?.required === true;
  const witnessHash = String(witnessRaw?.witness_entry_hash || '').trim().toLowerCase();
  const custodianDigest = String(witnessRaw?.custodian_countersign_digest || '').trim().toLowerCase();
  const witnessValid =
    !witnessRequired ||
    (HEX64.test(witnessHash) &&
      (custodianDigest.length === 0 || HEX64.test(custodianDigest)));

  const requireOrdering = options.requireTemporalOrdering !== false;
  const lastAt = parseIsoMs(lastPermitRaw?.observed_at);
  const killAt = parseIsoMs(killPayload?.at);
  const temporalOrderingValid =
    !requireOrdering ||
    (lastAt != null &&
      killAt != null &&
      startedMs != null &&
      lastAt <= killAt &&
      killAt <= startedMs);

  const enforcementDecayRaw = doc?.enforcement_decay;
  const enforcementDecayCheck = validateShutdownDrillEnforcementDecay(
    enforcementDecayRaw,
    doc?.session_scope != null ? String(doc.session_scope) : null,
  );
  const enforcementDecayValid = enforcementDecayCheck.ok === true;

  let bundleDigestMatches = false;
  if (schemaValid && doc && killSwitchDoc) {
    const decayRecord =
      enforcementDecayRaw != null && typeof enforcementDecayRaw === 'object' && !Array.isArray(enforcementDecayRaw)
        ? (enforcementDecayRaw as Record<string, unknown>)
        : null;
    const preimage = buildShutdownDrillBundlePreimage({
      drill_id: String(doc.drill_id || ''),
      organization_id,
      target_agent_id,
      session_scope: doc.session_scope != null ? String(doc.session_scope) : null,
      exported_at: String(doc.exported_at || ''),
      last_permit: {
        entry_hash: lastEntry,
        receipt_profile: lastProfile as ShutdownDrillLastPermitProfile,
        observed_at: String(lastPermitRaw?.observed_at || ''),
      },
      kill_switch_attestation: killSwitchDoc,
      silence_window: {
        started_at: String(silenceRaw?.started_at || ''),
        ended_at: String(silenceRaw?.ended_at || ''),
        duration_ms: durationMs,
        permit_receipt_count: permitCount,
        permit_entry_hashes_observed: observedHashes || [],
      },
      witness: {
        required: witnessRequired,
        witness_entry_hash: witnessHash || null,
        custodian_countersign_digest: custodianDigest || null,
      },
      verify_manifest: parseVerifyManifest(doc.verify_manifest),
      non_goals: Array.isArray(doc.non_goals) ? doc.non_goals.map(String) : [],
      enforcement_decay: decayRecord
        ? {
            schema: String(decayRecord.schema || ''),
            session_id: decayRecord.session_id != null ? String(decayRecord.session_id) : null,
            pre_drill_chain_enforcement_mode: String(decayRecord.pre_drill_chain_enforcement_mode || ''),
            pre_drill_weakest_link_index:
              decayRecord.pre_drill_weakest_link_index != null
                ? Number(decayRecord.pre_drill_weakest_link_index)
                : null,
            post_kill_switch_effective_mode: String(decayRecord.post_kill_switch_effective_mode || ''),
            decay_note: String(decayRecord.decay_note || ''),
            chain_enforcement_rollup_schema: String(decayRecord.chain_enforcement_rollup_schema || ''),
          }
        : null,
    });
    const expected = sha256HexUtf8(stableStringify(preimage));
    bundleDigestMatches = String(doc.bundle_digest || '') === expected;
  }

  const profileComplete =
    schemaValid &&
    organizationIdPresent &&
    targetAgentPresent &&
    bundleDigestMatches &&
    lastPermitValid &&
    killSwitchAttestationValid &&
    killSwitchAgentMatches &&
    silenceWindowValid &&
    silenceWindowProven &&
    witnessValid &&
    temporalOrderingValid &&
    enforcementDecayValid;

  const ok = profileComplete;

  let note: string | null = null;
  if (!schemaValid) note = `schema must be ${SHUTDOWN_DRILL_BUNDLE_SCHEMA}`;
  else if (!enforcementDecayValid) note = enforcementDecayCheck.note || 'enforcement_decay invalid';
  else if (!bundleDigestMatches) note = 'bundle_digest does not match canonical preimage';
  else if (!lastPermitValid) note = 'last_permit requires hex entry_hash, PERMITTED/HITL_RELEASED profile, observed_at';
  else if (!killSwitchAttestationValid) note = killSwitchVerify?.note || 'kill_switch_attestation verification failed';
  else if (!killSwitchAgentMatches) note = 'kill_switch target agent must match bundle target_agent_id';
  else if (!silenceWindowValid) note = 'silence_window timestamps or duration_ms invalid';
  else if (!silenceWindowProven) note = 'silence_window must show zero permit receipts during drill window';
  else if (!witnessValid) note = 'witness.required=true but witness_entry_hash missing or invalid';
  else if (!temporalOrderingValid) note = 'temporal ordering requires last_permit ≤ kill engage ≤ silence start';

  return {
    schema: SHUTDOWN_DRILL_BUNDLE_SCHEMA,
    sku: SHUTDOWN_DRILL_BUNDLE_SKU,
    ok,
    checks: {
      schemaValid,
      organizationIdPresent,
      targetAgentPresent,
      bundleDigestMatches,
      lastPermitValid,
      killSwitchAttestationValid,
      killSwitchAgentMatches,
      silenceWindowValid,
      silenceWindowProven,
      witnessValid,
      temporalOrderingValid,
      enforcementDecayValid,
      profileComplete,
    },
    kill_switch: killSwitchVerify,
    gtmLine:
      'Platforms claim a kill switch. Aevesa proves you used it, receipts stopped, and a witness can countersign the gap.',
    note,
  };
}
