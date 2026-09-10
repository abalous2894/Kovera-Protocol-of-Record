import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';

export const SHUTDOWN_DRILL_BUNDLE_SCHEMA = 'aevesa.shutdown-drill-bundle/v1' as const;

export const SHUTDOWN_DRILL_LAST_PERMIT_PROFILES = ['PERMITTED', 'HITL_RELEASED'] as const;

export type ShutdownDrillLastPermitProfile = (typeof SHUTDOWN_DRILL_LAST_PERMIT_PROFILES)[number];

export interface ShutdownDrillLastPermit {
  entry_hash: string;
  receipt_profile: ShutdownDrillLastPermitProfile;
  observed_at: string;
}

export interface ShutdownDrillSilenceWindow {
  started_at: string;
  ended_at: string;
  duration_ms: number;
  /** Must be 0 for a passing drill */
  permit_receipt_count: number;
  permit_entry_hashes_observed: string[];
}

export interface ShutdownDrillWitness {
  required: boolean;
  witness_entry_hash?: string | null;
  custodian_countersign_digest?: string | null;
}

export interface ShutdownDrillVerifyManifest {
  offline_cli: string;
  portal_base: string;
  kill_switch_schema: string;
  bundle_schema: string;
}

export interface ShutdownDrillBundleInput {
  drill_id: string;
  organization_id: string;
  target_agent_id: string;
  session_scope?: string | null;
  exported_at?: string;
  last_permit: ShutdownDrillLastPermit;
  kill_switch_attestation: Record<string, unknown>;
  silence_window: ShutdownDrillSilenceWindow;
  witness?: ShutdownDrillWitness;
  verify_manifest: ShutdownDrillVerifyManifest;
  non_goals?: string[];
}



function normalizeWitness(witness: ShutdownDrillWitness | undefined): ShutdownDrillWitness {
  return {
    required: witness?.required === true,
    witness_entry_hash: witness?.witness_entry_hash ?? null,
    custodian_countersign_digest: witness?.custodian_countersign_digest ?? null,
  };
}

function killSwitchEntryHash(attestation: Record<string, unknown>): string {
  const ledger = attestation?.ledger_attestation as Record<string, unknown> | undefined;
  return String(ledger?.entryHash || '').trim().toLowerCase();
}

/**
 * Canonical bundle preimage — excludes bundle_digest and embedded receipt bodies.
 */
export function buildShutdownDrillBundlePreimage(input: ShutdownDrillBundleInput): Record<string, unknown> {
  const witness = normalizeWitness(input.witness);
  const silence = input.silence_window;
  return {
    schema: SHUTDOWN_DRILL_BUNDLE_SCHEMA,
    drill_id: String(input.drill_id || '').trim(),
    organization_id: String(input.organization_id || '').trim(),
    target_agent_id: String(input.target_agent_id || '').trim(),
    session_scope: input.session_scope != null ? String(input.session_scope).trim() : null,
    exported_at: input.exported_at || new Date(0).toISOString(),
    last_permit: {
      entry_hash: String(input.last_permit.entry_hash || '').trim().toLowerCase(),
      receipt_profile: input.last_permit.receipt_profile,
      observed_at: String(input.last_permit.observed_at || ''),
    },
    kill_switch_entry_hash: killSwitchEntryHash(input.kill_switch_attestation),
    silence_window: {
      started_at: String(silence.started_at || ''),
      ended_at: String(silence.ended_at || ''),
      duration_ms: Number(silence.duration_ms),
      permit_receipt_count: Number(silence.permit_receipt_count),
      permit_entry_hashes_observed: [...(silence.permit_entry_hashes_observed || [])]
        .map((h) => String(h).trim().toLowerCase())
        .sort(),
    },
    witness: {
      required: witness.required,
      witness_entry_hash: witness.witness_entry_hash
        ? String(witness.witness_entry_hash).trim().toLowerCase()
        : null,
      custodian_countersign_digest: witness.custodian_countersign_digest
        ? String(witness.custodian_countersign_digest).trim().toLowerCase()
        : null,
    },
    verify_manifest: input.verify_manifest,
    non_goals: input.non_goals ?? [],
  };
}

export function buildShutdownDrillBundleDocument(input: ShutdownDrillBundleInput) {
  const exported_at = input.exported_at || new Date().toISOString();
  const preimage = buildShutdownDrillBundlePreimage({ ...input, exported_at });
  const bundle_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    exported_at,
    kill_switch_attestation: input.kill_switch_attestation,
    bundle_digest,
  };
}

/** Hash-only binding for insurance signal digest drill freshness (Track L6). */
export function buildKillSwitchDrillFreshnessDigest(input: {
  organization_id: string;
  drill_id: string;
  bundle_digest: string;
}): string {
  return sha256HexUtf8(
    stableStringify({
      organization_id: String(input.organization_id || '').trim(),
      drill_id: String(input.drill_id || '').trim(),
      bundle_digest: String(input.bundle_digest || '').trim().toLowerCase(),
    }),
  );
}
