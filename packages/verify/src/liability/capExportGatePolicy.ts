import { isRecord } from '../core/isRecord.js';

/** HTTP cap-bundle export gate semantics — bump version when default enforcement changes. */
export const CAP_EXPORT_GATE_POLICY_SCHEMA = 'aevesa.cap-export-gate-policy/v1' as const;

/** Current cap-bundle gate profile (James Sep 2026 — requireCarrierReady default ON). */
export const CAP_EXPORT_GATE_POLICY_VERSION = 'carrier_default_v1' as const;

/** Floor integrators compare against — reject bodies below this, not equality to `version`. */
export const CAP_EXPORT_GATE_POLICY_MIN_SUPPORTED_VERSION = CAP_EXPORT_GATE_POLICY_VERSION;

export const CAP_EXPORT_GATE_POLICY_EFFECTIVE_FROM = '2026-09-12' as const;

const GATE_POLICY_VERSION_RE = /^carrier_default_v(\d+)$/;

export interface CapExportGatePolicyInput {
  /** Mirrors `?requireCarrierReady=` on GET cap-bundle (default true). */
  require_carrier_ready_applied?: boolean;
}

export interface CapExportGatePolicy {
  schema: typeof CAP_EXPORT_GATE_POLICY_SCHEMA;
  version: typeof CAP_EXPORT_GATE_POLICY_VERSION | string;
  min_supported_version: typeof CAP_EXPORT_GATE_POLICY_MIN_SUPPORTED_VERSION | string;
  effective_from: string;
  require_carrier_ready_default: true;
  require_carrier_ready_applied: boolean;
  stale_body_note: string;
}

/** Parse `carrier_default_vN` revision, or null when unknown. */
export function parseCapExportGatePolicyRevision(version: unknown): number | null {
  const m = String(version ?? '').trim().match(GATE_POLICY_VERSION_RE);
  if (!m) return null;
  const n = Number(m[1]);
  return Number.isFinite(n) ? n : null;
}

/** True when `version` meets or exceeds `minSupported` (James — floor, not exact pin). */
export function isCapExportGatePolicySupported(
  version: unknown,
  minSupported: string = CAP_EXPORT_GATE_POLICY_MIN_SUPPORTED_VERSION,
): boolean {
  const minRev = parseCapExportGatePolicyRevision(minSupported);
  const rev = parseCapExportGatePolicyRevision(version);
  if (minRev == null || rev == null) return false;
  return rev >= minRev;
}

/**
 * Machine-readable stamp for cap-bundle HTTP envelopes.
 * Integrators: missing policy or version below `min_supported_version` ⇒ stale pre-flip body.
 */
export function buildCapExportGatePolicy(
  input: CapExportGatePolicyInput = {},
): CapExportGatePolicy {
  const require_carrier_ready_applied = input.require_carrier_ready_applied !== false;
  return {
    schema: CAP_EXPORT_GATE_POLICY_SCHEMA,
    version: CAP_EXPORT_GATE_POLICY_VERSION,
    min_supported_version: CAP_EXPORT_GATE_POLICY_MIN_SUPPORTED_VERSION,
    effective_from: CAP_EXPORT_GATE_POLICY_EFFECTIVE_FROM,
    require_carrier_ready_default: true,
    require_carrier_ready_applied,
    stale_body_note: require_carrier_ready_applied
      ? 'Reject cached bodies when export_gate_policy is missing or version is below min_supported_version — re-fetch before carrier handoff.'
      : 'Diagnostic opt-out (?requireCarrierReady=0) — not a carrier-handoff profile.',
  };
}

/** True when a cached cap-bundle body lacks a supported export gate policy (pre-min or missing). */
export function isCapExportEnvelopeStale(cached: unknown): boolean {
  if (!isRecord(cached)) return true;
  const policy = cached.export_gate_policy;
  if (!isRecord(policy)) return true;
  if (policy.schema !== CAP_EXPORT_GATE_POLICY_SCHEMA) return true;

  const localFloor = CAP_EXPORT_GATE_POLICY_MIN_SUPPORTED_VERSION;
  if (!isCapExportGatePolicySupported(policy.version, localFloor)) {
    return true;
  }

  const claimedMin = String(policy.min_supported_version ?? '').trim();
  if (claimedMin) {
    const localRev = parseCapExportGatePolicyRevision(localFloor);
    const claimedRev = parseCapExportGatePolicyRevision(claimedMin);
    if (localRev != null && claimedRev != null && claimedRev < localRev) {
      return true;
    }
  }

  return false;
}
