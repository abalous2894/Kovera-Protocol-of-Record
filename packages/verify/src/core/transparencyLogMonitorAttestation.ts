import { sha256HexUtf8 } from './sha256.js';
import { stableStringify } from './stableStringify.js';

/** Track P12 PR2 — monitor attestation for guardian bundles + offline verify. */

export const TRANSPARENCY_LOG_MONITOR_ATTESTATION_SCHEMA =
  'aevesa.transparency-log-monitor-attestation/v1' as const;

export const TRANSPARENCY_LOG_MONITOR_ATTESTATION_SKU =
  'aevesa-transparency-log-monitor-attestation-v1' as const;

export type MonitorAttestationState = 'healthy' | 'degraded' | 'unavailable';

export interface MonitorAttestationConsistencyProof {
  schema: string;
  from_index: number;
  to_index: number;
  entry_count: number;
  root_hash: string;
  log_id: string;
}

export interface MonitorAttestationAssertions {
  consistency_proof_verified: boolean;
  third_party_monitorable: boolean;
  log_enabled?: boolean;
}

export interface TransparencyLogMonitorAttestationInput {
  organization_id?: string | null;
  log_id: string;
  monitor_state: MonitorAttestationState;
  generated_at?: string;
  consistency_proof: MonitorAttestationConsistencyProof;
  monitor_assertions: MonitorAttestationAssertions;
  disclaimer?: string;
}

function normalizeHex64(value: unknown): string {
  return String(value || '').trim().toLowerCase();
}

export function buildTransparencyLogMonitorAttestationPreimage(
  input: TransparencyLogMonitorAttestationInput & { generated_at: string },
): Record<string, unknown> {
  const proof = input.consistency_proof;
  return {
    schema: TRANSPARENCY_LOG_MONITOR_ATTESTATION_SCHEMA,
    organization_id: input.organization_id ? String(input.organization_id).trim() : null,
    log_id: String(input.log_id || '').trim(),
    monitor_state: input.monitor_state,
    generated_at: input.generated_at,
    consistency_proof: {
      schema: String(proof.schema || '').trim(),
      from_index: Number(proof.from_index) || 0,
      to_index: Number(proof.to_index) || 0,
      entry_count: Number(proof.entry_count) || 0,
      root_hash: normalizeHex64(proof.root_hash),
      log_id: String(proof.log_id || '').trim(),
    },
    monitor_assertions: {
      consistency_proof_verified: input.monitor_assertions.consistency_proof_verified === true,
      third_party_monitorable: input.monitor_assertions.third_party_monitorable === true,
      ...(input.monitor_assertions.log_enabled != null
        ? { log_enabled: input.monitor_assertions.log_enabled === true }
        : {}),
    },
    disclaimer:
      input.disclaimer
      ?? 'Transparency log monitor attestation — evidence substrate only; not a certified CT log operator attestation.',
  };
}

export interface TransparencyLogMonitorAttestationDocument {
  schema: typeof TRANSPARENCY_LOG_MONITOR_ATTESTATION_SCHEMA;
  organization_id: string | null;
  log_id: string;
  monitor_state: MonitorAttestationState;
  generated_at: string;
  consistency_proof: MonitorAttestationConsistencyProof;
  monitor_assertions: MonitorAttestationAssertions;
  disclaimer: string;
  attestation_digest: string;
}

export function buildTransparencyLogMonitorAttestationDocument(
  input: TransparencyLogMonitorAttestationInput,
): TransparencyLogMonitorAttestationDocument {
  const generated_at = input.generated_at || new Date().toISOString();
  const preimage = buildTransparencyLogMonitorAttestationPreimage({ ...input, generated_at });
  const attestation_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...(preimage as Omit<TransparencyLogMonitorAttestationDocument, 'attestation_digest'>),
    attestation_digest,
  };
}
