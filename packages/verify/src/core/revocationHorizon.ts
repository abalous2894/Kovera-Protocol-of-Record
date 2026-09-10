import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';

export const REVOCATION_HORIZON_SCHEMA = 'aevesa.revocation-horizon/v1' as const;

export const REVOCATION_HORIZON_ATTESTATIONS = ['WITHIN_SLA', 'VIOLATION'] as const;
export type RevocationHorizonAttestation = (typeof REVOCATION_HORIZON_ATTESTATIONS)[number];

export interface RevocationHorizonInput {
  session_id: string;
  revoke_signal_entry_hash: string;
  last_permitted_action_entry_hash?: string | null;
  horizon_ms: number;
  horizon_ms_observed: number;
  revoke_signal_timestamp_ms?: number;
  last_permitted_action_timestamp_ms?: number | null;
}



const HEX64 = /^[a-f0-9]{64}$/;

function normalizeHex64(v: unknown): string | null {
  const s = String(v ?? '').trim().toLowerCase();
  return HEX64.test(s) ? s : null;
}

/**
 * Witness revocation horizon SLA — zero permitted irreversible actions after revoke within horizon.
 */
export function evaluateRevocationHorizon(input: RevocationHorizonInput): {
  attestation: RevocationHorizonAttestation;
  horizon_digest: string;
} {
  const revokeTs = input.revoke_signal_timestamp_ms;
  const lastPermTs = input.last_permitted_action_timestamp_ms;

  let attestation: RevocationHorizonAttestation = 'WITHIN_SLA';

  if (
    lastPermTs != null &&
    revokeTs != null &&
    Number.isFinite(lastPermTs) &&
    Number.isFinite(revokeTs) &&
    lastPermTs > revokeTs
  ) {
    const delta = lastPermTs - revokeTs;
    if (delta <= input.horizon_ms_observed) {
      attestation = 'VIOLATION';
    }
  }

  const horizon_digest = sha256HexUtf8(
    stableStringify({
      schema: REVOCATION_HORIZON_SCHEMA,
      session_id: String(input.session_id).trim(),
      revoke_signal_entry_hash: normalizeHex64(input.revoke_signal_entry_hash),
      ...(input.last_permitted_action_entry_hash
        ? {
            last_permitted_action_entry_hash: normalizeHex64(
              input.last_permitted_action_entry_hash,
            ),
          }
        : {}),
      horizon_ms: input.horizon_ms,
      horizon_ms_observed: input.horizon_ms_observed,
      attestation,
      ...(revokeTs != null ? { revoke_signal_timestamp_ms: revokeTs } : {}),
      ...(lastPermTs != null ? { last_permitted_action_timestamp_ms: lastPermTs } : {}),
    }),
  );

  return { attestation, horizon_digest };
}

export function buildRevocationHorizonDocument(
  input: RevocationHorizonInput,
): Record<string, unknown> {
  const evalResult = evaluateRevocationHorizon(input);
  return {
    schema: REVOCATION_HORIZON_SCHEMA,
    session_id: String(input.session_id).trim(),
    revoke_signal_entry_hash: normalizeHex64(input.revoke_signal_entry_hash),
    ...(input.last_permitted_action_entry_hash
      ? {
          last_permitted_action_entry_hash: normalizeHex64(
            input.last_permitted_action_entry_hash,
          ),
        }
      : {}),
    horizon_ms: input.horizon_ms,
    horizon_ms_observed: input.horizon_ms_observed,
    attestation: evalResult.attestation,
    horizon_digest: evalResult.horizon_digest,
    ...(input.revoke_signal_timestamp_ms != null
      ? { revoke_signal_timestamp_ms: input.revoke_signal_timestamp_ms }
      : {}),
    ...(input.last_permitted_action_timestamp_ms != null
      ? { last_permitted_action_timestamp_ms: input.last_permitted_action_timestamp_ms }
      : {}),
  };
}
