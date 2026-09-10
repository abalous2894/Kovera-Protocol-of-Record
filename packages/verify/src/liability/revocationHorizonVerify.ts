import {
  REVOCATION_HORIZON_SCHEMA,
  REVOCATION_HORIZON_ATTESTATIONS,
  evaluateRevocationHorizon,
  type RevocationHorizonAttestation,
} from '../core/revocationHorizon.js';

export const REVOCATION_HORIZON_SKU = 'aevesa-revocation-horizon-v1' as const;

export interface RevocationHorizonDocument {
  schema?: string;
  session_id?: string;
  revoke_signal_entry_hash?: string;
  last_permitted_action_entry_hash?: string;
  horizon_ms?: number;
  horizon_ms_observed?: number;
  attestation?: string;
  horizon_digest?: string;
  revoke_signal_timestamp_ms?: number;
  last_permitted_action_timestamp_ms?: number;
}

export interface RevocationHorizonVerifyOptions {
  requireWithinSla?: boolean;
}

export interface RevocationHorizonVerifyChecks {
  schemaValid: boolean;
  sessionIdPresent: boolean;
  revokeHashPresent: boolean;
  horizonMsValid: boolean;
  attestationValid: boolean;
  horizonDigestMatches: boolean;
  withinSla: boolean;
  profileComplete: boolean;
}

export interface RevocationHorizonVerifyResult {
  schema: typeof REVOCATION_HORIZON_SCHEMA;
  sku: typeof REVOCATION_HORIZON_SKU;
  ok: boolean;
  checks: RevocationHorizonVerifyChecks;
  gtmLine: string;
  note: string | null;
}

const HEX64 = /^[a-f0-9]{64}$/;

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

/**
 * Verify revocation horizon witness — standing delegation SLA after revoke signal.
 */
export function verifyRevocationHorizonBundle(
  input: unknown,
  options: RevocationHorizonVerifyOptions = {},
): RevocationHorizonVerifyResult {
  const doc = asRecord(input) as RevocationHorizonDocument | null;
  const schemaValid = doc?.schema === REVOCATION_HORIZON_SCHEMA;
  const session_id = String(doc?.session_id || '').trim();
  const sessionIdPresent = session_id.length > 0;

  const revoke_signal_entry_hash = String(doc?.revoke_signal_entry_hash || '')
    .trim()
    .toLowerCase();
  const revokeHashPresent = HEX64.test(revoke_signal_entry_hash);

  const horizon_ms = Number(doc?.horizon_ms);
  const horizon_ms_observed = Number(doc?.horizon_ms_observed);
  const horizonMsValid =
    Number.isFinite(horizon_ms) &&
    horizon_ms > 0 &&
    Number.isFinite(horizon_ms_observed) &&
    horizon_ms_observed >= 0;

  const attestation = String(doc?.attestation || '').trim() as RevocationHorizonAttestation;
  const attestationValid = REVOCATION_HORIZON_ATTESTATIONS.includes(attestation);

  let horizonDigestMatches = false;
  let withinSla = false;
  if (sessionIdPresent && revokeHashPresent && horizonMsValid) {
    const evalResult = evaluateRevocationHorizon({
      session_id,
      revoke_signal_entry_hash,
      last_permitted_action_entry_hash: doc?.last_permitted_action_entry_hash,
      horizon_ms,
      horizon_ms_observed,
      revoke_signal_timestamp_ms: doc?.revoke_signal_timestamp_ms,
      last_permitted_action_timestamp_ms: doc?.last_permitted_action_timestamp_ms,
    });
    horizonDigestMatches =
      Boolean(doc?.horizon_digest) && doc!.horizon_digest === evalResult.horizon_digest;
    withinSla = evalResult.attestation === 'WITHIN_SLA';
    if (attestationValid && attestation !== evalResult.attestation) {
      horizonDigestMatches = false;
    }
  }

  const requireWithinSla = options.requireWithinSla === true;
  const profileComplete =
    schemaValid &&
    sessionIdPresent &&
    revokeHashPresent &&
    horizonMsValid &&
    attestationValid &&
    horizonDigestMatches &&
    (!requireWithinSla || withinSla);

  let note: string | null = null;
  if (profileComplete) {
    note = withinSla
      ? 'Revocation horizon verified — no permitted actions within observed SLA window after revoke'
      : 'Revocation horizon verified — VIOLATION attested for post-revoke permitted action';
  } else if (!horizonDigestMatches) {
    note = 'horizon_digest does not match revoke signal + observation window';
  } else if (requireWithinSla && !withinSla) {
    note = 'Revocation horizon requires attestation WITHIN_SLA';
  } else {
    note = 'Revocation horizon verification failed';
  }

  return {
    schema: REVOCATION_HORIZON_SCHEMA,
    sku: REVOCATION_HORIZON_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      sessionIdPresent,
      revokeHashPresent,
      horizonMsValid,
      attestationValid,
      horizonDigestMatches,
      withinSla,
      profileComplete,
    },
    gtmLine:
      'IAM revokes tokens. Aevesa witnesses revocation horizon SLA — verifier-grade standing mandate withdrawal.',
    note,
  };
}
