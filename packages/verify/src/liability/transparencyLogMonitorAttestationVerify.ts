import { sha256HexUtf8 } from '../core/sha256.js';
import { stableStringify } from '../core/stableStringify.js';
import {
  TRANSPARENCY_LOG_MONITOR_ATTESTATION_SCHEMA,
  TRANSPARENCY_LOG_MONITOR_ATTESTATION_SKU,
  buildTransparencyLogMonitorAttestationPreimage,
  type MonitorAttestationState,
  type TransparencyLogMonitorAttestationDocument,
} from '../core/transparencyLogMonitorAttestation.js';

import { verifyWitnessConsistencyProof } from '../witness/witnessConsistencyVerify.js';

export type { TransparencyLogMonitorAttestationDocument };

export interface TransparencyLogMonitorAttestationVerifyOptions {
  entryDigests?: string[];
  requireHealthyState?: boolean;
}

export interface TransparencyLogMonitorAttestationVerifyResult {
  schema: typeof TRANSPARENCY_LOG_MONITOR_ATTESTATION_SCHEMA;
  sku: typeof TRANSPARENCY_LOG_MONITOR_ATTESTATION_SKU;
  ok: boolean;
  checks: {
    schemaValid: boolean;
    logIdPresent: boolean;
    monitorStateValid: boolean;
    consistencyProofPresent: boolean;
    consistencyProofVerified: boolean;
    attestationDigestMatches: boolean;
    assertionsPresent: boolean;
    profileComplete: boolean;
  };
  gtmLine: string;
  note: string | null;
}

export function verifyTransparencyLogMonitorAttestation(
  input: unknown,
  options: TransparencyLogMonitorAttestationVerifyOptions = {},
): TransparencyLogMonitorAttestationVerifyResult {
  const doc = input != null && typeof input === 'object' && !Array.isArray(input)
    ? (input as TransparencyLogMonitorAttestationDocument)
    : null;

  const schemaValid = doc?.schema === TRANSPARENCY_LOG_MONITOR_ATTESTATION_SCHEMA;
  const logIdPresent = String(doc?.log_id || '').trim().length > 0;
  const monitorStateValid = ['healthy', 'degraded', 'unavailable'].includes(
    String(doc?.monitor_state || ''),
  );
  const consistencyProofPresent =
    doc?.consistency_proof != null && typeof doc.consistency_proof === 'object';

  const hasEntryDigests =
    Array.isArray(options.entryDigests) && options.entryDigests.length > 0;

  let consistencyProofVerified = false;
  if (consistencyProofPresent && hasEntryDigests) {
    consistencyProofVerified =
      verifyWitnessConsistencyProof(doc!.consistency_proof, options.entryDigests!).ok === true;
  }

  let attestationDigestMatches = false;
  if (schemaValid && doc?.generated_at && doc.consistency_proof && doc.monitor_assertions) {
    const expected = sha256HexUtf8(
      stableStringify(
        buildTransparencyLogMonitorAttestationPreimage({
          organization_id: doc.organization_id ?? null,
          log_id: String(doc.log_id),
          monitor_state: doc.monitor_state as MonitorAttestationState,
          generated_at: String(doc.generated_at),
          consistency_proof: doc.consistency_proof as never,
          monitor_assertions: doc.monitor_assertions as never,
          disclaimer: doc.disclaimer,
        }),
      ),
    );
    attestationDigestMatches = Boolean(doc.attestation_digest) && doc.attestation_digest === expected;
  }

  const assertionsPresent =
    doc?.monitor_assertions != null && typeof doc.monitor_assertions === 'object';

  const stateOk =
    options.requireHealthyState !== true
    || doc?.monitor_state === 'healthy';

  const profileComplete =
    schemaValid
    && logIdPresent
    && monitorStateValid
    && consistencyProofPresent
    && consistencyProofVerified
    && attestationDigestMatches
    && assertionsPresent
    && stateOk;

  let note: string | null = null;
  if (!schemaValid) note = 'Invalid monitor attestation schema.';
  else if (!attestationDigestMatches) note = 'attestation_digest mismatch.';
  else if (!consistencyProofVerified) {
    note = hasEntryDigests
      ? 'consistency proof not verified against witness log digests.'
      : 'entryDigests required to verify consistency proof — fail closed without witness log binding.';
  }
  else if (!stateOk) note = 'monitor_state must be healthy when requireHealthyState is set.';

  return {
    schema: TRANSPARENCY_LOG_MONITOR_ATTESTATION_SCHEMA,
    sku: TRANSPARENCY_LOG_MONITOR_ATTESTATION_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      logIdPresent,
      monitorStateValid,
      consistencyProofPresent,
      consistencyProofVerified,
      attestationDigestMatches,
      assertionsPresent,
      profileComplete,
    },
    gtmLine: profileComplete
      ? 'Transparency log monitor attestation verified — consistency proof bound for guardian bundle export.'
      : 'Transparency log monitor attestation verification failed.',
    note,
  };
}

export default {
  verifyTransparencyLogMonitorAttestation,
  TRANSPARENCY_LOG_MONITOR_ATTESTATION_SKU,
};
