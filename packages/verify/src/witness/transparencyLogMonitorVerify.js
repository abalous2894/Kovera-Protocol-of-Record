/**
 * Track P12 — transparency log monitor status snapshot verification.
 */

import { verifyWitnessConsistencyProof } from './witnessConsistencyVerify.js';

export const TRANSPARENCY_LOG_MONITOR_STATUS_SCHEMA =
  'aevesa.transparency-log-monitor-status/v1';

export const TRANSPARENCY_LOG_MONITOR_SKU = 'aevesa-transparency-log-monitor-v1';

/**
 * @param {unknown} snapshot
 * @param {{ entryDigests?: string[] }} [options]
 */
export function verifyTransparencyLogMonitorStatus(snapshot, options = {}) {
  const doc = snapshot && typeof snapshot === 'object' ? snapshot : null;
  const schemaValid = doc?.schema === TRANSPARENCY_LOG_MONITOR_STATUS_SCHEMA;
  const monitorStateValid = ['healthy', 'degraded', 'unavailable'].includes(
    String(doc?.monitor_state || ''),
  );
  const witnessLogPresent =
    doc?.witness_log != null && typeof doc.witness_log === 'object';

  let consistencyProofValid = true;
  const proof = doc?.consistency_proof_latest;
  const digests = options.entryDigests || [];
  if (proof && typeof proof === 'object') {
    if (digests.length > 0) {
      consistencyProofValid = verifyWitnessConsistencyProof(proof, digests).ok === true;
    } else {
      // Fail closed: consistency proof must be checked against witness log digests.
      consistencyProofValid = false;
    }
  }

  const assertions = doc?.monitor_assertions;
  const assertionsPresent = assertions != null && typeof assertions === 'object';

  const profileComplete =
    schemaValid && monitorStateValid && witnessLogPresent && assertionsPresent;

  const ok = profileComplete && consistencyProofValid;

  let note = null;
  if (!schemaValid) note = 'Invalid monitor status schema.';
  else if (!consistencyProofValid) {
    note =
      proof && digests.length === 0
        ? 'entryDigests required to verify consistency proof — fail closed without witness log binding.'
        : 'Latest consistency proof failed offline verify.';
  }
  else if (!monitorStateValid) note = 'monitor_state must be healthy, degraded, or unavailable.';

  return {
    schema: TRANSPARENCY_LOG_MONITOR_STATUS_SCHEMA,
    sku: TRANSPARENCY_LOG_MONITOR_SKU,
    ok,
    checks: {
      schemaValid,
      monitorStateValid,
      witnessLogPresent,
      consistencyProofValid,
      assertionsPresent,
      profileComplete,
    },
    gtmLine: ok
      ? 'Transparency log monitor status verified — consistency proof checks passed.'
      : 'Transparency log monitor verification failed.',
    note,
  };
}

export default {
  verifyTransparencyLogMonitorStatus,
  TRANSPARENCY_LOG_MONITOR_STATUS_SCHEMA,
  TRANSPARENCY_LOG_MONITOR_SKU,
};
