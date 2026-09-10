/**
 * aevesa.conformance-attestation/v1 — portable lab result + digest for third-party verification.
 */

import { sha256Utf8 } from '../core/sha256.js';
import { stableStringify } from '../core/stableStringify.js';
export const CONFORMANCE_ATTESTATION_SCHEMA = 'aevesa.conformance-attestation/v1';

/**
 * @param {object} attestation — without attestation_digest
 */
export function computeConformanceAttestationDigest(attestation) {
  const clone = { ...attestation };
  delete clone.attestation_digest;
  delete clone.attestationDigest;
  return sha256Utf8(stableStringify(clone));
}

/**
 * @param {{
 *   apiBase?: string | null;
 *   programs: object[];
 *   interop?: object | null;
 *   remote?: object | null;
 *   generatedAt?: string;
 * }} input
 */
export function buildConformanceAttestation(input) {
  const programs = Array.isArray(input.programs) ? input.programs : [];
  const ok = programs.length > 0 && programs.every((p) => p?.ok === true);

  const body = {
    schema: CONFORMANCE_ATTESTATION_SCHEMA,
    sku: 'aevesa-conformance-lab-cli-v1',
    deployment: {
      api_base: input.apiBase ? String(input.apiBase).replace(/\/+$/, '') : null,
      mode: input.apiBase ? 'remote_probe_plus_local' : 'local_only',
    },
    generated_at: input.generatedAt ?? new Date().toISOString(),
    ok,
    programs,
    interop: input.interop ?? null,
    remote: input.remote ?? null,
    verify_hint: 'Re-run: aevesa conformance verify <this-file.json>',
  };

  return {
    ...body,
    attestation_digest: computeConformanceAttestationDigest(body),
  };
}

/**
 * @param {unknown} attestation
 */
export function verifyConformanceAttestation(attestation) {
  const errors = [];
  if (!attestation || typeof attestation !== 'object') {
    return { ok: false, errors: ['attestation must be an object'] };
  }

  const a = /** @type {Record<string, unknown>} */ (attestation);

  if (a.schema !== CONFORMANCE_ATTESTATION_SCHEMA) {
    errors.push(`schema must be ${CONFORMANCE_ATTESTATION_SCHEMA}`);
  }

  const digest = String(a.attestation_digest || a.attestationDigest || '');
  if (!/^[a-f0-9]{64}$/.test(digest)) {
    errors.push('attestation_digest must be 64-char lowercase hex');
  } else {
    const expected = computeConformanceAttestationDigest(a);
    if (expected !== digest) {
      errors.push('attestation_digest mismatch — document may be tampered');
    }
  }

  const programs = a.programs;
  if (!Array.isArray(programs) || programs.length === 0) {
    errors.push('programs array required');
  }

  const interop = a.interop;
  if (interop && typeof interop === 'object') {
    const ih = String(/** @type {Record<string, unknown>} */ (interop).entry_hash || '');
    if (ih && !/^[a-f0-9]{64}$/.test(ih)) {
      errors.push('interop.entry_hash must be 64-char hex when present');
    }
    const local = /** @type {Record<string, unknown>} */ (interop).local;
    if (local && local.ok !== true && a.ok === true) {
      errors.push('interop.local failed but attestation marked ok');
    }
  }

  const declaredOk = a.ok === true;
  const computedOk = Array.isArray(programs) && programs.every((p) => p?.ok === true);
  if (declaredOk !== computedOk) {
    errors.push('ok flag does not match program results');
  }

  return {
    ok: errors.length === 0,
    errors,
    attestation_digest: digest || null,
  };
}

export default {
  CONFORMANCE_ATTESTATION_SCHEMA,
  computeConformanceAttestationDigest,
  buildConformanceAttestation,
  verifyConformanceAttestation,
};
