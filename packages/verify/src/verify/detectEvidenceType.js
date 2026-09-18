/**
 * Auto-detect evidence artifact type for unified aevesa verify.
 */

export const EVIDENCE_KINDS = [
  'entry_hash',
  'liability_receipt',
  'proof_of_action_bundle',
  'policy_proof_bundle',
  'session_proof_bundle',
  'channel_provenance',
  'session_payload_gate',
  'aeg_integrity',
  'constraint_closure',
  'hitl_preimage_binding',
  'execution_surface_completeness',
  'provable_execution_boundary',
  'behavioral_sbom',
  'revocation_horizon',
  'conformity_closure',
  'declared_adaptation_envelope',
  'substantial_modification_signal',
  'adaptation_lifecycle_export',
  'evidence_resurrection_batch',
  'license_survivable_bundle',
  'independent_guardian_bundle',
  'transparency_log_monitor_attestation',
  'transparency_log_monitor_status',
  'proof_strength_disclosure',
  'egress_attestation',
  'egress_proxy_attribution',
  'egress_proxy_collector_envelope',
  'conformance_attestation',
  'scitt_witness_export',
  'auditor_packet',
  'unknown',
];

/**
 * @param {unknown} obj
 */
export function isProofOfActionBundle(obj) {
  if (!obj || typeof obj !== 'object') return false;
  const o = /** @type {Record<string, unknown>} */ (obj);
  if (o.proof_of_action_format_version) return true;
  if (o.manifest && typeof o.manifest === 'object') {
    const m = /** @type {Record<string, unknown>} */ (o.manifest);
    if (m.bundle_kind === 'proof_of_action') return true;
    if (m.schema === 'aevesa.proof-of-action-bundle/v1') return true;
    if (m.entry_hash && m.proof_profile) return true;
  }
  if (o.bundle_id && o.manifest) return true;
  return false;
}

/**
 * @param {object} obj
 */
export function normalizeProofBundleInput(obj) {
  if (obj?.bundle && typeof obj.bundle === 'object' && isProofOfActionBundle(obj.bundle)) {
    return /** @type {object} */ (obj.bundle);
  }
  if (obj?.ok === true && obj?.bundle && typeof obj.bundle === 'object') {
    return /** @type {object} */ (obj.bundle);
  }
  return obj;
}

/**
 * @param {unknown} input — JSON object or raw string (JSON or 64-char hex)
 */
export function detectEvidenceType(input) {
  if (typeof input === 'string') {
    const t = input.trim();
    if (!t) {
      return { kind: 'unknown', error: 'empty input' };
    }
    if (/^[a-f0-9]{64}$/i.test(t)) {
      return { kind: 'entry_hash', entryHash: t.toLowerCase(), payload: null };
    }
    try {
      return detectEvidenceType(JSON.parse(t));
    } catch {
      return { kind: 'unknown', error: 'invalid JSON or entry hash' };
    }
  }

  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { kind: 'unknown', error: 'expected JSON object' };
  }

  const obj = /** @type {Record<string, unknown>} */ (input);
  const schema = String(obj.schema || '');

  if (schema === 'aevesa.compositional-accountability/v1') {
    return { kind: 'session_proof_bundle', payload: obj };
  }
  if (schema === 'aevesa.channel-provenance/v1') {
    return { kind: 'channel_provenance', payload: obj };
  }
  if (schema === 'aevesa.session-payload-gate/v1') {
    return { kind: 'session_payload_gate', payload: obj };
  }
  if (schema === 'aevesa.aeg-integrity/v1') {
    return { kind: 'aeg_integrity', payload: obj };
  }
  if (schema === 'aevesa.constraint-closure/v1') {
    return { kind: 'constraint_closure', payload: obj };
  }
  if (schema === 'aevesa.hitl-preimage-binding/v1') {
    return { kind: 'hitl_preimage_binding', payload: obj };
  }
  if (schema === 'aevesa.execution-surface-completeness/v1') {
    return { kind: 'execution_surface_completeness', payload: obj };
  }
  if (schema === 'aevesa.provable-execution-boundary/v1') {
    return { kind: 'provable_execution_boundary', payload: obj };
  }
  if (schema === 'aevesa.behavioral-sbom/v1') {
    return { kind: 'behavioral_sbom', payload: obj };
  }
  if (schema === 'aevesa.conformity-closure/v1') {
    return { kind: 'conformity_closure', payload: obj };
  }
  if (schema === 'aevesa.declared-adaptation-envelope/v1-draft') {
    return { kind: 'declared_adaptation_envelope', payload: obj };
  }
  if (schema === 'aevesa.substantial-modification-signal/v1') {
    return { kind: 'substantial_modification_signal', payload: obj };
  }
  if (schema === 'aevesa.adaptation-lifecycle-export/v1') {
    return { kind: 'adaptation_lifecycle_export', payload: obj };
  }
  if (schema === 'aevesa.evidence-resurrection-batch/v1') {
    return { kind: 'evidence_resurrection_batch', payload: obj };
  }
  if (schema === 'aevesa.license-survivable-bundle/v1') {
    return { kind: 'license_survivable_bundle', payload: obj };
  }
  if (schema === 'aevesa.independent-guardian-bundle/v1') {
    return { kind: 'independent_guardian_bundle', payload: obj };
  }
  if (schema === 'aevesa.transparency-log-monitor-attestation/v1') {
    return { kind: 'transparency_log_monitor_attestation', payload: obj };
  }
  if (schema === 'aevesa.transparency-log-monitor-status/v1') {
    return { kind: 'transparency_log_monitor_status', payload: obj };
  }
  if (schema === 'aevesa.proof-strength-disclosure/v1') {
    return { kind: 'proof_strength_disclosure', payload: obj };
  }
  if (schema === 'aevesa.egress-attestation/v1' || schema === 'aevesa.egress-attestation/v2') {
    return { kind: 'egress_attestation', payload: obj };
  }
  if (schema === 'aevesa.egress-proxy-attribution/v1') {
    return { kind: 'egress_proxy_attribution', payload: obj };
  }
  if (schema === 'aevesa.egress-proxy-collector-envelope/v1') {
    return { kind: 'egress_proxy_collector_envelope', payload: obj };
  }
  if (schema === 'aevesa.revocation-horizon/v1') {
    return { kind: 'revocation_horizon', payload: obj };
  }
  if (schema === 'liability-receipt/v1') {
    return { kind: 'liability_receipt', payload: obj };
  }
  if (schema === 'aevesa.policy-proof-bundle/v1') {
    return { kind: 'policy_proof_bundle', payload: obj };
  }
  if (schema === 'aevesa.conformance-attestation/v1') {
    return { kind: 'conformance_attestation', payload: obj };
  }
  if (schema === 'aevesa.auditor-packet/v1') {
    return { kind: 'auditor_packet', payload: obj };
  }
  if (
    schema === 'aevesa.scitt-refusal-witness-verify/v1' ||
    schema === 'aevesa.scitt-refusal-export/v1' ||
    obj.offline_verification_export
  ) {
    return { kind: 'scitt_witness_export', payload: obj };
  }

  const bundleCandidate = normalizeProofBundleInput(obj);
  if (isProofOfActionBundle(bundleCandidate)) {
    return { kind: 'proof_of_action_bundle', payload: bundleCandidate, wrapped: bundleCandidate !== obj };
  }

  if (obj.receipt && typeof obj.receipt === 'object' && obj.datalog_export) {
    return { kind: 'policy_proof_bundle', payload: obj };
  }

  if (obj.receipt && typeof obj.receipt === 'object') {
    const receipt = /** @type {Record<string, unknown>} */ (obj.receipt);
    if (receipt.schema === 'liability-receipt/v1') {
      return { kind: 'auditor_packet', payload: obj };
    }
  }

  return { kind: 'unknown', payload: obj, error: 'unrecognized evidence schema' };
}

export default { detectEvidenceType, isProofOfActionBundle, normalizeProofBundleInput, EVIDENCE_KINDS };
