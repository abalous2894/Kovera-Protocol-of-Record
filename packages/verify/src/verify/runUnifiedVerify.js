/**
 * Unified offline verification — one entry point for all Aevesa evidence types.
 */

import { verifyReceipt, verifyProveBundle, verifySessionProof, evaluateClosureShipGate, verifyChannelProvenanceBundle, verifySessionPayloadGateBundle, verifyAegIntegrityBundle, verifyConstraintClosureBundle, verifyHitlPreimageBindingBundle, verifyExecutionSurfaceCompletenessBundle, verifyProvableExecutionBoundaryBundle, verifyBehavioralSbomBundle, verifyRevocationHorizonBundle, verifyConformityClosureBundle, verifyDeclaredAdaptationEnvelopeBundle, verifySubstantialModificationSignalBundle, verifyAdaptationLifecycleExportBundle, verifyEvidenceResurrectionBatchBundle, verifyLicenseSurvivableBundle, verifyIndependentGuardianBundle, verifyTransparencyLogMonitorAttestation, verifyTransparencyLogMonitorStatus, verifyProofStrengthDisclosure, verifyEgressAttestationBundle } from '../../dist/index.js';
import { detectEvidenceType, isProofOfActionBundle } from './detectEvidenceType.js';
import { buildVerificationReport, executiveSummaryFromReceipt } from './verificationReport.js';
import { replayProofBundle } from '../replay/replayProofBundle.js';
import { verifyPolicyProofBundle } from '../policy/policyProofVerify.js';
import { verifyConformanceAttestation } from '../conformance/conformanceAttestation.js';
import { verifyScittRefusalWitnessBundle } from '../witness/witnessInclusionVerify.js';
import { buildAuditorPacketDigest, verifyAuditorPacket } from './buildAuditorPacket.js';

/**
 * Extract liability receipt from proof bundle artifacts if present.
 * @param {object} bundle
 */
function extractReceiptFromBundle(bundle) {
  const artifacts = bundle?.artifacts;
  if (!artifacts || typeof artifacts !== 'object') return null;
  const keys = [
    'liability/receipt',
    'liability_receipt',
    'receipt',
    'governance/liability_receipt',
  ];
  for (const key of keys) {
    const val = artifacts[key];
    if (val && typeof val === 'object' && val.schema === 'liability-receipt/v1') return val;
  }
  return null;
}

/**
 * @param {string} entryHash
 * @param {string} apiBase
 */
async function fetchPublicEvidenceByEntryHash(entryHash, apiBase) {
  const base = String(apiBase || 'https://api.aevesa.com').replace(/\/+$/, '');
  const url = `${base}/api/v1/public/truth?entryHash=${encodeURIComponent(entryHash)}`;
  const res = await fetch(url, { headers: { Accept: 'application/json' } });
  if (!res.ok) {
    throw new Error(`Public truth API HTTP ${res.status}`);
  }
  const body = await res.json();
  if (body?.receipt) return body.receipt;
  if (body?.liability_receipt) return body.liability_receipt;
  if (body?.ok === true && body?.document) return body.document;
  throw new Error('Public truth response missing receipt payload');
}

/**
 * @param {unknown} input
 * @param {{
 *   fetch?: boolean;
 *   apiBase?: string;
 *   summary?: boolean;
 * }} [opts]
 */
export async function runUnifiedVerify(input, opts = {}) {
  const detected = detectEvidenceType(input);
  /** @type {object[]} */
  const checks = [];
  /** @type {string[]} */
  const errors = [];
  /** @type {object | null} */
  let replay = null;
  /** @type {object | null} */
  let detail = null;
  /** @type {string | null} */
  let entryHash = detected.entryHash ?? null;
  /** @type {object | null} */
  let diligenceSummary = null;
  let executiveSummary = null;

  if (detected.kind === 'unknown') {
    return buildVerificationReport({
      ok: false,
      kind: 'unknown',
      errors: [detected.error || 'Unrecognized evidence format'],
      checks: [{ id: 'detect', ok: false, detail: detected.error || 'unknown schema' }],
    });
  }

  if (detected.kind === 'entry_hash') {
    entryHash = detected.entryHash ?? null;
    if (opts.fetch !== false) {
      try {
        const receipt = await fetchPublicEvidenceByEntryHash(entryHash, opts.apiBase);
        return runUnifiedVerify(receipt, { ...opts, fetch: false });
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        return buildVerificationReport({
          ok: false,
          kind: 'entry_hash',
          entryHash,
          errors: [`Could not fetch receipt for entry hash (${msg})`],
          executiveSummary: `Entry hash ${entryHash?.slice(0, 12)}… — paste full JSON or use verify.aevesa.com/?entryHash=${entryHash}`,
          checks: [{ id: 'fetch_public_truth', ok: false, detail: msg }],
          verifyHint: `verify.aevesa.com/?entryHash=${entryHash}`,
        });
      }
    }
    return buildVerificationReport({
      ok: false,
      kind: 'entry_hash',
      entryHash,
      errors: ['entry_hash only — re-run with --fetch or paste full JSON'],
      checks: [{ id: 'entry_hash', ok: false, detail: 'fetch disabled' }],
    });
  }

  const payload = detected.payload;

  if (detected.kind === 'liability_receipt') {
    const receipt = payload;
    const digestOk = verifyReceipt(receipt, { ledgerDocument: null });
    checks.push({ id: 'receipt_structure', ok: digestOk.isValid === true, detail: digestOk.error ?? 'valid' });
    if (!digestOk.isValid) errors.push(digestOk.error || 'receipt verification failed');

    const isDeny =
      receipt.policy?.decision === 'deny' || receipt.session?.outcome === 'blocked';
    entryHash = receipt.proof?.primary_anchor?.entry_hash ?? entryHash;
    diligenceSummary = receipt.diligence_summary ?? null;
    executiveSummary = executiveSummaryFromReceipt(receipt);
    detail = { receipt_profile: receipt.receipt_profile ?? null, is_denied: isDeny };

    return buildVerificationReport({
      ok: digestOk.isValid === true,
      kind: 'liability_receipt',
      verdict: digestOk.isValid ? (isDeny ? 'DENIED_VALID' : 'VERIFIED') : 'TAMPERED',
      checks,
      errors,
      entryHash,
      executiveSummary,
      diligenceSummary,
      detail,
    });
  }

  if (detected.kind === 'proof_of_action_bundle') {
    const bundle = payload;
    try {
      replay = replayProofBundle(bundle);
      checks.push({ id: 'session_replay', ok: true, detail: `${replay.event_count} events` });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      checks.push({ id: 'session_replay', ok: false, detail: msg });
      errors.push(`replay: ${msg}`);
    }

    entryHash =
      bundle.manifest?.entry_hash ??
      bundle.anchor?.entry_hash ??
      replay?.entry_hash ??
      entryHash;

    const receipt = extractReceiptFromBundle(bundle);
    if (receipt) {
      const prove = verifyProveBundle(receipt, { entryHash: entryHash ?? undefined });
      checks.push({ id: 'prove_bundle_receipt', ok: prove.ok === true, detail: prove.note });
      if (!prove.ok) errors.push(prove.note || 'prove bundle verify failed');
      diligenceSummary = receipt.diligence_summary ?? null;
      executiveSummary = executiveSummaryFromReceipt(receipt);
      detail = { prove_bundle: prove };
    } else {
      const chainOk = bundle.manifest?.proof_chain_summary?.ok ?? bundle.proof_chain?.ok;
      checks.push({
        id: 'manifest_proof_chain',
        ok: chainOk !== false,
        detail: chainOk === true ? 'export-time chain OK' : 'no embedded receipt — replay only',
      });
      executiveSummary = `Proof-of-Action bundle ${bundle.bundle_id || bundle.manifest?.bundle_id || ''} — ${replay?.event_count ?? 0} timeline events reconstructed offline.`;
    }

    return buildVerificationReport({
      ok: errors.length === 0 && checks.every((c) => c.ok !== false),
      kind: 'proof_of_action_bundle',
      checks,
      errors,
      entryHash,
      replay,
      executiveSummary,
      diligenceSummary,
      detail,
    });
  }

  if (detected.kind === 'session_proof_bundle') {
    const result = verifySessionProof(payload);
    checks.push({ id: 'session_proof', ok: result.ok === true, detail: result.note });
    if (!result.ok) errors.push(...(result.errors || []));
    entryHash =
      payload.terminal_receipt?.proof?.primary_anchor?.entry_hash ??
      entryHash;
    const closure = result.composition_closure;
    const closureShipGate = evaluateClosureShipGate(closure);
    if (closureShipGate.blocked && closureShipGate.note) {
      checks.push({
        id: 'closure_ship_gate',
        ok: false,
        detail: closureShipGate.note,
      });
      errors.push(closureShipGate.note);
    } else if (closureShipGate.carrier_submission_ready) {
      checks.push({
        id: 'closure_ship_gate',
        ok: true,
        detail: 'carrier_submission_ready',
      });
    }
    if (result.ok && closure?.carrier_review_ready) {
      executiveSummary = `CAP session proof carrier-ready — ${payload.manifest?.declared_count ?? '?'} hops bundled and verified under set_root.`;
    } else if (result.ok && closure) {
      executiveSummary = `Set integrity verified — closure ${closure.closure_verdict}. ${closure.note || 'See composition_closure before carrier submission.'}`;
    } else if (result.ok) {
      executiveSummary = `CAP set integrity verified — ${payload.manifest?.declared_count ?? '?'} hops under set_root with partial_path alignment.`;
    } else {
      executiveSummary = 'Session proof verification failed.';
    }
    detail = { ...result, closure_ship_gate: closureShipGate };
    const carrierReady = closureShipGate.carrier_submission_ready === true;
    return buildVerificationReport({
      ok: result.ok === true,
      kind: 'session_proof_bundle',
      verdict: result.ok && carrierReady ? 'VERIFIED' : result.ok ? 'PARTIAL' : 'TAMPERED',
      checks,
      errors,
      entryHash,
      executiveSummary,
      detail,
    });
  }

  if (detected.kind === 'channel_provenance') {
    const result = verifyChannelProvenanceBundle(payload);
    checks.push({ id: 'channel_provenance', ok: result.ok === true, detail: result.note });
    if (!result.ok && result.note) errors.push(result.note);
    executiveSummary = result.ok
      ? 'Channel provenance verified — instruction sources bound at decision time.'
      : 'Channel provenance verification failed.';
    detail = result;
    return buildVerificationReport({
      ok: result.ok === true,
      kind: 'channel_provenance',
      checks,
      errors,
      executiveSummary,
      detail,
    });
  }

  if (detected.kind === 'session_payload_gate') {
    const result = verifySessionPayloadGateBundle(payload, {
      attestationSecret: opts.attestationSecret,
      requireChannelProvenance: opts.requireChannelProvenance,
    });
    checks.push({ id: 'session_payload_gate', ok: result.ok === true, detail: result.note });
    if (!result.ok && result.note) errors.push(result.note);
    entryHash = payload.ledger_attestation?.entryHash ?? entryHash;
    executiveSummary = result.ok
      ? `Session payload gate verified — ${payload.mutation?.action_type} ${payload.verdict} pre-execution.`
      : 'Session payload gate verification failed.';
    detail = result;
    return buildVerificationReport({
      ok: result.ok === true,
      kind: 'session_payload_gate',
      verdict: payload.verdict === 'DENY' ? 'DENIED_VALID' : result.ok ? 'VERIFIED' : 'UNKNOWN',
      checks,
      errors,
      entryHash,
      executiveSummary,
      detail,
    });
  }

  if (detected.kind === 'aeg_integrity') {
    const result = verifyAegIntegrityBundle(payload, {
      requireFailureAttribution: opts.requireFailureAttribution,
    });
    checks.push({ id: 'aeg_integrity', ok: result.ok === true, detail: result.note });
    if (!result.ok && result.note) errors.push(result.note);
    executiveSummary = result.ok
      ? 'AEG integrity verified — structural source attribution bound at decision edge.'
      : 'AEG integrity verification failed.';
    detail = result;
    return buildVerificationReport({
      ok: result.ok === true,
      kind: 'aeg_integrity',
      checks,
      errors,
      executiveSummary,
      detail,
    });
  }

  if (detected.kind === 'constraint_closure') {
    const result = verifyConstraintClosureBundle(payload, {
      requirePass: opts.requireConstraintClosurePass,
    });
    checks.push({ id: 'constraint_closure', ok: result.ok === true, detail: result.note });
    if (!result.ok && result.note) errors.push(result.note);
    executiveSummary = result.ok
      ? `Constraint closure verified — recomposition ${payload.recomposition_result}.`
      : 'Constraint closure verification failed.';
    detail = result;
    return buildVerificationReport({
      ok: result.ok === true,
      kind: 'constraint_closure',
      verdict: payload.recomposition_result === 'FAIL' && result.ok ? 'DENIED_VALID' : result.ok ? 'VERIFIED' : 'UNKNOWN',
      checks,
      errors,
      executiveSummary,
      detail,
    });
  }

  if (detected.kind === 'hitl_preimage_binding') {
    const result = verifyHitlPreimageBindingBundle(payload, { requireMatch: opts.requireHitlMatch });
    checks.push({ id: 'hitl_preimage_binding', ok: result.ok === true, detail: result.note });
    if (!result.ok && result.note) errors.push(result.note);
    executiveSummary = result.ok
      ? `HITL preimage binding verified — ${payload.binding_result}.`
      : 'HITL preimage binding verification failed.';
    detail = result;
    return buildVerificationReport({
      ok: result.ok === true,
      kind: 'hitl_preimage_binding',
      verdict: payload.binding_result === 'DIVERGENCE' && result.ok ? 'DENIED_VALID' : result.ok ? 'VERIFIED' : 'UNKNOWN',
      checks,
      errors,
      executiveSummary,
      detail,
    });
  }

  if (detected.kind === 'execution_surface_completeness') {
    const result = verifyExecutionSurfaceCompletenessBundle(payload, {
      requireComplete: opts.requireSurfaceComplete,
    });
    checks.push({ id: 'execution_surface_completeness', ok: result.ok === true, detail: result.note });
    if (!result.ok && result.note) errors.push(result.note);
    executiveSummary = result.ok
      ? `Execution surface completeness verified — ${payload.completeness_result}.`
      : 'Execution surface completeness verification failed.';
    detail = result;
    return buildVerificationReport({
      ok: result.ok === true,
      kind: 'execution_surface_completeness',
      checks,
      errors,
      executiveSummary,
      detail,
    });
  }

  if (detected.kind === 'provable_execution_boundary') {
    const result = verifyProvableExecutionBoundaryBundle(payload, {
      requireComplete: opts.requirePebComplete,
      requireChannelProvenance: opts.requirePebChannel,
      requireEnvironmentalSource: opts.requireEnvironmentalSource,
      requireSurfaceComplete: opts.requireSurfaceComplete,
    });
    checks.push({ id: 'provable_execution_boundary', ok: result.ok === true, detail: result.note });
    if (!result.ok && result.note) errors.push(result.note);
    executiveSummary = result.ok
      ? `Provable execution boundary verified — ${payload.boundary_result}.`
      : 'Provable execution boundary verification failed.';
    detail = result;
    return buildVerificationReport({
      ok: result.ok === true,
      kind: 'provable_execution_boundary',
      checks,
      errors,
      executiveSummary,
      detail,
    });
  }

  if (detected.kind === 'behavioral_sbom') {
    const result = verifyBehavioralSbomBundle(payload, {
      requireBehavioralAgents: opts.requireBehavioralAgents,
      requireNoGaps: opts.requireBehavioralSbomNoGaps,
    });
    checks.push({ id: 'behavioral_sbom', ok: result.ok === true, detail: result.note });
    if (!result.ok && result.note) errors.push(result.note);
    executiveSummary = result.ok
      ? 'Behavioral SBOM verified — config vs behavior gap summary attested offline.'
      : 'Behavioral SBOM verification failed.';
    detail = result;
    return buildVerificationReport({
      ok: result.ok === true,
      kind: 'behavioral_sbom',
      checks,
      errors,
      executiveSummary,
      detail,
    });
  }

  if (detected.kind === 'conformity_closure') {
    const result = verifyConformityClosureBundle(payload, {
      requireClosureEntryHash: opts.requireClosureEntryHash,
    });
    checks.push({ id: 'conformity_closure', ok: result.ok === true, detail: result.note });
    if (!result.ok && result.note) errors.push(result.note);
    executiveSummary = result.ok
      ? 'Conformity closure verified — obligation met live signal threshold offline.'
      : 'Conformity closure verification failed.';
    detail = result;
    return buildVerificationReport({
      ok: result.ok === true,
      kind: 'conformity_closure',
      checks,
      errors,
      executiveSummary,
      detail,
    });
  }

  if (detected.kind === 'declared_adaptation_envelope') {
    const result = verifyDeclaredAdaptationEnvelopeBundle(payload, {
      requireEnvelopeEntryHash: opts.requireEnvelopeEntryHash,
    });
    checks.push({
      id: 'declared_adaptation_envelope',
      ok: result.ok === true,
      detail: result.note,
    });
    if (!result.ok && result.note) errors.push(result.note);
    executiveSummary = result.ok
      ? result.gtmLine
      : 'Declared adaptation envelope verification failed.';
    detail = result;
    return buildVerificationReport({
      ok: result.ok === true,
      kind: 'declared_adaptation_envelope',
      checks,
      errors,
      executiveSummary,
      detail,
    });
  }

  if (detected.kind === 'substantial_modification_signal') {
    const result = verifySubstantialModificationSignalBundle(payload, {
      requireSignalEntryHash: opts.requireSignalEntryHash,
      requireContributingEntryHashes: opts.requireContributingEntryHashes,
    });
    checks.push({
      id: 'substantial_modification_signal',
      ok: result.ok === true,
      detail: result.note,
    });
    if (!result.ok && result.note) errors.push(result.note);
    executiveSummary = result.ok
      ? result.gtmLine
      : 'Substantial modification signal verification failed.';
    detail = result;
    return buildVerificationReport({
      ok: result.ok === true,
      kind: 'substantial_modification_signal',
      checks,
      errors,
      executiveSummary,
      detail,
    });
  }

  if (detected.kind === 'adaptation_lifecycle_export') {
    const result = verifyAdaptationLifecycleExportBundle(payload, {
      requireBreachSignalWhenBreach: opts.requireBreachSignalWhenBreach !== false,
    });
    checks.push({
      id: 'adaptation_lifecycle_export',
      ok: result.ok === true,
      detail: result.note,
    });
    if (!result.ok && result.note) errors.push(result.note);
    executiveSummary = result.ok
      ? result.gtmLine
      : 'Adaptation lifecycle export verification failed.';
    detail = result;
    return buildVerificationReport({
      ok: result.ok === true,
      kind: 'adaptation_lifecycle_export',
      checks,
      errors,
      executiveSummary,
      detail,
    });
  }

  if (detected.kind === 'evidence_resurrection_batch') {
    const result = verifyEvidenceResurrectionBatchBundle(payload, {
      requireReceiptHashes: opts.requireResurrectionReceiptHashes,
    });
    checks.push({ id: 'evidence_resurrection_batch', ok: result.ok === true, detail: result.note });
    if (!result.ok && result.note) errors.push(result.note);
    executiveSummary = result.ok
      ? 'Evidence resurrection batch verified — resurrected gateway decisions bound offline.'
      : 'Evidence resurrection batch verification failed.';
    detail = result;
    return buildVerificationReport({
      ok: result.ok === true,
      kind: 'evidence_resurrection_batch',
      checks,
      errors,
      executiveSummary,
      detail,
    });
  }

  if (detected.kind === 'license_survivable_bundle') {
    const result = verifyLicenseSurvivableBundle(payload);
    checks.push({ id: 'license_survivable_bundle', ok: result.ok === true, detail: result.note });
    if (!result.ok && result.note) errors.push(result.note);
    executiveSummary = result.ok
      ? 'License-survivable bundle verified — resurrected receipts verify without platform access.'
      : 'License-survivable bundle verification failed.';
    detail = result;
    return buildVerificationReport({
      ok: result.ok === true,
      kind: 'license_survivable_bundle',
      checks,
      errors,
      executiveSummary,
      detail,
    });
  }

  if (detected.kind === 'transparency_log_monitor_attestation') {
    const result = verifyTransparencyLogMonitorAttestation(payload, {
      entryDigests: opts.monitorAttestationEntryDigests,
      requireHealthyState: opts.requireHealthyMonitorState,
    });
    checks.push({
      id: 'transparency_log_monitor_attestation',
      ok: result.ok === true,
      detail: result.note,
    });
    if (!result.ok && result.note) errors.push(result.note);
    executiveSummary = result.gtmLine;
    detail = result;
    return buildVerificationReport({
      ok: result.ok === true,
      kind: 'transparency_log_monitor_attestation',
      checks,
      errors,
      executiveSummary,
      detail,
    });
  }

  if (detected.kind === 'proof_strength_disclosure') {
    const result = verifyProofStrengthDisclosure(payload);
    checks.push({
      id: 'proof_strength_disclosure',
      ok: result.ok === true,
      detail: result.note,
    });
    if (!result.ok && result.note) errors.push(result.note);
    executiveSummary = result.gtmLine;
    detail = result;
    return buildVerificationReport({
      ok: result.ok === true,
      kind: 'proof_strength_disclosure',
      checks,
      errors,
      executiveSummary,
      detail,
    });
  }

  if (detected.kind === 'egress_attestation') {
    const result = verifyEgressAttestationBundle(payload);
    checks.push({
      id: 'egress_attestation',
      ok: result.ok === true,
      detail: result.note,
    });
    if (!result.ok && result.note) errors.push(result.note);
    executiveSummary = result.gtmLine;
    detail = result;
    return buildVerificationReport({
      ok: result.ok === true,
      kind: 'egress_attestation',
      checks,
      errors,
      executiveSummary,
      detail,
    });
  }

  if (detected.kind === 'transparency_log_monitor_status') {
    const result = verifyTransparencyLogMonitorStatus(payload, {
      entryDigests: opts.monitorAttestationEntryDigests,
    });
    checks.push({
      id: 'transparency_log_monitor_status',
      ok: result.ok === true,
      detail: result.note,
    });
    if (!result.ok && result.note) errors.push(result.note);
    executiveSummary = result.ok
      ? 'Transparency log monitor status verified — consistency proof bound for public monitor surface.'
      : 'Transparency log monitor status verification failed.';
    detail = result;
    return buildVerificationReport({
      ok: result.ok === true,
      kind: 'transparency_log_monitor_status',
      checks,
      errors,
      executiveSummary,
      detail,
    });
  }

  if (detected.kind === 'independent_guardian_bundle') {
    const result = verifyIndependentGuardianBundle(payload, {
      memberContexts: opts.memberContexts,
      requireCustodianWitness: opts.requireCustodianWitness,
      requireDualProfile: opts.requireDualProfile,
      requireMonitorAttestation: opts.requireMonitorAttestation,
      monitorAttestationEntryDigests: opts.monitorAttestationEntryDigests,
    });
    checks.push({ id: 'independent_guardian_bundle', ok: result.ok === true, detail: result.note });
    if (!result.ok && result.note) errors.push(result.note);
    executiveSummary = result.ok
      ? 'Independent Guardian bundle verified — custodian witness + verifiable denial composed offline.'
      : 'Independent Guardian bundle verification failed.';
    detail = result;
    return buildVerificationReport({
      ok: result.ok === true,
      kind: 'independent_guardian_bundle',
      checks,
      errors,
      executiveSummary,
      detail,
    });
  }

  if (detected.kind === 'revocation_horizon') {
    const result = verifyRevocationHorizonBundle(payload, { requireWithinSla: opts.requireRevocationWithinSla });
    checks.push({ id: 'revocation_horizon', ok: result.ok === true, detail: result.note });
    if (!result.ok && result.note) errors.push(result.note);
    executiveSummary = result.ok
      ? `Revocation horizon verified — ${payload.attestation}.`
      : 'Revocation horizon verification failed.';
    detail = result;
    return buildVerificationReport({
      ok: result.ok === true,
      kind: 'revocation_horizon',
      verdict: payload.attestation === 'VIOLATION' && result.ok ? 'DENIED_VALID' : result.ok ? 'VERIFIED' : 'UNKNOWN',
      checks,
      errors,
      executiveSummary,
      detail,
    });
  }

  if (detected.kind === 'policy_proof_bundle') {
    const result = verifyPolicyProofBundle(payload);
    checks.push({ id: 'policy_proof', ok: result.ok === true, detail: result.note });
    if (!result.ok) errors.push(...result.errors);
    entryHash = payload.receipt?.proof?.primary_anchor?.entry_hash ?? entryHash;
    executiveSummary = result.deny_proven
      ? 'Policy deny proven offline from Datalog facts — no Aevesa API required.'
      : 'Policy proof verification did not complete.';
    detail = result;
    return buildVerificationReport({
      ok: result.ok === true,
      kind: 'policy_proof_bundle',
      verdict: result.deny_proven ? 'DENIED_VALID' : result.ok ? 'VERIFIED' : 'UNKNOWN',
      checks,
      errors,
      entryHash,
      executiveSummary,
      detail,
    });
  }

  if (detected.kind === 'conformance_attestation') {
    const result = verifyConformanceAttestation(payload);
    checks.push({ id: 'conformance_attestation', ok: result.ok === true });
    if (!result.ok) errors.push(...result.errors);
    executiveSummary = result.ok
      ? 'Deployment conformance attestation digest and program results verified offline.'
      : 'Conformance attestation failed verification.';
    detail = result;
    return buildVerificationReport({
      ok: result.ok === true,
      kind: 'conformance_attestation',
      checks,
      errors,
      executiveSummary,
      detail,
    });
  }

  if (detected.kind === 'scitt_witness_export') {
    const exportBody = payload.offline_verification_export ?? payload;
    const result = verifyScittRefusalWitnessBundle(exportBody);
    checks.push({ id: 'scitt_witness', ok: result.ok === true, detail: result.note });
    if (!result.ok) errors.push(result.note || 'witness verify failed');
    executiveSummary = result.ok
      ? 'SCITT refusal witness and inclusion proof verified offline.'
      : 'Witness verification failed.';
    detail = result;
    return buildVerificationReport({
      ok: result.ok === true,
      kind: 'scitt_witness_export',
      checks,
      errors,
      executiveSummary,
      detail,
    });
  }

  if (detected.kind === 'auditor_packet') {
    const packetVerify = verifyAuditorPacket(payload);
    checks.push({ id: 'auditor_packet', ok: packetVerify.ok === true, detail: packetVerify.note });
    if (!packetVerify.ok) errors.push(...packetVerify.errors);

    const inner = payload.receipt
      ? await runUnifiedVerify(payload.receipt, { ...opts, fetch: false })
      : payload.bundle
        ? await runUnifiedVerify(payload.bundle, { ...opts, fetch: false })
        : null;

    if (inner) {
      checks.push(...(inner.checks || []).map((c) => ({ ...c, id: `packet/${c.id}` })));
      if (!inner.ok) errors.push(...(inner.errors || []));
      replay = inner.replay ?? null;
      entryHash = inner.entry_hash ?? entryHash;
      diligenceSummary = inner.diligence_summary ?? null;
    }

    executiveSummary =
      payload.executive_summary ??
      packetVerify.executive_summary ??
      inner?.executive_summary ??
      'Auditor packet verified offline.';

    return buildVerificationReport({
      ok: packetVerify.ok === true && (inner?.ok !== false),
      kind: 'auditor_packet',
      checks,
      errors,
      entryHash,
      replay,
      executiveSummary,
      diligenceSummary,
      detail: { packet: packetVerify, inner },
    });
  }

  return buildVerificationReport({
    ok: false,
    kind: detected.kind,
    errors: ['Unhandled evidence kind'],
  });
}

export default { runUnifiedVerify };
