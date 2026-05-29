/**
 * Proof-of-Intent Merkle binding — identical to proofOfIntentService.js (node:crypto only).
 */

import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';

const NO_REASONING_DIGEST = createHash('sha256').update('(no reasoning path)', 'utf8').digest('hex');

/**
 * @param {string | null | undefined} text
 */
export function digestReasoningText(text) {
  if (text == null || typeof text !== 'string' || !text.trim()) {
    return NO_REASONING_DIGEST;
  }
  const normalized = text.slice(0, 4096).toLowerCase().replace(/\s+/g, ' ').trim();
  return createHash('sha256').update(normalized, 'utf8').digest('hex');
}

/**
 * @param {object} params
 */
export function buildReasoningPath({ intentAnalysis, reasoning, payload = {}, eventType = null }) {
  const ia = intentAnalysis && typeof intentAnalysis === 'object' ? intentAnalysis : null;
  const p = payload && typeof payload === 'object' ? payload : {};
  const rawReasoning =
    reasoning ??
    (typeof ia?.reasoning === 'string' ? ia.reasoning : null) ??
    (typeof p.agentReasoning === 'string' ? p.agentReasoning : null) ??
    (typeof p.reasoning === 'string' ? p.reasoning : null) ??
    null;

  const opProfile = ia?.opProfile && typeof ia.opProfile === 'object' ? ia.opProfile : null;
  const intentProfile = ia?.intentProfile && typeof ia.intentProfile === 'object' ? ia.intentProfile : null;
  const alignment = ia?.alignment && typeof ia.alignment === 'object' ? ia.alignment : null;

  let operationDescriptor = null;
  if (opProfile?.model || opProfile?.operation) {
    operationDescriptor = `${opProfile.model ?? '?'}::${opProfile.operation ?? '?'}`;
  } else if (p.toolName) {
    operationDescriptor = `${p.model ?? p.primaryModel ?? '?'}::${p.toolName}`;
  } else if (eventType) {
    operationDescriptor = `${p.model ?? p.primaryModel ?? '?'}::${eventType}`;
  }

  return {
    primaryIntent: intentProfile?.primary != null ? String(intentProfile.primary) : null,
    alignmentLevel: alignment?.level != null ? String(alignment.level) : null,
    divergenceScore:
      typeof alignment?.score === 'number' ? Number(Number(alignment.score).toFixed(4)) : null,
    operationDescriptor,
    reasoningDigest: digestReasoningText(rawReasoning),
  };
}

/**
 * @param {object} params
 */
export function buildConstraintsApplied({ payload = {}, policySeal = null }) {
  const p = payload && typeof payload === 'object' ? payload : {};
  const pw = p.passportWitness && typeof p.passportWitness === 'object' ? p.passportWitness : null;
  const seal =
    policySeal && typeof policySeal === 'object'
      ? policySeal
      : p.sovereigntyPolicySeal && typeof p.sovereigntyPolicySeal === 'object'
        ? p.sovereigntyPolicySeal
        : null;

  /** @type {string[]} */
  const constraintKeys = [];
  const rawConstraints = p.delegation_constraints ?? p.delegationConstraints ?? null;
  if (rawConstraints && typeof rawConstraints === 'object' && !Array.isArray(rawConstraints)) {
    constraintKeys.push(...Object.keys(rawConstraints).sort());
  } else if (Array.isArray(rawConstraints)) {
    constraintKeys.push(...rawConstraints.map((c) => String(c)).sort());
  }

  return {
    policyVersionHash: seal?.policyVersionHash != null ? String(seal.policyVersionHash) : null,
    passportHash: pw?.passportHash != null ? String(pw.passportHash) : null,
    primaryMandateId: pw?.primaryMandateId != null ? String(pw.primaryMandateId) : null,
    toolName: p.toolName != null ? String(p.toolName) : null,
    permission:
      p.requestedPermission != null
        ? String(p.requestedPermission)
        : p.permission != null
          ? String(p.permission)
          : null,
    delegationConstraintKeys: constraintKeys,
  };
}

/**
 * @param {object} params
 */
export function buildModelFingerprint({ payload = {}, intentAnalysis = null }) {
  const p = payload && typeof payload === 'object' ? payload : {};
  const ia = intentAnalysis && typeof intentAnalysis === 'object' ? intentAnalysis : null;
  /** @type {Set<string>} */
  const models = new Set();

  const candidates = [
    ia?.opProfile && typeof ia.opProfile === 'object' ? ia.opProfile.model : null,
    ia?.command && typeof ia.command === 'object' ? ia.command.model : null,
    p.model,
    p.primaryModel,
    p.agent_request && typeof p.agent_request === 'object' ? p.agent_request.model : null,
  ];
  for (const c of candidates) {
    if (c != null && String(c).trim()) models.add(String(c).trim());
  }

  const observed = [...models].sort();
  return {
    primaryModel: observed[0] || null,
    modelsObserved: observed,
  };
}

/**
 * @param {object} params
 */
export function buildCausalBinding({ payload = {}, swarmFirstAction = false }) {
  const p = payload && typeof payload === 'object' ? payload : {};
  const parentEntryHash =
    p.parentEntryHash != null && String(p.parentEntryHash).trim()
      ? String(p.parentEntryHash).trim().toLowerCase()
      : null;
  if (!swarmFirstAction || !parentEntryHash) {
    return null;
  }
  return {
    parentEntryHash,
    parentSessionId:
      p.parentSessionId != null && String(p.parentSessionId).trim() ? String(p.parentSessionId).trim() : null,
    rootSessionId:
      p.rootSessionId != null && String(p.rootSessionId).trim() ? String(p.rootSessionId).trim() : null,
  };
}

/**
 * @param {{ reasoningPath: object, constraintsApplied: object, modelFingerprint: object, causalBinding?: object | null }} envelope
 */
export function computeProofOfIntent(envelope) {
  const preimage = {
    reasoningPath: envelope.reasoningPath,
    constraintsApplied: envelope.constraintsApplied,
    modelFingerprint: envelope.modelFingerprint,
  };
  if (envelope.causalBinding?.parentEntryHash) {
    preimage.causalBinding = envelope.causalBinding;
  }
  return createHash('sha256').update(stableStringify(preimage), 'utf8').digest('hex');
}

/**
 * Build proof-of-intent envelope from spec-style input (reasoningFromContext + payload).
 * @param {object} input
 */
export function buildProofOfIntentFromSpecInput(input) {
  const payload = input?.payload && typeof input.payload === 'object' ? input.payload : {};
  const swarmFirstAction = input.swarmFirstAction === true || payload.swarmFirstAction === true;
  const causalBinding = buildCausalBinding({ payload, swarmFirstAction });

  const envelope = {
    reasoningPath: buildReasoningPath({
      reasoning: input.reasoningFromContext ?? null,
      payload,
      eventType: input.eventType ?? null,
    }),
    constraintsApplied: buildConstraintsApplied({ payload }),
    modelFingerprint: buildModelFingerprint({ payload }),
    ...(causalBinding ? { causalBinding } : {}),
  };

  return {
    envelope,
    proofOfIntent: computeProofOfIntent(envelope),
  };
}

/**
 * @param {object} doc
 */
export function verifyProofOfIntentForStoredRow(doc) {
  const stored = doc?.proofOfIntent ?? doc?.payload?.proofOfIntent ?? null;
  if (stored == null || String(stored).trim() === '') {
    return { applicable: false, ok: null, stored: null, recomputed: null };
  }

  const envelope = doc?.payload?.proofOfIntentEnvelope;
  if (!envelope || typeof envelope !== 'object') {
    return {
      applicable: true,
      ok: false,
      stored: String(stored).toLowerCase(),
      recomputed: null,
      detail: 'proofOfIntent present but proofOfIntentEnvelope missing — cannot recompute',
    };
  }

  const recomputed = computeProofOfIntent(envelope);
  const ok = String(stored).toLowerCase() === recomputed;
  return {
    applicable: true,
    ok,
    stored: String(stored).toLowerCase(),
    recomputed,
    detail: ok
      ? 'proofOfIntent matches recomputed reasoning/constraints/model seal'
      : `mismatch stored=${String(stored).slice(0, 16)}… recomputed=${recomputed.slice(0, 16)}…`,
  };
}

export { NO_REASONING_DIGEST };
