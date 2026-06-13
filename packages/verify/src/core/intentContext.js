/**
 * Proof-of-Intent (liability-receipt intent_context + aegis/1 governanceBinding).
 * Deterministic serialization for entryHash preimage and receipt_digest.
 */

import { canonicalize } from './canonicalize.js';
import { stableStringify } from './stableStringify.js';
import { sha256Utf8 } from './sha256.js';

export const INTENT_CONTEXT_MAX_REASONING = 4096;
export const INTENT_CONTEXT_MAX_MODEL = 256;

/**
 * Canonical intent_context object (snake_case keys, fixed field order via canonicalize).
 * @param {unknown} input
 */
export function serializeIntentContext(input) {
  if (input == null || typeof input !== 'object') {
    return {
      reasoning_summary: '',
      model_fingerprint: '',
    };
  }
  const raw = /** @type {Record<string, unknown>} */ (input);
  const reasoning = String(
    raw.reasoning_summary ?? raw.reasoningSummary ?? '',
  )
    .trim()
    .slice(0, INTENT_CONTEXT_MAX_REASONING);
  const model = String(raw.model_fingerprint ?? raw.modelFingerprint ?? '')
    .trim()
    .slice(0, INTENT_CONTEXT_MAX_MODEL);
  return {
    reasoning_summary: reasoning,
    model_fingerprint: model,
  };
}

/**
 * @param {ReturnType<typeof serializeIntentContext>} intentContext
 */
export function canonicalizeIntentContextForBinding(intentContext) {
  return canonicalize(serializeIntentContext(intentContext));
}

/**
 * @param {ReturnType<typeof serializeIntentContext>} intentContext
 */
export function computeIntentContextDigest(intentContext) {
  return sha256Utf8(stableStringify(canonicalizeIntentContextForBinding(intentContext)));
}

/**
 * @param {{
 *   reasoningSummary?: string | null;
 *   modelFingerprint?: string | null;
 *   reasoningFromContext?: string | null;
 *   proofOfIntentEnvelope?: { reasoningPath?: { primaryIntent?: string }; modelFingerprint?: { primaryModel?: string } } | null;
 *   normalizedPayload?: Record<string, unknown> | null;
 * }} sources
 */
export function buildIntentContextFromSources(sources = {}) {
  const payload = sources.normalizedPayload && typeof sources.normalizedPayload === 'object'
    ? sources.normalizedPayload
    : {};
  const payloadBlock =
    payload.intent_context && typeof payload.intent_context === 'object'
      ? payload.intent_context
      : payload.intentContext && typeof payload.intentContext === 'object'
        ? payload.intentContext
        : null;

  const envelope = sources.proofOfIntentEnvelope;
  const reasoning =
    sources.reasoningSummary ??
    sources.reasoningFromContext ??
    payloadBlock?.reasoning_summary ??
    payloadBlock?.reasoningSummary ??
    (envelope?.reasoningPath?.primaryIntent
      ? String(envelope.reasoningPath.primaryIntent)
      : '') ??
    '';

  const model =
    sources.modelFingerprint ??
    payloadBlock?.model_fingerprint ??
    payloadBlock?.modelFingerprint ??
    envelope?.modelFingerprint?.primaryModel ??
    payload.model ??
    '';

  return serializeIntentContext({
    reasoning_summary: reasoning,
    model_fingerprint: model,
  });
}

/**
 * @param {ReturnType<typeof serializeIntentContext>} intentContext
 */
export function intentContextIsPresent(intentContext) {
  const s = serializeIntentContext(intentContext);
  return s.reasoning_summary.length > 0 || s.model_fingerprint.length > 0;
}
