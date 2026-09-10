import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';

export const HITL_PREIMAGE_BINDING_SCHEMA = 'aevesa.hitl-preimage-binding/v1' as const;

export const HITL_BINDING_RESULTS = ['MATCH', 'DIVERGENCE'] as const;
export type HitlBindingResult = (typeof HITL_BINDING_RESULTS)[number];

export interface HitlPreimageBindingInput {
  session_id: string;
  approval_request_id?: string;
  human_visible_preimage: unknown;
  gate_evaluation_preimage: unknown;
}



export function computeHitlPreimageDigest(preimage: unknown): string {
  return sha256HexUtf8(stableStringify(preimage ?? {}));
}

/**
 * Compare human-visible UI preimage vs gate evaluation preimage (HITL semantic binding).
 */
export function evaluateHitlPreimageBinding(input: HitlPreimageBindingInput): {
  human_visible_digest: string;
  gate_evaluation_digest: string;
  binding_result: HitlBindingResult;
  binding_digest: string;
} {
  const human_visible_digest = computeHitlPreimageDigest(input.human_visible_preimage);
  const gate_evaluation_digest = computeHitlPreimageDigest(input.gate_evaluation_preimage);
  const binding_result: HitlBindingResult =
    human_visible_digest === gate_evaluation_digest ? 'MATCH' : 'DIVERGENCE';

  const binding_digest = sha256HexUtf8(
    stableStringify({
      schema: HITL_PREIMAGE_BINDING_SCHEMA,
      session_id: String(input.session_id).trim(),
      ...(input.approval_request_id
        ? { approval_request_id: String(input.approval_request_id).trim() }
        : {}),
      human_visible_digest,
      gate_evaluation_digest,
      binding_result,
    }),
  );

  return {
    human_visible_digest,
    gate_evaluation_digest,
    binding_result,
    binding_digest,
  };
}

export function buildHitlPreimageBindingDocument(
  input: HitlPreimageBindingInput,
): Record<string, unknown> {
  const evalResult = evaluateHitlPreimageBinding(input);
  return {
    schema: HITL_PREIMAGE_BINDING_SCHEMA,
    session_id: String(input.session_id).trim(),
    ...(input.approval_request_id
      ? { approval_request_id: String(input.approval_request_id).trim() }
      : {}),
    human_visible_digest: evalResult.human_visible_digest,
    gate_evaluation_digest: evalResult.gate_evaluation_digest,
    binding_result: evalResult.binding_result,
    binding_digest: evalResult.binding_digest,
  };
}

export function computeHitlBindingDigestFromFields(input: {
  session_id: string;
  approval_request_id?: string;
  human_visible_digest: string;
  gate_evaluation_digest: string;
  binding_result: HitlBindingResult;
}): string {
  return sha256HexUtf8(
    stableStringify({
      schema: HITL_PREIMAGE_BINDING_SCHEMA,
      session_id: String(input.session_id).trim(),
      ...(input.approval_request_id
        ? { approval_request_id: String(input.approval_request_id).trim() }
        : {}),
      human_visible_digest: input.human_visible_digest,
      gate_evaluation_digest: input.gate_evaluation_digest,
      binding_result: input.binding_result,
    }),
  );
}
