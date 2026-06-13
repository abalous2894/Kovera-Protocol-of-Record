import type { ParsedLiabilityReceipt } from './schema.js';
import {
  evaluateIntentAlignment,
  normalizeStructuralPayload,
  canonicalizeIntentAlignmentForDigest,
} from '../core/intentAlignment.js';

const PILLAR_IDS = ['identity', 'policy', 'hitl', 'side_effects', 'proof'] as const;

export function validateAccountabilityPillars(receipt: ParsedLiabilityReceipt): {
  ok: boolean;
  error?: string;
  pillarsValidated: string[];
} {
  const pillarsValidated: string[] = [...PILLAR_IDS];

  if (receipt.session.outcome === 'released_after_hitl') {
    if (!receipt.identity.human_release_actor) {
      return {
        ok: false,
        error: 'identity.human_release_actor required when session.outcome is released_after_hitl',
        pillarsValidated,
      };
    }
    if (receipt.hitl.status !== 'signed') {
      return {
        ok: false,
        error: 'hitl.status must be signed when session.outcome is released_after_hitl',
        pillarsValidated,
      };
    }
    if (receipt.hitl.release_consumed !== true) {
      return {
        ok: false,
        error: 'hitl.release_consumed must be true for released_after_hitl financial outcomes',
        pillarsValidated,
      };
    }
  }

  if (receipt.session.outcome === 'pending_human_release') {
    if (receipt.hitl.status !== 'pending') {
      return {
        ok: false,
        error: 'hitl.status must be pending when session.outcome is pending_human_release',
        pillarsValidated,
      };
    }
  }

  if (receipt.side_effects.effect_class === 'financial_void' && receipt.hitl.required && receipt.session.outcome === 'released_after_hitl') {
    if (!receipt.hitl.approval_request_id) {
      return {
        ok: false,
        error: 'hitl.approval_request_id required for financial_void with HITL release',
        pillarsValidated,
      };
    }
  }

  if (!receipt.diligence_summary.who_acted || !receipt.diligence_summary.what_policy_allowed || !receipt.diligence_summary.what_proof_says) {
    return {
      ok: false,
      error: 'diligence_summary narrative fields must be non-empty',
      pillarsValidated,
    };
  }

  if (receipt.intent_alignment && !receipt.intent_context) {
    return {
      ok: false,
      error: 'intent_context is required when intent_alignment is present',
      pillarsValidated,
    };
  }

  if (receipt.intent_context && receipt.intent_alignment) {
    const action = receipt.side_effects.action;
    const recomputed = evaluateIntentAlignment(
      receipt.intent_context,
      normalizeStructuralPayload({
        tool: action.tool_name,
        verb: action.verb,
        path: action.target_path,
        host: action.target_host,
        metric_value: action.metric_value,
        amount: action.metric_value,
        scopes: action.execution_scopes,
      }),
    );
    const stamped = canonicalizeIntentAlignmentForDigest(receipt.intent_alignment);
    const fresh = canonicalizeIntentAlignmentForDigest(recomputed);
    if (JSON.stringify(stamped) !== JSON.stringify(fresh)) {
      return {
        ok: false,
        error: 'intent_alignment does not match recomputed structural evaluation from intent_context and side_effects',
        pillarsValidated,
      };
    }
  }

  return { ok: true, pillarsValidated };
}
