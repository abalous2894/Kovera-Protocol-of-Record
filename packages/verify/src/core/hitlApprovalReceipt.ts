import { sha256HexUtf8 } from './sha256.js';
import { stableStringify } from './stableStringify.js';
import {
  computeHitlPreimageDigest,
  HITL_PREIMAGE_BINDING_SCHEMA,
  type HitlBindingResult,
} from './hitlPreimageBinding.js';

/** Wave 14 Track C — HITL approval receipt (GAP-04 / ASI09). */

export const HITL_APPROVAL_RECEIPT_SCHEMA = 'aevesa.hitl-approval-receipt/v1' as const;

export const HITL_APPROVAL_DECISIONS = ['APPROVE', 'DENY'] as const;
export type HitlApprovalDecision = (typeof HITL_APPROVAL_DECISIONS)[number];

export const HITL_APPROVAL_CHANNELS = ['slack', 'teams', 'dashboard', 'api'] as const;
export type HitlApprovalChannel = (typeof HITL_APPROVAL_CHANNELS)[number];

export type ApprovalReadiness = 'asi09_ready' | 'partial' | 'unverified';

export interface HitlPreimageBindingMember {
  schema: typeof HITL_PREIMAGE_BINDING_SCHEMA;
  session_id: string;
  approval_request_id?: string;
  human_visible_digest: string;
  gate_evaluation_digest: string;
  binding_result: HitlBindingResult;
  binding_digest: string;
}

export interface SessionChainBinding {
  session_id: string;
  required_entry_hash: string | null;
  release_entry_hash: string | null;
  content_digest: string;
  normalization_bound: boolean;
}

export interface ApprovalAssertionsInput {
  third_party_verifiable: boolean;
}

export interface HitlApprovalReceiptInput {
  organization_id: string;
  session_id: string;
  approval_request_id: string;
  generated_at?: string;
  approved_at: string;
  decision: HitlApprovalDecision;
  channel: HitlApprovalChannel;
  tool_name: string;
  content_digest: string;
  arguments_digest?: string | null;
  approver_identity_digest: string;
  hitl_preimage_binding: HitlPreimageBindingMember;
  session_chain_binding: SessionChainBinding;
  approval_assertions: ApprovalAssertionsInput;
  disclaimer?: string;
}

export function buildApproverIdentityDigest(input: {
  approver_id: string;
  channel?: HitlApprovalChannel;
  okta_uid?: string | null;
  slack_user_id?: string | null;
  email_digest?: string | null;
}): string {
  return sha256HexUtf8(
    stableStringify({
      schema: 'aevesa.approver-identity/v1',
      approver_id: String(input.approver_id || '').trim(),
      channel: input.channel ?? 'api',
      okta_uid: input.okta_uid?.trim() || null,
      slack_user_id: input.slack_user_id?.trim() || null,
      email_digest: input.email_digest?.trim()?.toLowerCase() || null,
    }),
  );
}

export function computeApprovalContentDigest(gateEvaluationPreimage: unknown): string {
  return computeHitlPreimageDigest(gateEvaluationPreimage);
}

export function deriveApprovalReadiness(
  preimageBindingMatch: boolean,
  contentDigestMatches: boolean,
  thirdPartyVerifiable: boolean,
  normalizationBound: boolean,
  chainLinked: boolean,
): ApprovalReadiness {
  if (
    preimageBindingMatch
    && contentDigestMatches
    && thirdPartyVerifiable
    && normalizationBound
    && chainLinked
  ) {
    return 'asi09_ready';
  }
  if (preimageBindingMatch && contentDigestMatches && thirdPartyVerifiable && normalizationBound) {
    return 'partial';
  }
  return 'unverified';
}

export function buildApprovalAssertionsBlock(
  input: ApprovalAssertionsInput,
  preimageBindingMatch: boolean,
  contentDigestMatches: boolean,
  normalizationBound: boolean,
  chainLinked: boolean,
) {
  const content_bound = contentDigestMatches && preimageBindingMatch;
  const approval_readiness = deriveApprovalReadiness(
    preimageBindingMatch,
    contentDigestMatches,
    input.third_party_verifiable === true,
    normalizationBound,
    chainLinked,
  );

  return {
    third_party_verifiable: input.third_party_verifiable === true,
    preimage_binding_match: preimageBindingMatch,
    content_bound,
    approval_readiness,
  };
}

export function buildHitlApprovalReceiptPreimage(
  input: Omit<HitlApprovalReceiptInput, 'disclaimer' | 'approval_assertions'> & {
    generated_at: string;
    approval_assertions: ReturnType<typeof buildApprovalAssertionsBlock>;
  },
): Record<string, unknown> {
  const binding = input.session_chain_binding;
  const member = input.hitl_preimage_binding;

  return {
    schema: HITL_APPROVAL_RECEIPT_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    session_id: String(input.session_id || '').trim(),
    approval_request_id: String(input.approval_request_id || '').trim(),
    generated_at: input.generated_at,
    approved_at: String(input.approved_at || '').trim(),
    decision: input.decision,
    channel: input.channel,
    tool_name: String(input.tool_name || '').trim(),
    content_digest: String(input.content_digest || '').trim().toLowerCase(),
    arguments_digest: input.arguments_digest
      ? String(input.arguments_digest).trim().toLowerCase()
      : null,
    approver_identity_digest: String(input.approver_identity_digest || '').trim().toLowerCase(),
    hitl_preimage_binding: {
      schema: HITL_PREIMAGE_BINDING_SCHEMA,
      session_id: String(member.session_id || '').trim(),
      ...(member.approval_request_id
        ? { approval_request_id: String(member.approval_request_id).trim() }
        : {}),
      human_visible_digest: String(member.human_visible_digest || '').toLowerCase(),
      gate_evaluation_digest: String(member.gate_evaluation_digest || '').toLowerCase(),
      binding_result: member.binding_result,
      binding_digest: String(member.binding_digest || '').toLowerCase(),
    },
    session_chain_binding: {
      session_id: String(binding.session_id || '').trim(),
      required_entry_hash: binding.required_entry_hash
        ? String(binding.required_entry_hash).trim().toLowerCase()
        : null,
      release_entry_hash: binding.release_entry_hash
        ? String(binding.release_entry_hash).trim().toLowerCase()
        : null,
      content_digest: String(binding.content_digest || '').trim().toLowerCase(),
      normalization_bound: binding.normalization_bound === true,
    },
    approval_assertions: input.approval_assertions,
  };
}

export interface HitlApprovalReceiptDocument {
  schema: typeof HITL_APPROVAL_RECEIPT_SCHEMA;
  organization_id: string;
  session_id: string;
  approval_request_id: string;
  generated_at: string;
  approved_at: string;
  decision: HitlApprovalDecision;
  channel: HitlApprovalChannel;
  tool_name: string;
  content_digest: string;
  arguments_digest: string | null;
  approver_identity_digest: string;
  hitl_preimage_binding: HitlPreimageBindingMember;
  session_chain_binding: SessionChainBinding;
  approval_assertions: ReturnType<typeof buildApprovalAssertionsBlock>;
  approval_digest: string;
  disclaimer: string;
}

export function buildHitlApprovalReceiptDocument(
  input: HitlApprovalReceiptInput,
): HitlApprovalReceiptDocument {
  const generated_at = input.generated_at || new Date().toISOString();
  const member = input.hitl_preimage_binding;
  const preimageBindingMatch = member.binding_result === 'MATCH';
  const contentDigestMatches =
    String(input.content_digest || '').toLowerCase() ===
    String(member.gate_evaluation_digest || '').toLowerCase();
  const chainLinked =
    input.session_chain_binding.required_entry_hash != null
    && input.session_chain_binding.release_entry_hash != null;

  const approval_assertions = buildApprovalAssertionsBlock(
    input.approval_assertions,
    preimageBindingMatch,
    contentDigestMatches,
    input.session_chain_binding.normalization_bound === true,
    chainLinked,
  );

  const preimage = buildHitlApprovalReceiptPreimage({
    ...input,
    generated_at,
    approval_assertions,
  });
  const approval_digest = sha256HexUtf8(stableStringify(preimage));

  return {
    ...(preimage as Omit<HitlApprovalReceiptDocument, 'approval_digest' | 'disclaimer'>),
    approval_digest,
    disclaimer:
      input.disclaimer ??
      'HITL approval receipt — proves yes-to-what for ASI09; not legal advice.',
  };
}

export default {
  HITL_APPROVAL_RECEIPT_SCHEMA,
  buildHitlApprovalReceiptDocument,
  buildHitlApprovalReceiptPreimage,
  buildApprovalAssertionsBlock,
  buildApproverIdentityDigest,
  computeApprovalContentDigest,
  deriveApprovalReadiness,
};
