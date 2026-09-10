import { sha256HexUtf8 } from '../core/sha256.js';
import { stableStringify } from '../core/stableStringify.js';
import {
  buildHitlApprovalReceiptPreimage,
  HITL_APPROVAL_RECEIPT_SCHEMA,
  type ApprovalReadiness,
} from '../core/hitlApprovalReceipt.js';
import {
  HITL_APPROVAL_CHANNELS,
  HITL_APPROVAL_DECISIONS,
} from '../core/hitlApprovalReceipt.js';
import { verifyHitlPreimageBindingBundle } from './hitlPreimageBindingVerify.js';

export const HITL_APPROVAL_RECEIPT_SKU = 'aevesa-hitl-approval-receipt-v1' as const;

const HEX64 = /^[a-f0-9]{64}$/;
const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|ssn|phone|address|pan|cvv)$/i;

export interface HitlApprovalReceiptVerifyOptions {
  requireMatch?: boolean;
  requireChainLink?: boolean;
}

export interface HitlApprovalReceiptVerifyResult {
  schema: typeof HITL_APPROVAL_RECEIPT_SCHEMA;
  sku: typeof HITL_APPROVAL_RECEIPT_SKU;
  ok: boolean;
  checks: Record<string, boolean>;
  approval_readiness: ApprovalReadiness | null;
  profileComplete: boolean;
  gtmLine: string;
  note: string | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function hasForbiddenKeys(value: unknown, depth = 0): boolean {
  if (depth > 8 || value == null) return false;
  if (Array.isArray(value)) return value.some((v) => hasForbiddenKeys(v, depth + 1));
  if (typeof value !== 'object') return false;
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (FORBIDDEN_KEYS.test(key)) return true;
    if (hasForbiddenKeys(child, depth + 1)) return true;
  }
  return false;
}

export function verifyHitlApprovalReceipt(
  docInput: unknown,
  options: HitlApprovalReceiptVerifyOptions = {},
): HitlApprovalReceiptVerifyResult {
  const doc = asRecord(docInput);
  const schemaValid = doc?.schema === HITL_APPROVAL_RECEIPT_SCHEMA;
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;
  const sessionIdPresent = String(doc?.session_id || '').trim().length > 0;
  const approvalRequestIdPresent = String(doc?.approval_request_id || '').trim().length > 0;
  const approvedAtPresent = String(doc?.approved_at || '').trim().length > 0;
  const generatedAtPresent = String(doc?.generated_at || '').trim().length > 0;
  const toolNamePresent = String(doc?.tool_name || '').trim().length > 0;

  const decisionValid = HITL_APPROVAL_DECISIONS.includes(
    String(doc?.decision || '') as (typeof HITL_APPROVAL_DECISIONS)[number],
  );
  const channelValid = HITL_APPROVAL_CHANNELS.includes(
    String(doc?.channel || '') as (typeof HITL_APPROVAL_CHANNELS)[number],
  );

  const contentDigestValid = HEX64.test(String(doc?.content_digest || '').toLowerCase());
  const approvalDigestValid = HEX64.test(String(doc?.approval_digest || '').toLowerCase());
  const approverDigestValid = HEX64.test(String(doc?.approver_identity_digest || '').toLowerCase());

  const argumentsDigestRaw = doc?.arguments_digest;
  const argumentsDigestValid =
    argumentsDigestRaw == null || HEX64.test(String(argumentsDigestRaw).toLowerCase());

  const member = asRecord(doc?.hitl_preimage_binding) || {};
  const preimageVerify = verifyHitlPreimageBindingBundle(member, {
    requireMatch: options.requireMatch === true,
  });
  const preimageBindingValid = preimageVerify.ok === true;
  const preimageBindingMatch = preimageVerify.checks.bindingMatch === true;

  const contentDigestMatches =
    contentDigestValid &&
    HEX64.test(String(member.gate_evaluation_digest || '').toLowerCase()) &&
    String(doc?.content_digest || '').toLowerCase() ===
      String(member.gate_evaluation_digest || '').toLowerCase();

  const binding = asRecord(doc?.session_chain_binding) || {};
  const normalizationBound = binding.normalization_bound === true;
  const bindingContentDigestValid = HEX64.test(String(binding.content_digest || '').toLowerCase());
  const requiredHashRaw = binding.required_entry_hash;
  const releaseHashRaw = binding.release_entry_hash;
  const requiredHashValid =
    requiredHashRaw == null || HEX64.test(String(requiredHashRaw).toLowerCase());
  const releaseHashValid =
    releaseHashRaw == null || HEX64.test(String(releaseHashRaw).toLowerCase());

  const bindingMatchesFields =
    String(binding.session_id || '') === String(doc?.session_id || '') &&
    String(binding.content_digest || '').toLowerCase() ===
      String(doc?.content_digest || '').toLowerCase();

  const chainLinked =
    requiredHashRaw != null
    && releaseHashRaw != null
    && requiredHashValid
    && releaseHashValid;

  const hashOnlySurface = doc != null && !hasForbiddenKeys(doc);

  const assertions = asRecord(doc?.approval_assertions) || {};
  const derivedReadiness = String(assertions.approval_readiness || '') as ApprovalReadiness;

  let approvalAssertionsConsistent =
    assertions.third_party_verifiable === true && sessionIdPresent && approvalRequestIdPresent;

  if (derivedReadiness === 'asi09_ready') {
    approvalAssertionsConsistent =
      approvalAssertionsConsistent &&
      assertions.preimage_binding_match === true &&
      assertions.content_bound === true &&
      preimageBindingMatch &&
      contentDigestMatches &&
      bindingMatchesFields &&
      normalizationBound &&
      chainLinked;
  } else if (derivedReadiness === 'partial') {
    approvalAssertionsConsistent =
      approvalAssertionsConsistent &&
      assertions.preimage_binding_match === true &&
      assertions.content_bound === true &&
      preimageBindingMatch &&
      contentDigestMatches &&
      bindingMatchesFields &&
      normalizationBound;
  }

  const readinessConsistent = assertions.approval_readiness === derivedReadiness;

  let approvalDigestMatches = false;
  if (schemaValid && doc && bindingContentDigestValid && preimageBindingValid) {
    const preimage = buildHitlApprovalReceiptPreimage({
      organization_id: String(doc.organization_id),
      session_id: String(doc.session_id),
      approval_request_id: String(doc.approval_request_id),
      generated_at: String(doc.generated_at || ''),
      approved_at: String(doc.approved_at),
      decision: String(doc.decision) as never,
      channel: String(doc.channel) as never,
      tool_name: String(doc.tool_name),
      content_digest: String(doc.content_digest),
      arguments_digest: argumentsDigestRaw != null ? String(argumentsDigestRaw) : null,
      approver_identity_digest: String(doc.approver_identity_digest),
      hitl_preimage_binding: member as never,
      session_chain_binding: {
        session_id: String(binding.session_id || ''),
        required_entry_hash:
          requiredHashRaw != null ? String(requiredHashRaw) : null,
        release_entry_hash: releaseHashRaw != null ? String(releaseHashRaw) : null,
        content_digest: String(binding.content_digest || ''),
        normalization_bound: normalizationBound,
      },
      approval_assertions: {
        third_party_verifiable: assertions.third_party_verifiable === true,
        preimage_binding_match: assertions.preimage_binding_match === true,
        content_bound: assertions.content_bound === true,
        approval_readiness: derivedReadiness,
      },
    });
    approvalDigestMatches =
      sha256HexUtf8(stableStringify(preimage)) ===
      String(doc.approval_digest || '').toLowerCase();
  }

  const chainRequired = options.requireChainLink === true;
  const chainOk = !chainRequired || chainLinked;

  const profileComplete =
    schemaValid &&
    organizationIdPresent &&
    sessionIdPresent &&
    approvalRequestIdPresent &&
    approvedAtPresent &&
    generatedAtPresent &&
    toolNamePresent &&
    decisionValid &&
    channelValid &&
    contentDigestMatches &&
    approvalDigestMatches &&
    approverDigestValid &&
    argumentsDigestValid &&
    preimageBindingValid &&
    hashOnlySurface &&
    bindingMatchesFields &&
    normalizationBound &&
    approvalAssertionsConsistent &&
    readinessConsistent &&
    chainOk;

  const ok = profileComplete;

  let note: string | null = null;
  if (!schemaValid) {
    note = `schema must be ${HITL_APPROVAL_RECEIPT_SCHEMA}`;
  } else if (!contentDigestMatches) {
    note = 'content_digest does not match hitl_preimage_binding.gate_evaluation_digest';
  } else if (!approvalDigestMatches) {
    note = 'approval_digest does not match preimage';
  } else if (!preimageBindingMatch && options.requireMatch !== false) {
    note = 'HITL preimage binding requires binding_result MATCH for ASI09 approval';
  } else if (!hashOnlySurface) {
    note = 'document contains forbidden raw identity keys';
  } else if (!chainOk) {
    note = 'session_chain_binding requires required_entry_hash and release_entry_hash';
  } else if (!approvalAssertionsConsistent) {
    note = 'approval_assertions inconsistent with derived checks';
  }

  return {
    schema: HITL_APPROVAL_RECEIPT_SCHEMA,
    sku: HITL_APPROVAL_RECEIPT_SKU,
    ok,
    checks: {
      schemaValid: schemaValid === true,
      organizationIdPresent: organizationIdPresent === true,
      sessionIdPresent: sessionIdPresent === true,
      approvalRequestIdPresent: approvalRequestIdPresent === true,
      decisionValid: decisionValid === true,
      channelValid: channelValid === true,
      contentDigestMatches: contentDigestMatches === true,
      approvalDigestMatches: approvalDigestMatches === true,
      approverDigestValid: approverDigestValid === true,
      argumentsDigestValid: argumentsDigestValid === true,
      preimageBindingValid: preimageBindingValid === true,
      preimageBindingMatch: preimageBindingMatch === true,
      hashOnlySurface: hashOnlySurface === true,
      bindingMatchesFields: bindingMatchesFields === true,
      normalizationBound: normalizationBound === true,
      approvalAssertionsConsistent: approvalAssertionsConsistent === true,
      readinessConsistent: readinessConsistent === true,
      chainLinked: chainLinked === true,
      chainOk: chainOk === true,
      profileComplete: profileComplete === true,
    },
    approval_readiness: derivedReadiness || null,
    profileComplete,
    gtmLine:
      'Slack said yes. Aevesa proves yes to what — offline, ASI09-shaped, independent of the orchestrator.',
    note,
  };
}

export default { verifyHitlApprovalReceipt, HITL_APPROVAL_RECEIPT_SKU };
