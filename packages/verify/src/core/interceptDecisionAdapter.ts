import { sha256HexUtf8 } from './sha256.js';
import { stableStringify } from './stableStringify.js';
import { computeGatewayEventHash } from './gatewayDecisionEvent.js';

/** Wave 14 Track A — intercept vendor decision envelope normalization. */

export const AIR_SECURITY_INTERCEPT_SCHEMA = 'air.security.intercept-decision/v1' as const;
export const PORTKEY_AUDIT_LOG_SCHEMA = 'portkey.audit-log/v1' as const;

export const INTERCEPT_VENDOR_ADAPTER_IDS = [
  'portkey',
  'agent365',
  'air_security',
  'unity_gateway',
  'generic',
] as const;

export type InterceptVendorAdapterId = (typeof INTERCEPT_VENDOR_ADAPTER_IDS)[number];

export const INTERCEPT_DECISION_VALUES = ['ALLOW', 'DENY', 'QUARANTINE', 'ESCALATE'] as const;
export type InterceptDecisionValue = (typeof INTERCEPT_DECISION_VALUES)[number];

export interface InterceptToolCallFacts {
  tool_name_digest: string;
  arguments_digest: string | null;
  agent_identity_digest: string;
}

export interface InterceptDecisionEnvelope {
  vendor_adapter_id: InterceptVendorAdapterId;
  vendor_decision_id: string;
  decision: InterceptDecisionValue;
  evaluated_at: string;
  tool_call_facts: InterceptToolCallFacts;
  intercept_context_digest: string;
  policy_digest: string | null;
  gateway_event_hash: string | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function digestJson(value: unknown): string {
  return sha256HexUtf8(stableStringify(value));
}

function digestString(value: string): string {
  return sha256HexUtf8(
    stableStringify({
      schema: 'aevesa.intercept-string-digest/v1',
      value: String(value || '').trim(),
    }),
  );
}

export function mapGatewayPermitDenyToIntercept(
  decision: string | null | undefined,
): InterceptDecisionValue {
  const normalized = String(decision || '').trim().toLowerCase();
  if (normalized === 'deny') return 'DENY';
  if (normalized === 'quarantine') return 'QUARANTINE';
  if (normalized === 'escalate') return 'ESCALATE';
  return 'ALLOW';
}

export function mapInterceptDecisionToGatewayPermitDeny(
  decision: InterceptDecisionValue,
): 'permit' | 'deny' {
  if (decision === 'DENY' || decision === 'QUARANTINE') return 'deny';
  return 'permit';
}

function resolvePortkeyToolName(raw: Record<string, unknown>): string {
  const tool = asRecord(raw.tool);
  const fn = asRecord(tool?.function);
  return (
    (typeof fn?.name === 'string' && fn.name)
    || (typeof tool?.name === 'string' && tool.name)
    || (typeof raw.function_name === 'string' && raw.function_name)
    || (typeof raw.functionName === 'string' && raw.functionName)
    || (typeof raw.tool_name === 'string' && raw.tool_name)
    || 'llm.completion'
  );
}

function mapPortkeyWebhookDecision(raw: Record<string, unknown>): InterceptDecisionValue {
  if (raw.decision === 'deny' || raw.allowed === false) return 'DENY';
  const status = raw.response_status ?? raw.status_code;
  if (status === 446) return 'DENY';
  const guardrail = asRecord(raw.guardrail);
  if (guardrail?.verdict === false && guardrail.deny === true) return 'DENY';
  const hooks = Array.isArray(raw.hook_results) ? raw.hook_results : [];
  const hookFail = hooks.find((h) => {
    const hook = asRecord(h);
    return hook?.verdict === false && hook?.deny === true;
  });
  if (hookFail) return 'DENY';
  return 'ALLOW';
}

function resolveVendorAdapterFromGatewaySource(source: string): InterceptVendorAdapterId {
  const normalized = String(source || '').trim().toLowerCase();
  if (normalized === 'portkey') return 'portkey';
  if (normalized === 'microsoft_agent_365' || normalized === 'agent365') return 'agent365';
  if (normalized === 'air_security') return 'air_security';
  if (normalized === 'databricks_unity_ai' || normalized.includes('unity')) return 'unity_gateway';
  return 'generic';
}

export function buildInterceptContextDigest(input: {
  session_id?: string | null;
  correlation_id?: string | null;
  addon?: Record<string, unknown> | null;
  reasons?: string[] | null;
  data_classification_tag?: string | null;
}): string {
  return digestJson({
    schema: 'aevesa.intercept-context/v1',
    session_id: input.session_id?.trim() || null,
    correlation_id: input.correlation_id?.trim() || null,
    addon: input.addon ?? null,
    reasons: Array.isArray(input.reasons) ? [...input.reasons].sort() : null,
    data_classification_tag: input.data_classification_tag ?? null,
  });
}

export function buildPolicyDigest(policyReference: string | null | undefined): string | null {
  const ref = String(policyReference || '').trim();
  if (!ref) return null;
  return digestJson({
    schema: 'aevesa.intercept-policy-snapshot/v1',
    policy_reference: ref,
  });
}

export function buildToolCallFacts(input: {
  tool_name: string;
  arguments_digest?: string | null;
  agent_id: string;
  subject_id?: string | null;
}): InterceptToolCallFacts {
  const toolName = String(input.tool_name || '').trim() || 'unknown.tool';
  const agentId = String(input.agent_id || '').trim() || 'unknown-agent';
  return {
    tool_name_digest: digestString(toolName),
    arguments_digest: input.arguments_digest?.trim()
      ? String(input.arguments_digest).trim().toLowerCase()
      : null,
    agent_identity_digest: digestJson({
      schema: 'aevesa.agent-identity/v1',
      agent_id: agentId,
      subject_id: input.subject_id?.trim() || null,
    }),
  };
}

export function canonicalizeInterceptDecisionEnvelope(
  envelope: InterceptDecisionEnvelope,
): Record<string, unknown> {
  return {
    vendor_adapter_id: envelope.vendor_adapter_id,
    vendor_decision_id: String(envelope.vendor_decision_id || '').trim(),
    decision: envelope.decision,
    evaluated_at: String(envelope.evaluated_at || '').trim(),
    tool_call_facts: {
      tool_name_digest: String(envelope.tool_call_facts.tool_name_digest || '').toLowerCase(),
      arguments_digest: envelope.tool_call_facts.arguments_digest
        ? String(envelope.tool_call_facts.arguments_digest).toLowerCase()
        : null,
      agent_identity_digest: String(envelope.tool_call_facts.agent_identity_digest || '').toLowerCase(),
    },
    intercept_context_digest: String(envelope.intercept_context_digest || '').toLowerCase(),
    policy_digest: envelope.policy_digest
      ? String(envelope.policy_digest).toLowerCase()
      : null,
    gateway_event_hash: envelope.gateway_event_hash
      ? String(envelope.gateway_event_hash).toLowerCase()
      : null,
  };
}

export function buildInterceptDecisionEnvelopeDigest(envelope: InterceptDecisionEnvelope): string {
  return sha256HexUtf8(stableStringify(canonicalizeInterceptDecisionEnvelope(envelope)));
}

/**
 * Normalize AIR Security intercept webhook → canonical envelope.
 * Wire-shape assumptions live here only (Wave 14 containment rule).
 */
export function normalizeAirSecurityDecision(raw: unknown): InterceptDecisionEnvelope {
  const body = asRecord(raw);
  if (!body) {
    throw new Error('AIR Security intercept payload must be an object');
  }

  const decisionRaw = String(body.decision || body.verdict || '').trim().toLowerCase();
  let decision: InterceptDecisionValue = 'ALLOW';
  if (decisionRaw === 'deny' || decisionRaw === 'blocked' || decisionRaw === 'block') {
    decision = 'DENY';
  } else if (decisionRaw === 'quarantine' || decisionRaw === 'quarantined') {
    decision = 'QUARANTINE';
  } else if (decisionRaw === 'escalate' || decisionRaw === 'escalated') {
    decision = 'ESCALATE';
  } else if (decisionRaw === 'allow' || decisionRaw === 'permit') {
    decision = 'ALLOW';
  }

  const addon = asRecord(body.addon) || asRecord(body.add_on);
  const toolName =
    (typeof body.tool_name === 'string' && body.tool_name)
    || (typeof body.tool === 'string' && body.tool)
    || (typeof addon?.name === 'string' && addon.name)
    || 'mcp.tools.call';

  const agentId =
    (typeof body.agent_id === 'string' && body.agent_id)
    || (typeof body.agentId === 'string' && body.agentId)
    || 'air-agent';

  const evaluatedAt =
    (typeof body.evaluated_at === 'string' && body.evaluated_at.trim())
    || (typeof body.timestamp === 'string' && body.timestamp.trim())
    || new Date().toISOString();

  const policyRef =
    (typeof body.policy_id === 'string' && body.policy_id)
    || (typeof body.policy_reference === 'string' && body.policy_reference)
    || 'air_security/default';

  const vendorDecisionId =
    (typeof body.decision_id === 'string' && body.decision_id)
    || (typeof body.id === 'string' && body.id)
    || `air-${evaluatedAt}`;

  const sessionId =
    (typeof body.session_id === 'string' && body.session_id)
    || (typeof body.correlation_id === 'string' && body.correlation_id)
    || null;

  const argumentsDigest =
    typeof body.arguments_digest === 'string'
      ? body.arguments_digest
      : body.arguments != null
        ? digestJson(body.arguments)
        : null;

  const envelope: InterceptDecisionEnvelope = {
    vendor_adapter_id: 'air_security',
    vendor_decision_id: vendorDecisionId,
    decision,
    evaluated_at: evaluatedAt,
    tool_call_facts: buildToolCallFacts({
      tool_name: toolName,
      arguments_digest: argumentsDigest,
      agent_id: agentId,
      subject_id: typeof body.user_id === 'string' ? body.user_id : null,
    }),
    intercept_context_digest: buildInterceptContextDigest({
      session_id: sessionId,
      correlation_id: typeof body.correlation_id === 'string' ? body.correlation_id : sessionId,
      addon: addon
        ? {
            type: addon.type ?? addon.addon_type ?? 'mcp_server',
            id: addon.id ?? addon.addon_id ?? null,
            name: addon.name ?? null,
          }
        : null,
      reasons: Array.isArray(body.reasons)
        ? body.reasons.map((r) => String(r))
        : typeof body.reason === 'string'
          ? [body.reason]
          : null,
      data_classification_tag:
        typeof body.data_classification_tag === 'string'
          ? body.data_classification_tag
          : null,
    }),
    policy_digest: buildPolicyDigest(policyRef),
    gateway_event_hash: null,
  };

  return envelope;
}

/**
 * Normalize Portkey audit webhook → canonical envelope.
 */
export function normalizePortkeyDecision(raw: unknown): InterceptDecisionEnvelope {
  const body = asRecord(raw);
  if (!body) {
    throw new Error('Portkey audit payload must be an object');
  }

  const metadata = asRecord(body.metadata) || {};
  const agentId =
    (typeof metadata.agentId === 'string' && metadata.agentId)
    || (typeof metadata.agent_id === 'string' && metadata.agent_id)
    || (typeof body.virtual_key_id === 'string' && body.virtual_key_id)
    || (typeof body.virtualKeyId === 'string' && body.virtualKeyId)
    || 'portkey-agent';

  const evaluatedAt =
    (typeof body.evaluated_at === 'string' && body.evaluated_at.trim())
    || (typeof body.timestamp === 'string' && body.timestamp.trim())
    || (typeof body.created_at === 'string' && body.created_at.trim())
    || new Date().toISOString();

  const vendorDecisionId =
    (typeof body.trace_id === 'string' && body.trace_id)
    || (typeof body.request_id === 'string' && body.request_id)
    || (typeof body.id === 'string' && body.id)
    || `portkey-${evaluatedAt}`;

  const policyRef =
    (typeof body.policy_id === 'string' && body.policy_id)
    || (typeof body.config_id === 'string' && body.config_id)
    || asRecord(body.guardrail)?.name?.toString()
    || 'portkey/guardrail-default';

  const sessionId =
    (typeof body.session_id === 'string' && body.session_id)
    || (typeof metadata.sessionId === 'string' && metadata.sessionId)
    || (typeof body.correlation_id === 'string' && body.correlation_id)
    || null;

  const envelope: InterceptDecisionEnvelope = {
    vendor_adapter_id: 'portkey',
    vendor_decision_id: vendorDecisionId,
    decision: mapPortkeyWebhookDecision(body),
    evaluated_at: evaluatedAt,
    tool_call_facts: buildToolCallFacts({
      tool_name: resolvePortkeyToolName(body),
      agent_id: String(agentId),
      subject_id:
        (typeof metadata.userId === 'string' && metadata.userId)
        || (typeof metadata.user_id === 'string' && metadata.user_id)
        || (typeof body.tenant_id === 'string' ? body.tenant_id : null),
    }),
    intercept_context_digest: buildInterceptContextDigest({
      session_id: sessionId,
      correlation_id: typeof body.correlation_id === 'string' ? body.correlation_id : sessionId,
      addon: body.guardrail
        ? { type: 'guardrail', name: asRecord(body.guardrail)?.name ?? null }
        : null,
      data_classification_tag:
        typeof body.data_classification_tag === 'string'
          ? body.data_classification_tag
          : null,
    }),
    policy_digest: buildPolicyDigest(String(policyRef)),
    gateway_event_hash: null,
  };

  return envelope;
}

/**
 * Normalize aevesa.gateway-decision/v1 → canonical envelope.
 */
export function normalizeGatewayDecisionToEnvelope(
  raw: unknown,
  vendorAdapterId?: InterceptVendorAdapterId,
): InterceptDecisionEnvelope {
  const body = asRecord(raw);
  if (!body) {
    throw new Error('Gateway decision payload must be an object');
  }

  const gatewaySource = String(body.gateway_source || body.gatewaySource || 'generic');
  const vendorId = vendorAdapterId || resolveVendorAdapterFromGatewaySource(gatewaySource);
  const identity = asRecord(body.identity) || {};
  const tool = asRecord(body.tool) || {};
  const agentId =
    (typeof identity.agent_id === 'string' && identity.agent_id)
    || (typeof identity.agentId === 'string' && identity.agentId)
    || 'gateway-agent';

  const evaluatedAt =
    (typeof body.evaluated_at === 'string' && body.evaluated_at.trim())
    || new Date().toISOString();

  const gatewayEventHash = computeGatewayEventHash(body);

  return {
    vendor_adapter_id: vendorId,
    vendor_decision_id: String(body.gateway_decision_id || body.gatewayDecisionId || ''),
    decision: mapGatewayPermitDenyToIntercept(String(body.decision || '')),
    evaluated_at: evaluatedAt,
    tool_call_facts: buildToolCallFacts({
      tool_name: String(tool.name || 'unknown.tool'),
      agent_id: String(agentId),
      subject_id:
        typeof identity.subject_id === 'string'
          ? identity.subject_id
          : typeof identity.subjectId === 'string'
            ? identity.subjectId
            : null,
    }),
    intercept_context_digest: buildInterceptContextDigest({
      session_id: typeof body.session_id === 'string' ? body.session_id : null,
      correlation_id: typeof body.correlation_id === 'string' ? body.correlation_id : null,
      data_classification_tag:
        typeof body.data_classification_tag === 'string'
          ? body.data_classification_tag
          : null,
    }),
    policy_digest: buildPolicyDigest(
      typeof body.policy_reference === 'string'
        ? body.policy_reference
        : typeof body.policyReference === 'string'
          ? body.policyReference
          : null,
    ),
    gateway_event_hash: gatewayEventHash,
  };
}

export function coerceInterceptDecisionEnvelope(
  raw: unknown,
  vendorAdapterId?: InterceptVendorAdapterId | null,
): InterceptDecisionEnvelope {
  const body = asRecord(raw);
  if (!body) {
    throw new Error('Intercept decision payload must be an object');
  }

  const schema = typeof body.schema === 'string' ? body.schema : '';
  if (schema === AIR_SECURITY_INTERCEPT_SCHEMA || vendorAdapterId === 'air_security') {
    return normalizeAirSecurityDecision(body);
  }
  if (schema === PORTKEY_AUDIT_LOG_SCHEMA || vendorAdapterId === 'portkey') {
    return normalizePortkeyDecision(body);
  }
  if (schema === 'aevesa.gateway-decision/v1' || body.gateway_decision_id != null) {
    return normalizeGatewayDecisionToEnvelope(body, vendorAdapterId ?? undefined);
  }
  if (typeof body.virtual_key_id === 'string' || typeof body.virtualKeyId === 'string') {
    return normalizePortkeyDecision(body);
  }
  if (typeof body.agent_id === 'string' && typeof body.tool_name === 'string') {
    return normalizeGatewayDecisionToEnvelope(
      {
        schema: 'aevesa.gateway-decision/v1',
        gateway_decision_id: String(body.correlation_id || body.agent_id),
        gateway_source: 'air_security',
        decision: body.allowed === false ? 'deny' : 'permit',
        evaluated_at: new Date().toISOString(),
        identity: { agent_id: body.agent_id },
        tool: { name: body.tool_name },
      },
      vendorAdapterId ?? 'agent365',
    );
  }

  throw new Error('Unable to coerce intercept decision payload — unknown vendor shape');
}

export default {
  AIR_SECURITY_INTERCEPT_SCHEMA,
  PORTKEY_AUDIT_LOG_SCHEMA,
  INTERCEPT_VENDOR_ADAPTER_IDS,
  INTERCEPT_DECISION_VALUES,
  normalizeAirSecurityDecision,
  normalizePortkeyDecision,
  normalizeGatewayDecisionToEnvelope,
  coerceInterceptDecisionEnvelope,
  buildInterceptDecisionEnvelopeDigest,
  canonicalizeInterceptDecisionEnvelope,
  buildInterceptContextDigest,
  buildPolicyDigest,
  buildToolCallFacts,
  mapGatewayPermitDenyToIntercept,
  mapInterceptDecisionToGatewayPermitDeny,
};
