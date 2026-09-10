import { createHash } from 'node:crypto';
import * as jose from 'jose';
import { stableStringify } from '../core/stableStringify.js';
import { isRecord } from '../core/isRecord.js';

export const HITL_CRYPTO_BINDING_SCHEMA = 'aevesa.hitl-crypto-binding/v1' as const;
export const CAP_HITL_BINDING_SCHEMA = 'aevesa.cap-hitl-binding/v1' as const;
export const APPROVAL_WITNESS_TYPE = 'KoveraApprovalWitness' as const;

export type HitlBindingVerdict =
  | 'BOUND'
  | 'UNBOUND'
  | 'SCOPE_MISMATCH'
  | 'EXPIRED'
  | 'WITNESS_INVALID'
  | 'NO_WITNESS';

export interface HitlBindingHop {
  step_index?: number;
  tool_name: string;
  args_digest: string;
  entry_hash?: string | null;
  intent_id?: string | null;
}

export interface ApprovalWitnessPayloadLike {
  type?: string;
  version?: string;
  target_intent_hash?: string;
  operator_id?: string;
  active_policy_version_hash?: string;
  override_timestamp?: string;
  time_bound_expiry?: string;
  intent_id?: string;
  idp_sub?: string;
  tenant_id?: string;
  workforce_iss?: string;
  preferred_username?: string;
}

export interface HitlCryptoBindingResult {
  schema: typeof HITL_CRYPTO_BINDING_SCHEMA;
  ok: boolean;
  verdict: HitlBindingVerdict;
  /** Diligence field — approver witness scope matches requested tool + args binding. */
  approver_scope_subset_of_action: boolean;
  session_id: string | null;
  binding: {
    target_intent_hash: string | null;
    operator_id: string | null;
    active_policy_version_hash: string | null;
    override_timestamp: string | null;
    time_bound_expiry: string | null;
    idp_sub?: string | null;
    tenant_id?: string | null;
  };
  hop: HitlBindingHop;
  errors: string[];
  gtm_line: string;
  note: string | null;
}

export interface CapHitlBindingRecord {
  schema: typeof CAP_HITL_BINDING_SCHEMA;
  session_id: string;
  step_index: number;
  tool_name: string;
  args_digest: string;
  entry_hash?: string | null;
  intent_id?: string | null;
  approval_witness_jws?: string | null;
  target_intent_hash?: string | null;
  operator_id?: string | null;
  binding_ok: boolean;
  verdict: HitlBindingVerdict;
}

export interface SessionHitlBindingsResult {
  schema: 'aevesa.session-hitl-bindings/v1';
  ok: boolean;
  session_id: string;
  binding_count: number;
  bound_count: number;
  bindings: CapHitlBindingRecord[];
  gtm_line: string;
  note: string | null;
}

const HEX64 = /^[a-f0-9]{64}$/;

function normalizeHex64(v: unknown): string | null {
  const s = String(v ?? '').trim().toLowerCase();
  return HEX64.test(s) ? s : null;
}

/**
 * Canonical target intent hash — must match @aevesa/shared computeTargetIntentHash.
 */
export function computeTargetIntentHash(intentId: string, toolName: string, argsDigest: string): string {
  const body = stableStringify({
    intentId,
    toolName,
    argsDigest: String(argsDigest || '').toLowerCase(),
    gated: 'CRITICAL_ACTION_APPROVED',
  });
  return createHash('sha256').update(body, 'utf8').digest('hex');
}

/**
 * Session-scoped hop binding hash (CAP path correlation).
 */
export function computeCapHopBindingHash(
  sessionId: string,
  stepIndex: number,
  toolName: string,
  argsDigest: string,
): string {
  const body = stableStringify({
    session_id: String(sessionId),
    step_index: Number(stepIndex),
    tool_name: String(toolName),
    args_digest: String(argsDigest || '').toLowerCase(),
    schema: CAP_HITL_BINDING_SCHEMA,
  });
  return createHash('sha256').update(body, 'utf8').digest('hex');
}

export function parseApprovalWitnessPayload(data: unknown): ApprovalWitnessPayloadLike | null {
  if (!isRecord(data)) return null;
  if (data.type !== APPROVAL_WITNESS_TYPE) return null;
  return data as ApprovalWitnessPayloadLike;
}

function assertNotExpired(timeBoundExpiry: string, now: Date): string | null {
  const exp = Date.parse(timeBoundExpiry);
  if (Number.isNaN(exp)) return 'time_bound_expiry is not parseable';
  if (now.getTime() > exp) return 'approval witness has expired';
  return null;
}

/**
 * Structural HITL witness verify — no JWS signature (payload must be trusted or verified separately).
 */
export function verifyHitlWitnessPayloadStruct(
  payload: ApprovalWitnessPayloadLike,
  ctx: {
    intentId: string;
    toolName: string;
    argsDigest: string;
    activePolicyVersionHash?: string | null;
    now?: Date;
  },
): { ok: boolean; errors: string[] } {
  const errors: string[] = [];
  const now = ctx.now ?? new Date();

  if (payload.type !== APPROVAL_WITNESS_TYPE) {
    errors.push('witness type must be KoveraApprovalWitness');
  }
  if (payload.version !== '1.0') {
    errors.push('witness version must be 1.0');
  }

  const expectedTarget = computeTargetIntentHash(ctx.intentId, ctx.toolName, ctx.argsDigest);
  const witnessTarget = normalizeHex64(payload.target_intent_hash);
  if (!witnessTarget || witnessTarget !== expectedTarget) {
    errors.push('target_intent_hash does not match tool + args_digest binding');
  }

  if (payload.intent_id && payload.intent_id !== ctx.intentId) {
    errors.push('intent_id mismatch');
  }

  const policyHash = ctx.activePolicyVersionHash ? normalizeHex64(ctx.activePolicyVersionHash) : null;
  const witnessPolicy = normalizeHex64(payload.active_policy_version_hash);
  if (policyHash && witnessPolicy && policyHash !== witnessPolicy) {
    errors.push('active_policy_version_hash mismatch');
  }

  if (!payload.operator_id || !String(payload.operator_id).trim()) {
    errors.push('operator_id required on approval witness');
  }

  const expiryErr = payload.time_bound_expiry
    ? assertNotExpired(String(payload.time_bound_expiry), now)
    : 'time_bound_expiry required';
  if (expiryErr) errors.push(expiryErr);

  return { ok: errors.length === 0, errors };
}

/**
 * Verify compact RS256 approval witness JWS offline.
 */
export async function verifyHitlApprovalWitnessJws(
  jws: string,
  ctx: {
    intentId: string;
    toolName: string;
    argsDigest: string;
    activePolicyVersionHash?: string | null;
    now?: Date;
    issuerPublicKey?: string | Buffer;
  },
): Promise<{ ok: boolean; payload: ApprovalWitnessPayloadLike | null; errors: string[] }> {
  const errors: string[] = [];
  const compact = String(jws || '').trim();
  if (!compact || compact.split('.').length !== 3) {
    return { ok: false, payload: null, errors: ['approval_witness_jws must be a compact JWS'] };
  }
  if (!ctx.issuerPublicKey) {
    return { ok: false, payload: null, errors: ['issuerPublicKey required for JWS verification'] };
  }

  let payload: jose.JWTPayload;
  try {
    const key =
      typeof ctx.issuerPublicKey === 'string'
        ? await jose.importSPKI(ctx.issuerPublicKey, 'RS256')
        : await jose.importSPKI(String(ctx.issuerPublicKey), 'RS256');
    const verified = await jose.jwtVerify(compact, key, { algorithms: ['RS256'] });
    payload = verified.payload;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { ok: false, payload: null, errors: [`witness signature verification failed: ${msg}`] };
  }

  const parsed = parseApprovalWitnessPayload(payload);
  if (!parsed) {
    return { ok: false, payload: null, errors: ['witness payload is not KoveraApprovalWitness'] };
  }

  const structural = verifyHitlWitnessPayloadStruct(parsed, ctx);
  errors.push(...structural.errors);
  return { ok: structural.ok, payload: parsed, errors };
}

/**
 * Evaluate one HITL crypto binding — witness must cover exact tool + args_digest hop.
 */
export function evaluateHitlCryptoBinding(input: {
  session_id?: string | null;
  hop: HitlBindingHop;
  intent_id: string;
  witness_payload?: ApprovalWitnessPayloadLike | null;
  approval_witness_jws?: string | null;
  active_policy_version_hash?: string | null;
  jws_verify?: { ok: boolean; payload?: ApprovalWitnessPayloadLike | null; errors?: string[] };
  now?: Date;
}): HitlCryptoBindingResult {
  const errors: string[] = [];
  const hop = input.hop;
  const toolName = String(hop.tool_name || '').trim();
  const argsDigest = normalizeHex64(hop.args_digest);
  const intentId = String(input.intent_id || hop.intent_id || '').trim();

  if (!toolName || !argsDigest || !intentId) {
    return {
      schema: HITL_CRYPTO_BINDING_SCHEMA,
      ok: false,
      verdict: 'UNBOUND',
      approver_scope_subset_of_action: false,
      session_id: input.session_id != null ? String(input.session_id) : null,
      binding: {
        target_intent_hash: null,
        operator_id: null,
        active_policy_version_hash: null,
        override_timestamp: null,
        time_bound_expiry: null,
      },
      hop: { ...hop, tool_name: toolName, args_digest: argsDigest || String(hop.args_digest) },
      errors: ['tool_name, args_digest, and intent_id are required'],
      gtm_line:
        'Human approval must cryptographically bind to tool + args — not a ticket ID or Slack reaction alone.',
      note: 'Missing hop binding context',
    };
  }

  let payload = input.witness_payload ?? null;
  if (input.jws_verify) {
    if (!input.jws_verify.ok) {
      errors.push(...(input.jws_verify.errors ?? ['JWS verification failed']));
    } else if (input.jws_verify.payload) {
      payload = input.jws_verify.payload;
    }
  }

  if (!payload && !input.approval_witness_jws) {
    return {
      schema: HITL_CRYPTO_BINDING_SCHEMA,
      ok: false,
      verdict: 'NO_WITNESS',
      approver_scope_subset_of_action: false,
      session_id: input.session_id != null ? String(input.session_id) : null,
      binding: {
        target_intent_hash: null,
        operator_id: null,
        active_policy_version_hash: null,
        override_timestamp: null,
        time_bound_expiry: null,
      },
      hop: { ...hop, tool_name: toolName, args_digest: argsDigest, intent_id: intentId },
      errors: ['approval witness missing'],
      gtm_line:
        'Human approval must cryptographically bind to tool + args — not a ticket ID or Slack reaction alone.',
      note: 'No approval_witness_jws or witness_payload provided',
    };
  }

  if (!payload) {
    return {
      schema: HITL_CRYPTO_BINDING_SCHEMA,
      ok: false,
      verdict: 'WITNESS_INVALID',
      approver_scope_subset_of_action: false,
      session_id: input.session_id != null ? String(input.session_id) : null,
      binding: {
        target_intent_hash: null,
        operator_id: null,
        active_policy_version_hash: null,
        override_timestamp: null,
        time_bound_expiry: null,
      },
      hop: { ...hop, tool_name: toolName, args_digest: argsDigest, intent_id: intentId },
      errors: errors.length ? errors : ['witness payload unavailable after JWS verify'],
      gtm_line:
        'Human approval must cryptographically bind to tool + args — not a ticket ID or Slack reaction alone.',
      note: errors[0] || 'Witness invalid',
    };
  }

  const structural = verifyHitlWitnessPayloadStruct(payload, {
    intentId,
    toolName,
    argsDigest,
    activePolicyVersionHash: input.active_policy_version_hash ?? null,
    now: input.now,
  });
  errors.push(...structural.errors);

  let verdict: HitlBindingVerdict = 'BOUND';
  if (!structural.ok) {
    const expiryOnly =
      errors.length === 1 && errors[0] === 'approval witness has expired';
    verdict = expiryOnly ? 'EXPIRED' : 'SCOPE_MISMATCH';
  }

  const approver_scope_subset_of_action = structural.ok;

  return {
    schema: HITL_CRYPTO_BINDING_SCHEMA,
    ok: structural.ok,
    verdict,
    approver_scope_subset_of_action,
    session_id: input.session_id != null ? String(input.session_id) : null,
    binding: {
      target_intent_hash: normalizeHex64(payload.target_intent_hash),
      operator_id: payload.operator_id ? String(payload.operator_id) : null,
      active_policy_version_hash: normalizeHex64(payload.active_policy_version_hash),
      override_timestamp: payload.override_timestamp ? String(payload.override_timestamp) : null,
      time_bound_expiry: payload.time_bound_expiry ? String(payload.time_bound_expiry) : null,
      idp_sub: payload.idp_sub ? String(payload.idp_sub) : null,
      tenant_id: payload.tenant_id ? String(payload.tenant_id) : null,
    },
    hop: { ...hop, tool_name: toolName, args_digest: argsDigest, intent_id: intentId },
    errors,
    gtm_line:
      'Human approval must cryptographically bind to tool + args — not a ticket ID or Slack reaction alone.',
    note: structural.ok
      ? `Approver ${payload.operator_id} bound to ${toolName} under target_intent_hash ${normalizeHex64(payload.target_intent_hash)?.slice(0, 12)}…`
      : errors[0] || 'HITL binding verification failed',
  };
}

/**
 * Evaluate all CAP HITL binding records for a session export.
 */
export function evaluateSessionHitlBindings(
  sessionId: string,
  bindings: CapHitlBindingRecord[],
): SessionHitlBindingsResult {
  const sid = String(sessionId || '').trim();
  const bound_count = bindings.filter((b) => b.binding_ok === true).length;
  const ok = bindings.length > 0 && bound_count === bindings.length;

  return {
    schema: 'aevesa.session-hitl-bindings/v1',
    ok,
    session_id: sid,
    binding_count: bindings.length,
    bound_count,
    bindings,
    gtm_line:
      'Art. 14-grade oversight — every human release cryptographically bound to the governed hop it authorized.',
    note: ok
      ? `${bound_count} HITL binding(s) verified — approver scope matches tool + args_digest.`
      : bindings.length
        ? `${bindings.length - bound_count} binding(s) failed crypto scope check.`
        : 'No HITL_RELEASED path steps with approval witnesses.',
  };
}
