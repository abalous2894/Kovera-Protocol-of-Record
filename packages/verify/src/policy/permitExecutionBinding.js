/**
 * CAP Phase 2 — offline-verifiable permit ↔ execution parameter binding.
 */

import { createHash } from 'node:crypto';
import { stableStringify } from '../core/stableStringify.js';

export const PERMIT_EXECUTION_BINDING_SCHEMA = 'aevesa.permit-execution-binding/v1';
export const MANIFEST_CUSTODIAN_SCHEMA = 'aevesa.session-manifest-custodian/v1';

const HEX64 = /^[a-f0-9]{64}$/;

/**
 * @param {unknown} value
 */
export function canonicalizeToolArgs(value) {
  if (value == null) return value;
  if (Array.isArray(value)) return value.map((x) => canonicalizeToolArgs(x));
  if (typeof value === 'object') {
    const obj = /** @type {Record<string, unknown>} */ (value);
    return Object.keys(obj)
      .sort()
      .reduce((acc, k) => {
        acc[k] = canonicalizeToolArgs(obj[k]);
        return acc;
      }, /** @type {Record<string, unknown>} */ ({}));
  }
  return value;
}

/**
 * @param {unknown} args
 */
export function computeArgsDigest(args) {
  const canonical = canonicalizeToolArgs(args ?? {});
  return createHash('sha256').update(stableStringify(canonical), 'utf8').digest('hex');
}

/**
 * MCP hot-path binding digest (tool name + arguments envelope).
 * @param {string} toolName
 * @param {unknown} args
 */
export function computeToolParamsBindingDigest(toolName, args) {
  const name = String(toolName || '').trim();
  const payload = stableStringify({ name, arguments: canonicalizeToolArgs(args ?? {}) });
  return createHash('sha256').update(payload, 'utf8').digest('hex');
}

/**
 * @param {string} toolName
 * @param {unknown} args
 */
export function buildPermitExecutionStepBinding(toolName, args) {
  const canonical = canonicalizeToolArgs(args ?? {});
  const args_digest = computeArgsDigest(canonical);
  const binding_digest = computeToolParamsBindingDigest(toolName, canonical);
  return { args_digest, binding_digest };
}

/**
 * Build committed permit_execution block for partial_path.
 * @param {Array<{ index?: number, tool_name?: string, args_digest?: string|null, binding_digest?: string|null }>} partialSteps
 */
export function buildPermitExecutionCommitment(partialSteps = []) {
  const step_bindings = partialSteps.map((s, i) => ({
    index: s.index ?? i,
    tool_name: s.tool_name ?? '(unknown)',
    args_digest: String(s.args_digest || '').toLowerCase(),
    binding_digest: String(s.binding_digest || '').toLowerCase(),
  }));

  const body = {
    schema: PERMIT_EXECUTION_BINDING_SCHEMA,
    step_bindings,
  };
  const binding_state_hash = createHash('sha256').update(stableStringify(body), 'utf8').digest('hex');
  return {
    ...body,
    binding_state_hash,
  };
}

/**
 * @param {unknown} block
 */
export function verifyPermitExecutionCommitment(block) {
  if (!block || typeof block !== 'object' || Array.isArray(block)) {
    return { ok: false, code: 'INVALID_PERMIT_EXECUTION' };
  }
  const b = /** @type {Record<string, unknown>} */ (block);
  if (b.schema !== PERMIT_EXECUTION_BINDING_SCHEMA) {
    return { ok: false, code: 'INVALID_PERMIT_EXECUTION_SCHEMA' };
  }
  const stored = String(b.binding_state_hash || '').toLowerCase();
  if (!HEX64.test(stored)) {
    return { ok: false, code: 'MISSING_BINDING_STATE_HASH' };
  }
  const { binding_state_hash, ...rest } = b;
  const expected = createHash('sha256').update(stableStringify(rest), 'utf8').digest('hex');
  if (expected !== stored) {
    return { ok: false, code: 'BINDING_STATE_HASH_MISMATCH', expected, got: stored };
  }
  return { ok: true, code: 'PERMIT_EXECUTION_VERIFIED' };
}

/**
 * Verify partial_steps carry valid digests aligned with permit_execution block when present.
 * @param {Array<{ tool_name?: string, args_digest?: string|null, binding_digest?: string|null }>} partialSteps
 * @param {unknown} permitExecutionBlock
 */
export function verifyPartialStepsPermitExecution(partialSteps, permitExecutionBlock = null) {
  if (!Array.isArray(partialSteps) || partialSteps.length === 0) {
    return { ok: true, code: 'NO_PARTIAL_STEPS' };
  }

  for (let i = 0; i < partialSteps.length; i += 1) {
    const step = partialSteps[i];
    const argsDigest = step?.args_digest != null ? String(step.args_digest).toLowerCase() : null;
    const bindingDigest = step?.binding_digest != null ? String(step.binding_digest).toLowerCase() : null;
    if (argsDigest && !HEX64.test(argsDigest)) {
      return { ok: false, code: 'INVALID_ARGS_DIGEST', stepIndex: i };
    }
    if (bindingDigest && !HEX64.test(bindingDigest)) {
      return { ok: false, code: 'INVALID_BINDING_DIGEST', stepIndex: i };
    }
  }

  if (permitExecutionBlock) {
    const verify = verifyPermitExecutionCommitment(permitExecutionBlock);
    if (!verify.ok) return verify;
    const bindings = /** @type {{ step_bindings?: unknown[] }} */ (permitExecutionBlock).step_bindings;
    if (!Array.isArray(bindings)) {
      return { ok: false, code: 'MISSING_STEP_BINDINGS' };
    }
    for (const binding of bindings) {
      if (!binding || typeof binding !== 'object') continue;
      const b = /** @type {Record<string, unknown>} */ (binding);
      const idx = Number(b.index);
      const step = partialSteps[idx];
      if (!step) {
        return { ok: false, code: 'BINDING_STEP_INDEX_OUT_OF_RANGE', stepIndex: idx };
      }
      if (String(step.args_digest || '').toLowerCase() !== String(b.args_digest || '').toLowerCase()) {
        return { ok: false, code: 'ARGS_DIGEST_STEP_MISMATCH', stepIndex: idx };
      }
      if (String(step.binding_digest || '').toLowerCase() !== String(b.binding_digest || '').toLowerCase()) {
        return { ok: false, code: 'BINDING_DIGEST_STEP_MISMATCH', stepIndex: idx };
      }
    }
  }

  return { ok: true, code: 'PARTIAL_STEPS_PERMIT_EXECUTION_OK' };
}

/**
 * When member receipts include side_effects.action.args_digest, verify alignment with partial_steps.
 * @param {Array<{ tool_name?: string, args_digest?: string|null }>} partialSteps
 * @param {unknown[]} memberReceipts
 */
export function verifyMemberReceiptsArgsAlignment(partialSteps, memberReceipts) {
  if (!Array.isArray(memberReceipts) || memberReceipts.length === 0) {
    return { ok: true, code: 'NO_MEMBER_RECEIPTS' };
  }
  const errors = [];
  for (let i = 0; i < memberReceipts.length; i += 1) {
    const receipt = memberReceipts[i];
    if (!receipt || typeof receipt !== 'object') continue;
    const r = /** @type {Record<string, unknown>} */ (receipt);
    const sideEffects = r.side_effects;
    if (!sideEffects || typeof sideEffects !== 'object') continue;
    const action = /** @type {Record<string, unknown>} */ (sideEffects).action;
    if (!action || typeof action !== 'object') continue;
    const receiptArgsDigest =
      action.args_digest != null ? String(action.args_digest).toLowerCase() : null;
    if (!receiptArgsDigest || !HEX64.test(receiptArgsDigest)) continue;

    const step = partialSteps[i];
    if (!step) {
      errors.push(`member ${i}: partial_step missing for args_digest alignment`);
      continue;
    }
    const stepDigest = step.args_digest != null ? String(step.args_digest).toLowerCase() : null;
    if (stepDigest && stepDigest !== receiptArgsDigest) {
      errors.push(`member ${i}: args_digest mismatch — permit laundering`);
    }
  }
  return errors.length === 0
    ? { ok: true, code: 'MEMBER_ARGS_ALIGNED' }
    : { ok: false, code: 'MEMBER_ARGS_MISMATCH', errors };
}

/**
 * @param {{ session_id?: string, set_root?: string, witness_entry_hash?: string|null }} input
 */
export function buildManifestCustodianCommitment(input = {}) {
  const body = {
    schema: MANIFEST_CUSTODIAN_SCHEMA,
    session_id: input.session_id ?? null,
    set_root: String(input.set_root || '').toLowerCase(),
    witness_entry_hash: input.witness_entry_hash != null ? String(input.witness_entry_hash).toLowerCase() : null,
  };
  const custodian_digest = createHash('sha256').update(stableStringify(body), 'utf8').digest('hex');
  return {
    ...body,
    custodian_digest,
  };
}

/**
 * @param {unknown} block
 * @param {{ set_root?: string, session_id?: string, witness_entry_hash?: string|null }} [expected]
 */
export function verifyManifestCustodianCommitment(block, expected = {}) {
  if (!block || typeof block !== 'object' || Array.isArray(block)) {
    return { ok: false, code: 'INVALID_MANIFEST_CUSTODIAN' };
  }
  const b = /** @type {Record<string, unknown>} */ (block);
  if (b.schema !== MANIFEST_CUSTODIAN_SCHEMA) {
    return { ok: false, code: 'INVALID_MANIFEST_CUSTODIAN_SCHEMA' };
  }
  const stored = String(b.custodian_digest || '').toLowerCase();
  if (!HEX64.test(stored)) {
    return { ok: false, code: 'MISSING_CUSTODIAN_DIGEST' };
  }
  const { custodian_digest, ...rest } = b;
  const recomputed = createHash('sha256').update(stableStringify(rest), 'utf8').digest('hex');
  if (recomputed !== stored) {
    return { ok: false, code: 'CUSTODIAN_DIGEST_MISMATCH', expected: recomputed, got: stored };
  }
  if (expected.set_root && String(b.set_root || '').toLowerCase() !== String(expected.set_root).toLowerCase()) {
    return { ok: false, code: 'SET_ROOT_MISMATCH' };
  }
  if (expected.session_id && String(b.session_id || '') !== String(expected.session_id)) {
    return { ok: false, code: 'SESSION_ID_MISMATCH' };
  }
  if (
    expected.witness_entry_hash &&
    String(b.witness_entry_hash || '').toLowerCase() !== String(expected.witness_entry_hash).toLowerCase()
  ) {
    return { ok: false, code: 'WITNESS_ENTRY_HASH_MISMATCH' };
  }
  return { ok: true, code: 'MANIFEST_CUSTODIAN_VERIFIED' };
}
