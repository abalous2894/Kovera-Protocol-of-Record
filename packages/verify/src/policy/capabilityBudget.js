/**
 * CAP Phase 1 — monotonic capability budget attenuation (ChainCaps-inspired, offline-verifiable).
 */

import { createHash } from 'node:crypto';
import { stableStringify } from '../core/stableStringify.js';

export const CAPABILITY_BUDGET_SCHEMA = 'aevesa.capability-budget/v1';

/** @type {readonly string[]} */
export const CAPABILITY_SINKS = Object.freeze([
  'external_network',
  'email',
  'database_write',
  'file_export',
  'shell_exec',
]);

const READ_TOOLS = new Set([
  'read_file',
  'read',
  'grep_search',
  'grep',
  'list_dir',
  'list_directory',
  'search_files',
  'get_file_tree',
  'mcp_read_file',
  'mcp_list_dir',
  'mcp_query_db',
]);

const TRANSFORM_TOOLS = new Set([
  'summarize',
  'transform',
  'analyze',
  'grep_search',
  'mcp_summarize',
]);

const EXPORT_SINK_TOOLS = {
  export_data: ['file_export', 'external_network'],
  export_file: ['file_export'],
  download_file: ['file_export', 'external_network'],
  bulk_export: ['file_export', 'external_network'],
  mcp_export_report: ['file_export', 'external_network'],
};

const NETWORK_SINK_TOOLS = new Set([
  'http_post',
  'http_request',
  'fetch_url',
  'send_email',
  'post_message',
  'webhook',
  'external_api',
]);

const DB_SINK_TOOLS = new Set(['sql.execute', 'sql_execute', 'database_write', 'write_db']);

const SHELL_SINK_TOOLS = new Set(['execute_command', 'run_bash', 'shell', 'system.command.execute']);

/**
 * @returns {Record<string, boolean>}
 */
export function initialCapabilityBudget() {
  /** @type {Record<string, boolean>} */
  const budget = {};
  for (const sink of CAPABILITY_SINKS) budget[sink] = true;
  return budget;
}

/**
 * @param {Record<string, boolean>} a
 * @param {Record<string, boolean>} b
 */
export function intersectCapabilityBudgets(a, b) {
  /** @type {Record<string, boolean>} */
  const out = {};
  for (const sink of CAPABILITY_SINKS) {
    out[sink] = Boolean(a?.[sink]) && Boolean(b?.[sink]);
  }
  return out;
}

/**
 * Classify tool for budget propagation.
 * @param {string} toolName
 * @param {{ pathHint?: string|null, args?: Record<string, unknown>|null }} [ctx]
 */
export function classifyToolCapability(toolName, ctx = {}) {
  const name = String(toolName || '').trim().toLowerCase() || '(unknown)';
  const pathHint = String(ctx.pathHint || ctx.args?.path || ctx.args?.file_path || '').toLowerCase();

  /** @type {string[]} */
  const sinks = [];
  let role = 'other';
  let taintClass = null;

  if (READ_TOOLS.has(name) || name.includes('read')) {
    role = 'read';
    if (/confidential|secret|pii|private|\.env|credentials|password/.test(pathHint)) {
      taintClass = 'confidential';
    } else if (/internal|hr|payroll|finance/.test(pathHint)) {
      taintClass = 'internal';
    }
  } else if (TRANSFORM_TOOLS.has(name)) {
    role = 'transform';
  }

  if (EXPORT_SINK_TOOLS[name]) {
    sinks.push(...EXPORT_SINK_TOOLS[name]);
  }
  if (NETWORK_SINK_TOOLS.has(name) || name.includes('email') || name.includes('http')) {
    if (!sinks.includes('external_network')) sinks.push('external_network');
    if (name.includes('email')) sinks.push('email');
  }
  if (DB_SINK_TOOLS.has(name) || name.startsWith('sql')) {
    sinks.push('database_write');
  }
  if (SHELL_SINK_TOOLS.has(name)) {
    sinks.push('shell_exec');
  }

  return {
    toolName: name,
    role,
    sinks: [...new Set(sinks)],
    taintClass,
  };
}

/**
 * Attenuate budget after processing a read with taint.
 * @param {Record<string, boolean>} budget
 * @param {string|null} taintClass
 */
export function attenuateBudgetForTaint(budget, taintClass) {
  const next = { ...budget };
  if (taintClass === 'confidential') {
    next.external_network = false;
    next.email = false;
    next.file_export = false;
    next.database_write = false;
  } else if (taintClass === 'internal') {
    next.external_network = false;
    next.email = false;
  }
  return next;
}

/**
 * Fold session steps into current budget state.
 * @param {Array<{ toolName?: string, tool_name?: string, verdict?: string }>} steps
 */
export function deriveCapabilityBudgetFromSteps(steps = []) {
  let budget = initialCapabilityBudget();
  let taintClass = null;
  let tainted = false;

  for (const step of steps) {
    const toolName = step.toolName || step.tool_name || '';
    if (String(step.verdict || '').toUpperCase() === 'DENY') continue;
    const pathHint = step.pathHint ?? step.path_hint ?? null;
    const cls = classifyToolCapability(toolName, { pathHint });
    if (cls.role === 'read' && cls.taintClass) {
      taintClass = cls.taintClass;
      tainted = true;
      budget = attenuateBudgetForTaint(budget, cls.taintClass);
    }
  }

  return { budget, taintClass, tainted };
}

/**
 * Evaluate proposed tool against derived budget.
 * @param {Array<{ toolName?: string, tool_name?: string, verdict?: string }>} priorSteps
 * @param {string} proposedTool
 * @param {{ pathHint?: string|null, args?: Record<string, unknown>|null }} [ctx]
 */
export function evaluateCapabilityBudget(priorSteps, proposedTool, ctx = {}) {
  const derived = deriveCapabilityBudgetFromSteps(priorSteps);
  const proposed = classifyToolCapability(proposedTool, ctx);
  const blockedSinks = proposed.sinks.filter((s) => derived.budget[s] === false);

  if (blockedSinks.length > 0) {
    return {
      allow: false,
      code: 'CAPABILITY_BUDGET_EXHAUSTED',
      message: `Permission laundering blocked: ${proposedTool} requires sinks [${proposed.sinks.join(', ')}] but budget denies [${blockedSinks.join(', ')}].`,
      budget: derived.budget,
      taintClass: derived.taintClass,
      blockedSinks,
      proposedSinks: proposed.sinks,
    };
  }

  return {
    allow: true,
    code: 'CAPABILITY_BUDGET_ALLOW',
    message: 'Capability budget permits proposed tool sinks.',
    budget: derived.budget,
    taintClass: derived.taintClass,
    blockedSinks: [],
    proposedSinks: proposed.sinks,
  };
}

/**
 * Build committed capability budget block for partial_path.
 * @param {Record<string, boolean>} budget
 * @param {string|null} taintClass
 */
export function buildCapabilityBudgetCommitment(budget, taintClass = null) {
  const body = {
    schema: CAPABILITY_BUDGET_SCHEMA,
    sinks: budget,
    ...(taintClass ? { taint_class: taintClass } : {}),
  };
  const budget_state_hash = createHash('sha256').update(stableStringify(body), 'utf8').digest('hex');
  return {
    ...body,
    budget_state_hash,
  };
}

/**
 * Verify budget_state_hash on capability_budget block.
 * @param {unknown} block
 */
export function verifyCapabilityBudgetCommitment(block) {
  if (!block || typeof block !== 'object' || Array.isArray(block)) {
    return { ok: false, code: 'INVALID_CAPABILITY_BUDGET' };
  }
  const b = /** @type {Record<string, unknown>} */ (block);
  if (b.schema !== CAPABILITY_BUDGET_SCHEMA) {
    return { ok: false, code: 'INVALID_CAPABILITY_BUDGET_SCHEMA' };
  }
  const stored = String(b.budget_state_hash || '').toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(stored)) {
    return { ok: false, code: 'MISSING_BUDGET_STATE_HASH' };
  }
  const { budget_state_hash, ...rest } = b;
  const expected = createHash('sha256').update(stableStringify(rest), 'utf8').digest('hex');
  if (expected !== stored) {
    return { ok: false, code: 'BUDGET_STATE_HASH_MISMATCH', expected, got: stored };
  }
  return { ok: true, code: 'CAPABILITY_BUDGET_VERIFIED' };
}

/**
 * Verify budget monotonicity by replaying partial_steps tool names (offline).
 * @param {Array<{ tool_name?: string, verdict?: string }>} partialSteps
 */
export function verifyBudgetMonotonicityFromPartialSteps(partialSteps) {
  if (!Array.isArray(partialSteps) || partialSteps.length === 0) {
    return { ok: true, code: 'NO_PARTIAL_STEPS' };
  }
  let prior = initialCapabilityBudget();
  for (let i = 0; i < partialSteps.length; i += 1) {
    const prefix = partialSteps.slice(0, i + 1).map((s) => ({
      toolName: s.tool_name,
      verdict: s.verdict,
      pathHint: s.path_hint ?? null,
    }));
    const { budget } = deriveCapabilityBudgetFromSteps(prefix);
    for (const sink of CAPABILITY_SINKS) {
      if (prior[sink] === false && budget[sink] === true) {
        return {
          ok: false,
          code: 'BUDGET_MONOTONICITY_VIOLATION',
          stepIndex: i,
          sink,
          message: `Sink ${sink} widened at step ${i} — permission laundering`,
        };
      }
    }
    prior = { ...budget };
  }
  return { ok: true, code: 'BUDGET_MONOTONIC' };
}

/**
 * @deprecated use verifyBudgetMonotonicityFromPartialSteps
 * @param {Array<{ capability_budget?: { sinks?: Record<string, boolean> } }>} stepBudgets
 */
export function verifyMonotonicBudgetAttenuation(stepBudgets) {
  if (!Array.isArray(stepBudgets) || stepBudgets.length === 0) {
    return { ok: true, code: 'NO_BUDGET_STEPS' };
  }
  let prior = initialCapabilityBudget();
  for (let i = 0; i < stepBudgets.length; i += 1) {
    const sinks = stepBudgets[i]?.capability_budget?.sinks;
    if (!sinks || typeof sinks !== 'object') continue;
    for (const sink of CAPABILITY_SINKS) {
      if (prior[sink] === false && sinks[sink] === true) {
        return {
          ok: false,
          code: 'BUDGET_MONOTONICITY_VIOLATION',
          stepIndex: i,
          sink,
          message: `Sink ${sink} widened at step ${i} — permission laundering`,
        };
      }
    }
    prior = intersectCapabilityBudgets(prior, sinks);
  }
  return { ok: true, code: 'BUDGET_MONOTONIC' };
}
