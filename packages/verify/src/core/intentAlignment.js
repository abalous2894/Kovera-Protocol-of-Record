/**
 * KVR-101 — Unified structural intent alignment (deterministic, zero I/O).
 * Compares intent_context to normalized execution parameters.
 */

import { canonicalize } from './canonicalize.js';
import { serializeIntentContext } from './intentContext.js';

export const INTENT_ALIGNMENT_LEVEL = Object.freeze({
  ALIGNED: 'ALIGNED',
  ELEVATED: 'ELEVATED',
  CRITICAL: 'CRITICAL',
});

export const MAX_INTENT_ALIGNMENT_SIGNALS = 16;

const FINANCIAL_REASONING_RE =
  /\b(payment|transfer|void|refund|wire|ach|invoice|charge|withdraw|deposit|treasury|settlement|amount|usd|\$\d)\b/i;
const BENIGN_MAINTENANCE_RE =
  /\b(format|formatting|backup|log|archive|archival|rotate|retention|housekeeping|maintenance|compress|export\s+log)\b/i;
const BENIGN_EXTERNAL_RE =
  /\b(external|vendor|api|service|endpoint|saas|cloud|remote|upstream)\b/i;
const PRIVILEGE_REASONING_RE =
  /\b(admin|root|sudo|elevated|privileged|escalat|superuser|capability)\b/i;
const READ_ONLY_REASONING_RE =
  /\b(read|view|list|fetch|get|verify|check|confirm|inspect|audit|monitor)\b/i;

const RESTRICTED_PATH_RE =
  /(?:^|[\\/])(?:proc|sys|dev)(?:[\\/]|$)|(?:^|[\\/])etc[\\/](?:passwd|shadow|sudoers|hosts)|(?:^|[\\/])\.env\b|(?:^|[\\/])\.aws[\\/]|(?:^|[\\/])\.ssh[\\/]|\/proc\/self\/environ|\benviron\b/i;
const PATH_TRAVERSAL_RE = /\.\.[\\/]/;
const EXFIL_HOST_RE = /(?:^|\/\/)(?:\d{1,3}\.){3}\d{1,3}|attacker|exfil|malware|pastebin|ngrok/i;

const PRIVILEGED_SCOPE_RE = /^(?:admin|root|sudo|write_all|env_read|secret_read|privileged|cap_sys_admin)$/i;
const DESTRUCTIVE_METHOD_RE = /^(?:DELETE|DESTROY|DROP|TRUNCATE|REMOVE|WIPE)$/i;

const QUANT_ELEVATED_AMOUNT = 100;
const QUANT_CRITICAL_AMOUNT = 1000;

/**
 * @typedef {Object} IntentAlignmentOutput
 * @property {number} score
 * @property {'ALIGNED'|'ELEVATED'|'CRITICAL'} level
 * @property {string[]} signals
 */

/**
 * @param {unknown} raw
 * @returns {{
 *   tool: string;
 *   path: string;
 *   host: string;
 *   method: string;
 *   amount: number;
 *   scopes: string[];
 * }}
 */
export function normalizeStructuralPayload(raw) {
  const p = raw != null && typeof raw === 'object' && !Array.isArray(raw) ? /** @type {Record<string, unknown>} */ (raw) : {};

  const tool = String(p.tool ?? p.toolName ?? p.tool_name ?? p.action ?? '').trim().toLowerCase();
  const path = String(p.path ?? p.filePath ?? p.file_path ?? p.targetPath ?? p.uri ?? p.url ?? '').trim();
  const host = String(p.host ?? p.hostname ?? p.targetHost ?? '').trim().toLowerCase();
  const method = String(p.method ?? p.httpMethod ?? p.verb ?? p.operation ?? '').trim().toUpperCase();

  let amount = 0;
  const amountRaw = p.amount ?? p.metric_value ?? p.observedValue ?? p.value ?? p.void_amount_usd;
  if (typeof amountRaw === 'number' && Number.isFinite(amountRaw)) {
    amount = amountRaw;
  } else if (amountRaw != null && amountRaw !== '') {
    const parsed = Number(amountRaw);
    if (Number.isFinite(parsed)) amount = parsed;
  }

  /** @type {string[]} */
  let scopes = [];
  const scopeRaw = p.scopes ?? p.scope ?? p.permissions ?? p.requestedPermission;
  if (Array.isArray(scopeRaw)) {
    scopes = scopeRaw.map((s) => String(s).trim()).filter(Boolean);
  } else if (typeof scopeRaw === 'string' && scopeRaw.trim()) {
    scopes = scopeRaw
      .split(/[,;\s]+/)
      .map((s) => s.trim())
      .filter(Boolean);
  }

  const exfil = String(p.exfilTarget ?? p.exfil_target ?? '').trim();
  if (exfil && !path) {
    return { tool, path: exfil, host, method, amount, scopes };
  }

  return { tool, path, host, method, amount, scopes };
}

/**
 * @param {number} score
 */
function clampScore(score) {
  const n = Number(score);
  if (!Number.isFinite(n) || n <= 0) return 0;
  if (n >= 1) return 1;
  return Math.round(n * 100) / 100;
}

/**
 * @param {number} score
 * @returns {'ALIGNED'|'ELEVATED'|'CRITICAL'}
 */
export function intentAlignmentLevelFromScore(score) {
  const s = clampScore(score);
  if (s <= 0.2) return INTENT_ALIGNMENT_LEVEL.ALIGNED;
  if (s <= 0.6) return INTENT_ALIGNMENT_LEVEL.ELEVATED;
  return INTENT_ALIGNMENT_LEVEL.CRITICAL;
}

/**
 * @param {string[]} signals
 * @param {string} tag
 * @param {number} weight
 * @returns {number}
 */
function pushSignal(signals, tag, weight) {
  if (signals.length < MAX_INTENT_ALIGNMENT_SIGNALS && !signals.includes(tag)) {
    signals.push(tag);
  }
  return weight;
}

/**
 * @param {unknown} intentContext
 * @param {unknown} normalizedPayload
 * @returns {IntentAlignmentOutput}
 */
export function evaluateIntentAlignment(intentContext, normalizedPayload) {
  const ctx = serializeIntentContext(intentContext);
  const p = normalizeStructuralPayload(normalizedPayload);
  const reasoning = ctx.reasoning_summary.toLowerCase();
  const pathLower = p.path.toLowerCase();
  const hostLower = p.host.toLowerCase();
  const toolLower = p.tool;

  /** @type {string[]} */
  const signals = [];
  /** @type {number[]} */
  const weights = [0];

  const benignMaintenance = BENIGN_MAINTENANCE_RE.test(reasoning);
  const benignExternal = BENIGN_EXTERNAL_RE.test(reasoning);
  const financialReasoning = FINANCIAL_REASONING_RE.test(reasoning);
  const privilegeReasoning = PRIVILEGE_REASONING_RE.test(reasoning);
  const readOnlyReasoning = READ_ONLY_REASONING_RE.test(reasoning);

  if (RESTRICTED_PATH_RE.test(pathLower) || RESTRICTED_PATH_RE.test(p.path)) {
    weights.push(
      pushSignal(
        signals,
        'PATH_PROC_OR_ENV_ACCESS',
        benignMaintenance || readOnlyReasoning ? 1 : 0.85,
      ),
    );
  }

  if (PATH_TRAVERSAL_RE.test(pathLower)) {
    weights.push(pushSignal(signals, 'PATH_TRAVERSAL_SEQUENCE', 0.5));
  }

  if (
    benignMaintenance &&
    (pathLower.includes('/sys/') || pathLower.includes('/dev/') || hostLower === 'localhost' || hostLower === '127.0.0.1')
  ) {
    weights.push(pushSignal(signals, 'PATH_HOST_INTERNAL_BOUNDARY', 0.4));
  }

  if (benignExternal && (hostLower === 'localhost' || hostLower === '127.0.0.1' || hostLower === '0.0.0.0')) {
    weights.push(pushSignal(signals, 'HOST_LOCALHOST_VS_EXTERNAL_INTENT', 0.35));
  }

  if (EXFIL_HOST_RE.test(hostLower) || EXFIL_HOST_RE.test(pathLower)) {
    weights.push(pushSignal(signals, 'HOST_OR_TARGET_EXFIL_PATTERN', 0.55));
  }

  const exfilRaw =
    normalizedPayload != null && typeof normalizedPayload === 'object'
      ? /** @type {Record<string, unknown>} */ (normalizedPayload).exfilTarget ??
        /** @type {Record<string, unknown>} */ (normalizedPayload).exfil_target
      : null;
  if (exfilRaw != null && String(exfilRaw).trim()) {
    weights.push(pushSignal(signals, 'PAYLOAD_EXFIL_TARGET_FIELD', 0.55));
  }

  const privilegedScopes = p.scopes.filter((s) => PRIVILEGED_SCOPE_RE.test(s));
  if (privilegedScopes.length > 0 && !privilegeReasoning) {
    weights.push(pushSignal(signals, 'SCOPE_PRIVILEGE_ESCALATION', 0.35));
  }

  const READ_SCOPE_RE = /^(?:read|read_only|viewer?)$/i;
  const sensitiveUndeclaredScopes = p.scopes.filter((s) => !READ_SCOPE_RE.test(s));
  if (sensitiveUndeclaredScopes.length > 0 && !privilegeReasoning && !readOnlyReasoning && benignMaintenance) {
    weights.push(pushSignal(signals, 'SCOPE_UNDECLARED_IN_REASONING', 0.25));
  }

  if (!financialReasoning && p.amount >= QUANT_CRITICAL_AMOUNT) {
    weights.push(pushSignal(signals, 'QUANTITATIVE_VOLATILITY_CRITICAL', 0.65));
  } else if (!financialReasoning && p.amount >= QUANT_ELEVATED_AMOUNT) {
    weights.push(pushSignal(signals, 'QUANTITATIVE_VOLATILITY_ELEVATED', 0.5));
  }

  if (benignMaintenance && DESTRUCTIVE_METHOD_RE.test(p.method)) {
    weights.push(pushSignal(signals, 'METHOD_DESTRUCTIVE_VS_BENIGN_INTENT', 0.45));
  }

  const exfilTools = ['read_file', 'cat', 'curl', 'wget', 'fetch', 'http_get', 'shell_exec', 'exec'];
  if (
    exfilTools.some((t) => toolLower === t || toolLower.endsWith(`.${t}`)) &&
    (RESTRICTED_PATH_RE.test(pathLower) || EXFIL_HOST_RE.test(pathLower))
  ) {
    weights.push(pushSignal(signals, 'TOOL_EXFIL_VECTOR_MISMATCH', 0.5));
  }

  if (benignMaintenance && privilegedScopes.length === 0 && readOnlyReasoning && !RESTRICTED_PATH_RE.test(pathLower)) {
    // Fully aligned maintenance read — no extra weight
  }

  const score = clampScore(Math.max(...weights));
  const level = intentAlignmentLevelFromScore(score);

  return {
    score,
    level,
    signals: signals.slice(0, MAX_INTENT_ALIGNMENT_SIGNALS),
  };
}

/**
 * Deterministic intent_alignment for receipt_digest (KVR-102).
 * Keys sorted via canonicalize; signals sorted lexicographically; score fixed to 2 decimals.
 * @param {unknown} alignment
 */
export function canonicalizeIntentAlignmentForDigest(alignment) {
  if (alignment == null || typeof alignment !== 'object') {
    return { level: 'ALIGNED', score: 0, signals: [] };
  }
  const raw = /** @type {Record<string, unknown>} */ (alignment);
  const levelRaw = String(raw.level ?? 'ALIGNED').toUpperCase();
  const level =
    levelRaw === INTENT_ALIGNMENT_LEVEL.CRITICAL
      ? INTENT_ALIGNMENT_LEVEL.CRITICAL
      : levelRaw === INTENT_ALIGNMENT_LEVEL.ELEVATED
        ? INTENT_ALIGNMENT_LEVEL.ELEVATED
        : INTENT_ALIGNMENT_LEVEL.ALIGNED;
  const score = clampScore(raw.score);
  const signals = Array.isArray(raw.signals)
    ? [...raw.signals]
        .map((s) => String(s).trim())
        .filter(Boolean)
        .slice(0, MAX_INTENT_ALIGNMENT_SIGNALS)
        .sort()
    : [];
  return canonicalize({ level, score, signals });
}
