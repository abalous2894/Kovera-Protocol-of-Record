/**
 * aevesa.verification-report/v1 — unified output for aevesa verify.
 */

import { stableStringify } from '../core/stableStringify.js';
import { sha256Utf8 } from '../core/sha256.js';

export const VERIFICATION_REPORT_SCHEMA = 'aevesa.verification-report/v1';

/** @typedef {'VERIFIED' | 'DENIED_VALID' | 'TAMPERED' | 'PARTIAL' | 'UNKNOWN'} VerificationVerdict */

/**
 * @param {{
 *   ok: boolean;
 *   kind: string;
 *   verdict?: VerificationVerdict;
 *   checks?: object[];
 *   executiveSummary?: string | null;
 *   diligenceSummary?: object | null;
 *   entryHash?: string | null;
 *   replay?: object | null;
 *   detail?: object | null;
 *   errors?: string[];
 *   verifyHint?: string;
 * }} input
 */
export function buildVerificationReport(input) {
  const checks = Array.isArray(input.checks) ? input.checks : [];
  const errors = Array.isArray(input.errors) ? input.errors : [];
  const ok = input.ok === true && errors.length === 0;

  let verdict = input.verdict;
  if (!verdict) {
    if (ok) verdict = 'VERIFIED';
    else if (errors.some((e) => /tamper|digest mismatch|mismatch/i.test(e))) verdict = 'TAMPERED';
    else if (input.kind === 'policy_proof_bundle' && input.detail?.deny_proven) verdict = 'DENIED_VALID';
    else if (checks.length > 0 && checks.some((c) => c.ok) && checks.some((c) => !c.ok)) verdict = 'PARTIAL';
    else verdict = ok ? 'VERIFIED' : 'UNKNOWN';
  }

  const body = {
    schema: VERIFICATION_REPORT_SCHEMA,
    generated_at: new Date().toISOString(),
    offline: true,
    verify_without_aevesa: true,
    ok,
    verdict,
    evidence_kind: input.kind,
    executive_summary: input.executiveSummary ?? null,
    diligence_summary: input.diligenceSummary ?? null,
    entry_hash: input.entryHash ?? null,
    checks,
    replay: input.replay ?? null,
    detail: input.detail ?? null,
    errors,
    verify_hint: input.verifyHint ?? 'Re-run: aevesa verify <file.json>',
  };

  return {
    ...body,
    report_digest: sha256Utf8(stableStringify(body)),
  };
}

/**
 * @param {object | null | undefined} receipt
 */
export function executiveSummaryFromReceipt(receipt) {
  if (!receipt || typeof receipt !== 'object') return null;
  const ds = receipt.diligence_summary;
  if (ds && typeof ds === 'object') {
    const parts = [ds.who_acted, ds.what_policy_allowed, ds.what_proof_says].filter(Boolean);
    if (parts.length) return parts.join(' ');
  }
  const decision = receipt.policy?.decision ?? receipt.session?.outcome;
  const tool = receipt.side_effects?.action?.tool_name ?? receipt.side_effects?.action?.toolName;
  if (decision === 'deny' || receipt.session?.outcome === 'blocked') {
    return `Agent action ${tool ? `(${tool}) ` : ''}was blocked before execution. Cryptographic receipt verifies offline.`;
  }
  return `Agent session evidence verified offline${tool ? ` for ${tool}` : ''}.`;
}

export default { VERIFICATION_REPORT_SCHEMA, buildVerificationReport, executiveSummaryFromReceipt };
