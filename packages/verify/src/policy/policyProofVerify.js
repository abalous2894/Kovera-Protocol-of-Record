/**
 * aevesa.policy-proof-verify/v1 — offline proof that a DENY was correct given Datalog facts.
 */

import { stableStringify } from '../core/stableStringify.js';
import { sha256Utf8 } from '../core/sha256.js';
import { verifyReceipt } from '../../dist/liability/verifyReceipt.js';
import { verifyReceiptDigestMatch } from '../../dist/liability/digest.js';
import { verifyPartialPathCommitment } from '../core/partialPath.js';
import { parseDatalogFacts } from './datalogFactsParser.js';
import { evaluatePathFromFacts, matchKapteinPolicies } from './evaluatePathFromFacts.js';

export const POLICY_PROOF_BUNDLE_SCHEMA = 'aevesa.policy-proof-bundle/v1';
export const POLICY_PROOF_VERIFY_SCHEMA = 'aevesa.policy-proof-verify/v1';

/**
 * @param {object} bundle — without proof_digest
 */
export function computePolicyProofDigest(bundle) {
  const clone = { ...bundle };
  delete clone.proof_digest;
  delete clone.proofDigest;
  return sha256Utf8(stableStringify(clone));
}

/**
 * @param {unknown} bundle
 * @param {{ skipReceipt?: boolean }} [opts]
 */
export function verifyPolicyProofBundle(bundle, opts = {}) {
  const errors = [];
  const checks = {
    bundleSchema: false,
    factsParsed: false,
    policyReevaluationMatches: false,
    kapteinPolicyMatched: false,
    receiptDigestValid: false,
    receiptDecisionDeny: false,
    partialPathValid: false,
    proposedActionAligns: false,
  };

  if (!bundle || typeof bundle !== 'object') {
    return {
      ok: false,
      schema: POLICY_PROOF_VERIFY_SCHEMA,
      errors: ['bundle must be an object'],
      checks,
    };
  }

  const b = /** @type {Record<string, unknown>} */ (bundle);

  if (b.schema !== POLICY_PROOF_BUNDLE_SCHEMA) {
    errors.push(`schema must be ${POLICY_PROOF_BUNDLE_SCHEMA}`);
  } else {
    checks.bundleSchema = true;
  }

  const digest = String(b.proof_digest || b.proofDigest || '');
  if (digest && !/^[a-f0-9]{64}$/.test(digest)) {
    errors.push('proof_digest must be 64-char hex when present');
  } else if (digest) {
    const expected = computePolicyProofDigest(b);
    if (expected !== digest) {
      errors.push('proof_digest mismatch — bundle may be tampered');
    }
  }

  const datalogExport = b.datalog_export ?? b.datalogExport;
  if (!datalogExport || typeof datalogExport !== 'object') {
    errors.push('datalog_export required');
    return { ok: false, schema: POLICY_PROOF_VERIFY_SCHEMA, errors, checks };
  }

  const datalog = /** @type {Record<string, unknown>} */ (datalogExport);
  const facts = datalog.facts;
  const parseResult = parseDatalogFacts(Array.isArray(facts) ? facts : []);
  if (!parseResult.ok || !parseResult.parsed) {
    errors.push(...parseResult.errors.map((e) => `facts: ${e}`));
  } else {
    checks.factsParsed = true;
  }

  const rawParams = b.policy_params ?? b.policyParams ?? {};
  const policyParams = {
    maxReadsBeforeDestructive:
      rawParams.maxReadsBeforeDestructive ?? rawParams.max_reads_before_destructive ?? undefined,
  };
  const declaredEval = datalog.policy_evaluation ?? datalog.policyEvaluation;
  /** @type {object | null} */
  let reevaluation = null;

  if (parseResult.parsed) {
    reevaluation = evaluatePathFromFacts(parseResult.parsed, parseResult.parsed.proposedTool, policyParams);
    if (declaredEval && typeof declaredEval === 'object') {
      const declared = /** @type {Record<string, unknown>} */ (declaredEval);
      const allowMatch = declared.allow === reevaluation.allow;
      const codeMatch = String(declared.code || '') === String(reevaluation.code || '');
      checks.policyReevaluationMatches = allowMatch && codeMatch;
      if (!allowMatch) errors.push('policy_evaluation.allow does not match offline re-evaluation');
      if (!codeMatch) errors.push('policy_evaluation.code does not match offline re-evaluation');
    } else {
      errors.push('datalog_export.policy_evaluation required');
    }
  }

  const policyPack = b.policy_pack ?? b.policyPack;
  if (reevaluation && policyPack && typeof policyPack === 'object') {
    const matched = matchKapteinPolicies(String(reevaluation.matched_engine_code || reevaluation.code), policyPack);
    checks.kapteinPolicyMatched = matched.length > 0;
    if (reevaluation.allow === false && matched.length === 0) {
      errors.push('no Kaptein policy matched deny engine code');
    }
  } else if (reevaluation?.allow === false) {
    errors.push('policy_pack required for deny proof');
  }

  const receipt = b.receipt;
  if (receipt && typeof receipt === 'object' && !opts.skipReceipt) {
    const digestMatch = verifyReceiptDigestMatch(receipt);
    checks.receiptDigestValid = digestMatch.ok === true;
    if (!digestMatch.ok) errors.push('receipt digest mismatch');

    const verify = verifyReceipt(receipt, { ledgerDocument: null });
    if (!verify.isValid) errors.push(`receipt verify failed: ${verify.error ?? 'invalid'}`);

    checks.receiptDecisionDeny =
      /** @type {Record<string, unknown>} */ (receipt).policy?.decision === 'deny' ||
      /** @type {Record<string, unknown>} */ (receipt).session?.outcome === 'blocked';
    if (!checks.receiptDecisionDeny) errors.push('receipt must reflect deny/blocked outcome');

    const partialPath = /** @type {Record<string, unknown>} */ (receipt).partial_path;
    if (partialPath) {
      const pp = verifyPartialPathCommitment(partialPath);
      checks.partialPathValid = pp.ok === true;
      if (!pp.ok) errors.push(`partial_path: ${pp.code}`);
    }

    const proposed = parseResult.parsed?.proposedTool;
    const receiptTool =
      /** @type {Record<string, unknown>} */ (receipt).side_effects?.action?.tool_name ??
      partialPath?.proposed_action;
    if (proposed && receiptTool) {
      checks.proposedActionAligns = String(proposed) === String(receiptTool);
      if (!checks.proposedActionAligns) {
        errors.push(`proposed tool ${proposed} != receipt tool ${receiptTool}`);
      }
    }
  }

  const denyProven =
    checks.factsParsed &&
    checks.policyReevaluationMatches &&
    reevaluation?.allow === false &&
    (opts.skipReceipt || (checks.receiptDigestValid && checks.receiptDecisionDeny));

  const ok =
    errors.length === 0 &&
    checks.bundleSchema &&
    checks.factsParsed &&
    checks.policyReevaluationMatches &&
    denyProven;

  return {
    ok,
    schema: POLICY_PROOF_VERIFY_SCHEMA,
    offline: true,
    deny_proven: denyProven === true,
    checks,
    reevaluation,
    declared_evaluation: declaredEval ?? null,
    matched_policies:
      reevaluation && policyPack
        ? matchKapteinPolicies(String(reevaluation.code), policyPack)
        : [],
    errors,
    note: ok
      ? 'Offline policy re-evaluation confirms DENY matches signed evaluation trace and Datalog facts.'
      : 'Policy proof verification failed — see errors.',
  };
}

export default {
  POLICY_PROOF_BUNDLE_SCHEMA,
  POLICY_PROOF_VERIFY_SCHEMA,
  computePolicyProofDigest,
  verifyPolicyProofBundle,
};
