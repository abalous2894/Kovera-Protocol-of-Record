#!/usr/bin/env node
/**
 * aevesa policy-proof verify — offline proof that a DENY was policy-correct.
 */

import { readFileSync } from 'node:fs';
import { verifyPolicyProofBundle } from '../policy/policyProofVerify.js';
import { ExitCode } from '../exitCodes.js';

/**
 * @param {string} bundlePath
 * @param {{ json?: boolean; summary?: boolean }} opts
 */
export function runPolicyProofVerifyCommand(bundlePath, opts = {}) {
  let raw;
  try {
    raw = readFileSync(bundlePath, 'utf8');
  } catch (e) {
    console.error(`Cannot read policy proof bundle: ${e instanceof Error ? e.message : String(e)}`);
    return ExitCode.FILE_ERROR;
  }

  let bundle;
  try {
    bundle = JSON.parse(raw);
  } catch (e) {
    console.error(`Invalid JSON: ${e instanceof Error ? e.message : String(e)}`);
    return ExitCode.FILE_ERROR;
  }

  const result = verifyPolicyProofBundle(bundle);

  if (opts.json) {
    console.log(JSON.stringify(result, null, 2));
    return result.ok ? ExitCode.VERIFIED : ExitCode.MISMATCH;
  }

  if (opts.summary) {
    console.log('aevesa policy-proof verify (offline — no policy engine API)');
    console.log(`  ok:           ${result.ok}`);
    console.log(`  deny_proven:  ${result.deny_proven}`);
    console.log(`  policy_code:  ${result.reevaluation?.code ?? '—'}`);
    if (result.matched_policies?.length) {
      console.log(`  kaptein:      ${result.matched_policies.map((p) => p.id).join(', ')}`);
    }
    if (result.errors?.length) {
      console.log('  errors:');
      for (const err of result.errors) console.log(`    - ${err}`);
    }
    console.log(`  note:         ${result.note ?? '—'}`);
    return result.ok ? ExitCode.VERIFIED : ExitCode.MISMATCH;
  }

  console.log(JSON.stringify(result, null, 2));
  return result.ok ? ExitCode.VERIFIED : ExitCode.MISMATCH;
}

export default { runPolicyProofVerifyCommand };
