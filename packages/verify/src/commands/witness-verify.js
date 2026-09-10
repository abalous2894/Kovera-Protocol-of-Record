#!/usr/bin/env node
/**
 * aevesa witness-verify — offline SCITT refusal witness + inclusion proof verification.
 */

import { readFileSync } from 'node:fs';
import { verifyScittRefusalWitnessBundle } from '../witness/witnessInclusionVerify.js';
import { ExitCode } from '../exitCodes.js';

/**
 * @param {string} bundlePath
 * @param {{ json?: boolean; summary?: boolean }} opts
 */
export function runWitnessVerifyCommand(bundlePath, opts = {}) {
  let raw;
  try {
    raw = readFileSync(bundlePath, 'utf8');
  } catch (e) {
    console.error(`Cannot read witness bundle: ${e instanceof Error ? e.message : String(e)}`);
    return ExitCode.FILE_ERROR;
  }

  let bundle;
  try {
    bundle = JSON.parse(raw);
  } catch (e) {
    console.error(`Invalid JSON: ${e instanceof Error ? e.message : String(e)}`);
    return ExitCode.FILE_ERROR;
  }

  const result = verifyScittRefusalWitnessBundle(bundle);

  if (opts.json) {
    console.log(JSON.stringify(result, null, 2));
    return result.ok ? ExitCode.VERIFIED : ExitCode.MISMATCH;
  }

  if (opts.summary) {
    console.log('aevesa witness verify (offline — no Aevesa API)');
    console.log(`  ok:              ${result.ok}`);
    console.log(`  receipt_digest:  ${result.receiptDigest ?? '—'}`);
    console.log(`  inclusion:       ${result.checks.inclusionProofValid ? 'valid' : 'invalid'}`);
    if (result.checks.externalRekorValid != null) {
      console.log(`  rekor metadata:  ${result.checks.externalRekorValid ? 'valid' : 'invalid'}`);
      if (result.externalRekorVerification?.verification_hint) {
        console.log(`  rekor hint:      ${result.externalRekorVerification.verification_hint}`);
      }
    }
    console.log(`  note:            ${result.note ?? '—'}`);
    return result.ok ? ExitCode.VERIFIED : ExitCode.MISMATCH;
  }

  console.log(JSON.stringify(result, null, 2));
  return result.ok ? ExitCode.VERIFIED : ExitCode.MISMATCH;
}

export default { runWitnessVerifyCommand };
