#!/usr/bin/env node
/**
 * aevesa verify-session — offline Compositional Accountability Protocol (CAP) verification.
 */

import { readFileSync } from 'node:fs';
import { verifySessionProof } from '../../dist/index.js';
import { ExitCode } from '../exitCodes.js';

/**
 * @param {string} bundlePath
 * @param {{ json?: boolean; summary?: boolean; requireMembers?: boolean; requireCustodian?: boolean; requirePolicyProof?: boolean }} opts
 */
export function runVerifySessionCommand(bundlePath, opts = {}) {
  let raw;
  try {
    raw = readFileSync(bundlePath, 'utf8');
  } catch (e) {
    console.error(`Cannot read session proof bundle: ${e instanceof Error ? e.message : String(e)}`);
    return ExitCode.FILE_ERROR;
  }

  let bundle;
  try {
    bundle = JSON.parse(raw);
  } catch (e) {
    console.error(`Invalid JSON: ${e instanceof Error ? e.message : String(e)}`);
    return ExitCode.FILE_ERROR;
  }

  const issuerPublicKey =
    process.env.AEVESA_MERGE_ATTESTATION_PUBLIC_KEY_PEM?.trim() ||
    process.env.AEVESA_AUDIT_BUNDLE_PUBLIC_KEY_PEM?.trim() ||
    null;

  const result = verifySessionProof(bundle, {
    requireMemberReceipts: opts.requireMembers === true,
    requireCustodian: opts.requireCustodian === true,
    requirePolicyProof: opts.requirePolicyProof === true,
    issuerPublicKey: issuerPublicKey ?? undefined,
    skipIntegritySignatureWithoutKey: !issuerPublicKey,
  });

  if (opts.json) {
    console.log(JSON.stringify(result, null, 2));
    return result.ok ? ExitCode.VERIFIED : ExitCode.MISMATCH;
  }

  if (opts.summary) {
    const closure = result.composition_closure ?? null;
    const shipGate = result.closure_ship_gate ?? null;
    const carrierReady =
      closure?.carrier_review_ready === true && shipGate?.blocked !== true;
    console.log('aevesa verify-session (CAP — compositional accountability, offline)');
    console.log(`  ok:                           ${result.ok}`);
    console.log(`  session_proof_complete:         ${result.session_proof_complete}`);
    console.log(`  closure_verdict:                ${closure?.closure_verdict ?? '—'}`);
    console.log(`  carrier_submission_ready:       ${shipGate?.carrier_submission_ready === true}`);
    console.log(`  closure_ship_gate.blocked:      ${shipGate?.blocked === true}`);
    console.log(`  rollup_carrier_inference_allowed: ${shipGate?.rollup_carrier_inference_allowed === true}`);
    console.log(`  carrier_handoff_ready:          ${carrierReady}`);
    console.log(`  session_id:                     ${bundle?.session_id ?? '—'}`);
    console.log('  checks:');
    for (const [key, val] of Object.entries(result.checks)) {
      console.log(`    ${key}: ${val}`);
    }
    if (result.set_completeness?.computedSetRoot) {
      console.log(`  set_root:                       ${result.set_completeness.computedSetRoot.slice(0, 16)}…`);
    }
    if (result.errors?.length) {
      console.log('  errors:');
      for (const err of result.errors) console.log(`    - ${err}`);
    }
    console.log(`  note:                           ${result.note ?? '—'}`);
    if (!carrierReady && result.session_proof_complete === true) {
      console.log(
        '  warning:                      session_proof_complete does not imply carrier handoff — read closure_verdict',
      );
    }
    return result.ok ? ExitCode.VERIFIED : ExitCode.MISMATCH;
  }

  console.log(JSON.stringify(result, null, 2));
  return result.ok ? ExitCode.VERIFIED : ExitCode.MISMATCH;
}

export default { runVerifySessionCommand };
