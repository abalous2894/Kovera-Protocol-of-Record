#!/usr/bin/env node
/**
 * aevesa conformance — run lab against any deployment and emit attestation JSON.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { runConformanceLab } from '../conformance/runConformanceLab.js';
import { verifyConformanceAttestation } from '../conformance/conformanceAttestation.js';
import { ExitCode } from '../exitCodes.js';

/**
 * @param {{ apiBase?: string; localOnly?: boolean; fixture?: string; output?: string; json?: boolean; summary?: boolean; timeoutMs?: number }} opts
 */
export async function runConformanceRunCommand(opts = {}) {
  let attestation;
  try {
    attestation = await runConformanceLab({
      apiBase: opts.localOnly ? null : opts.apiBase ?? null,
      localOnly: opts.localOnly === true,
      fixturePath: opts.fixture,
      timeoutMs: opts.timeoutMs,
    });
  } catch (e) {
    console.error(`Conformance lab failed: ${e instanceof Error ? e.message : String(e)}`);
    return ExitCode.MISMATCH;
  }

  if (opts.output) {
    try {
      writeFileSync(opts.output, `${JSON.stringify(attestation, null, 2)}\n`, 'utf8');
    } catch (e) {
      console.error(`Cannot write attestation: ${e instanceof Error ? e.message : String(e)}`);
      return ExitCode.FILE_ERROR;
    }
  }

  if (opts.summary) {
    console.log('aevesa conformance lab attestation');
    console.log(`  ok:                  ${attestation.ok}`);
    console.log(`  mode:                ${attestation.deployment?.mode ?? '—'}`);
    console.log(`  api_base:            ${attestation.deployment?.api_base ?? '(local only)'}`);
    console.log(`  attestation_digest:  ${attestation.attestation_digest ?? '—'}`);
    console.log(`  elapsed_ms:          ${attestation.elapsed_ms ?? '—'}`);
    console.log('');
    for (const p of attestation.programs ?? []) {
      console.log(`  [${p.ok ? 'PASS' : 'FAIL'}] ${p.id}${p.detail ? ` — ${p.detail}` : ''}`);
    }
    if (attestation.interop?.entry_hash) {
      console.log('');
      console.log(`  interop entry_hash:  ${attestation.interop.entry_hash}`);
    }
    if (opts.output) {
      console.log('');
      console.log(`  written:             ${opts.output}`);
    }
    return attestation.ok ? ExitCode.VERIFIED : ExitCode.MISMATCH;
  }

  if (opts.json || !opts.output) {
    console.log(JSON.stringify(attestation, null, 2));
  }

  return attestation.ok ? ExitCode.VERIFIED : ExitCode.MISMATCH;
}

/**
 * @param {string} attestationPath
 * @param {{ json?: boolean; summary?: boolean }} opts
 */
export function runConformanceVerifyCommand(attestationPath, opts = {}) {
  let raw;
  try {
    raw = readFileSync(attestationPath, 'utf8');
  } catch (e) {
    console.error(`Cannot read attestation: ${e instanceof Error ? e.message : String(e)}`);
    return ExitCode.FILE_ERROR;
  }

  let attestation;
  try {
    attestation = JSON.parse(raw);
  } catch (e) {
    console.error(`Invalid JSON: ${e instanceof Error ? e.message : String(e)}`);
    return ExitCode.FILE_ERROR;
  }

  const result = verifyConformanceAttestation(attestation);

  if (opts.summary) {
    console.log('aevesa conformance attestation verify (offline)');
    console.log(`  ok:                  ${result.ok}`);
    console.log(`  attestation_digest:  ${result.attestation_digest ?? '—'}`);
    if (result.errors.length) {
      console.log('  errors:');
      for (const err of result.errors) console.log(`    - ${err}`);
    }
    return result.ok ? ExitCode.VERIFIED : ExitCode.MISMATCH;
  }

  if (opts.json) {
    console.log(JSON.stringify(result, null, 2));
    return result.ok ? ExitCode.VERIFIED : ExitCode.MISMATCH;
  }

  console.log(JSON.stringify(result, null, 2));
  return result.ok ? ExitCode.VERIFIED : ExitCode.MISMATCH;
}

export default { runConformanceRunCommand, runConformanceVerifyCommand };
