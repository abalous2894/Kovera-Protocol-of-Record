#!/usr/bin/env node
/**
 * aevesa verify — unified offline verification (auto-detect evidence type).
 */

import { readFileSync } from 'node:fs';
import { runUnifiedVerify } from '../verify/runUnifiedVerify.js';
import { ExitCode } from '../exitCodes.js';

/**
 * @param {string} inputPath
 * @param {{
 *   json?: boolean;
 *   summary?: boolean;
 *   fetch?: boolean;
 *   apiBase?: string;
 *   raw?: string;
 * }} opts
 */
export async function runVerifyCommand(inputPath, opts = {}) {
  let raw = opts.raw;
  if (!raw) {
    try {
      raw = readFileSync(inputPath, 'utf8').trim();
    } catch (e) {
      console.error(`Cannot read input: ${e instanceof Error ? e.message : String(e)}`);
      return ExitCode.FILE_ERROR;
    }
  }

  let input;
  if (/^[a-f0-9]{64}$/i.test(raw)) {
    input = raw;
  } else {
    try {
      input = JSON.parse(raw);
    } catch (e) {
      console.error(`Invalid JSON: ${e instanceof Error ? e.message : String(e)}`);
      return ExitCode.FILE_ERROR;
    }
  }

  let report;
  try {
    report = await runUnifiedVerify(input, {
      fetch: opts.fetch !== false,
      apiBase: opts.apiBase,
    });
  } catch (e) {
    console.error(`Verify failed: ${e instanceof Error ? e.message : String(e)}`);
    return ExitCode.MISMATCH;
  }

  if (opts.summary) {
    console.log('aevesa verify (offline — no Aevesa login)');
    console.log(`  ok:                  ${report.ok}`);
    console.log(`  verdict:             ${report.verdict}`);
    console.log(`  evidence:            ${report.evidence_kind}`);
    console.log(`  entry_hash:          ${report.entry_hash ?? '—'}`);
    if (report.executive_summary) {
      console.log('');
      console.log(`  summary:  ${report.executive_summary}`);
    }
    if (report.replay?.event_count != null) {
      console.log(`  timeline:  ${report.replay.event_count} events`);
    }
    if (report.errors?.length) {
      console.log('  errors:');
      for (const err of report.errors) console.log(`    - ${err}`);
    }
    return report.ok ? ExitCode.VERIFIED : ExitCode.MISMATCH;
  }

  if (opts.json || !opts.summary) {
    console.log(JSON.stringify(report, null, 2));
  }

  return report.ok ? ExitCode.VERIFIED : ExitCode.MISMATCH;
}

export default { runVerifyCommand };
