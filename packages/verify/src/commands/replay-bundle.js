#!/usr/bin/env node
/**
 * aevesa replay-bundle — reconstruct session timeline from Proof-of-Action JSON (offline).
 */

import { readFileSync } from 'node:fs';
import { replayProofBundle } from '../replay/replayProofBundle.js';
import { ExitCode } from '../exitCodes.js';

/**
 * @param {string} bundlePath
 * @param {{ json?: boolean; summary?: boolean }} opts
 */
export function runReplayBundleCommand(bundlePath, opts = {}) {
  let raw;
  try {
    raw = readFileSync(bundlePath, 'utf8');
  } catch (e) {
    console.error(`Cannot read bundle: ${e instanceof Error ? e.message : String(e)}`);
    return ExitCode.FILE_ERROR;
  }

  let bundle;
  try {
    bundle = JSON.parse(raw);
  } catch (e) {
    console.error(`Invalid JSON: ${e instanceof Error ? e.message : String(e)}`);
    return ExitCode.FILE_ERROR;
  }

  let replay;
  try {
    replay = replayProofBundle(bundle);
  } catch (e) {
    console.error(`Replay failed: ${e instanceof Error ? e.message : String(e)}`);
    return ExitCode.MISMATCH;
  }

  if (opts.json) {
    console.log(JSON.stringify(replay, null, 2));
    return ExitCode.VERIFIED;
  }

  if (opts.summary) {
    console.log(`aevesa session replay (offline)`);
    console.log(`  bundle_id:     ${replay.bundle_id ?? '—'}`);
    console.log(`  entry_hash:    ${replay.entry_hash ?? '—'}`);
    console.log(`  proof_profile: ${replay.proof_profile ?? '—'}`);
    console.log(`  events:        ${replay.event_count}`);
    console.log('');
    for (const ev of replay.timeline) {
      const ts = ev.timestamp ? ev.timestamp.slice(0, 19) : '—';
      console.log(`  ${String(ev.sequence).padStart(2, '0')}  [${ts}]  ${ev.kind}`);
      console.log(`      ${ev.summary}`);
      if (ev.verdict) console.log(`      verdict: ${ev.verdict}`);
    }
    return ExitCode.VERIFIED;
  }

  console.log(JSON.stringify(replay, null, 2));
  return ExitCode.VERIFIED;
}

export default { runReplayBundleCommand };
