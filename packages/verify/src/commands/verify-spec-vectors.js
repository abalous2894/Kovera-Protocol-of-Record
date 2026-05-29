import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runSpecVectors } from '../spec/runSpecVectors.js';
import { ExitCode } from '../exitCodes.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_SPEC = path.resolve(__dirname, '../../../../docs/spec/kovera-sovereign-ledger-spec.md');

/**
 * @param {{ specPath?: string, json?: boolean }} [opts]
 */
export function runVerifySpecVectorsCommand(opts = {}) {
  const specPath = opts.specPath ?? DEFAULT_SPEC;
  const { ok, results } = runSpecVectors({ specPath, silent: opts.json });

  if (opts.json) {
    console.log(JSON.stringify({ ok, specPath, results }, null, 2));
  }

  return ok ? ExitCode.VERIFIED : ExitCode.MISMATCH;
}
