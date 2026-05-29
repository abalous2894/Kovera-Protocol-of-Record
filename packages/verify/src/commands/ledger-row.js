import fs from 'node:fs';
import path from 'node:path';
import { verifyLedgerEntryPreimage } from '../core/ledgerPreimage.js';
import { ExitCode } from '../exitCodes.js';

/**
 * @param {string} jsonPath
 * @param {{ prevContextHash?: string, json?: boolean, skipProofOfIntent?: boolean }} [opts]
 */
export function runLedgerRowCommand(jsonPath, opts = {}) {
  const abs = path.isAbsolute(jsonPath) ? jsonPath : path.join(process.cwd(), jsonPath);
  let raw;
  try {
    raw = fs.readFileSync(abs, 'utf8');
  } catch (e) {
    console.error(`FILE ERROR: cannot read ${abs}: ${e.message}`);
    return ExitCode.FILE_ERROR;
  }

  let doc;
  try {
    doc = JSON.parse(raw);
  } catch (e) {
    console.error(`FILE ERROR: invalid JSON: ${e.message}`);
    return ExitCode.FILE_ERROR;
  }

  const prevContextHash =
    opts.prevContextHash ??
    doc._verify?.prevContextHash ??
    doc.__verify?.prevContextHash ??
    null;

  let result;
  try {
    result = verifyLedgerEntryPreimage(doc, {
      prevContextHash,
      verifyProofOfIntent: !opts.skipProofOfIntent,
    });
  } catch (e) {
    console.error(`FILE ERROR: ${e.message}`);
    return ExitCode.FILE_ERROR;
  }

  if (result.error === 'CONTEXT_CHAIN_REQUIRES_PREV_CONTEXT_HASH') {
    console.error(`FILE ERROR: ${result.detail}`);
    return ExitCode.FILE_ERROR;
  }

  if (opts.json) {
    console.log(JSON.stringify(result, null, 2));
  } else if (result.ok) {
    console.log(`OK — ${result.spec} integrity verified`);
    console.log(`  entryHash: ${result.storedEntryHash}`);
    for (const layer of result.layers) {
      console.log(`  ${layer.id}: ${layer.detail}`);
    }
  } else {
    console.error(`FAIL — ${result.spec} integrity mismatch`);
    for (const layer of result.layers) {
      if (!layer.pass) console.error(`  ${layer.id}: ${layer.detail}`);
    }
  }

  return result.ok ? ExitCode.VERIFIED : ExitCode.MISMATCH;
}
