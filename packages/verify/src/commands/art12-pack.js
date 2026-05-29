import { verifyArt12PackPath } from '../core/art12PackVerify.js';
import { ExitCode } from '../exitCodes.js';

/**
 * @param {string} packPath
 * @param {{ secret?: string, json?: boolean }} [opts]
 */
export function runArt12PackCommand(packPath, opts = {}) {
  let result;
  try {
    result = verifyArt12PackPath(packPath, { secret: opts.secret });
  } catch (e) {
    console.error(`FILE ERROR: ${e.message}`);
    return ExitCode.FILE_ERROR;
  }

  if (opts.json) {
    console.log(JSON.stringify(result, null, 2));
  } else if (result.ok) {
    console.log('OK — Art. 12 Conformity Pack integrity verified');
    for (const layer of result.layers || []) {
      console.log(`  ${layer.step}: ${layer.detail}`);
    }
  } else {
    console.error(`FAIL — ${result.reason}: ${result.detail || ''}`);
    for (const layer of result.layers || []) {
      if (!layer.pass) console.error(`  ${layer.step}: ${layer.detail}`);
    }
  }

  if (result.reason === 'UNSUPPORTED_PATH' || result.reason === 'MISSING_MANIFEST') {
    return ExitCode.FILE_ERROR;
  }
  return result.ok ? ExitCode.VERIFIED : ExitCode.MISMATCH;
}
