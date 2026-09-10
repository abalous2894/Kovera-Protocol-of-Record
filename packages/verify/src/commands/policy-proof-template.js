#!/usr/bin/env node
/**
 * aevesa policy-proof template — list and export Kaptein path audit packs.
 */

import {
  exportPolicyProofTemplate,
  loadPolicyProofTemplateIndex,
} from '../policy/policyProofTemplates.js';
import { ExitCode } from '../exitCodes.js';

export function runPolicyProofTemplateListCommand(opts = {}) {
  const index = loadPolicyProofTemplateIndex();
  if (opts.json) {
    console.log(JSON.stringify(index, null, 2));
    return ExitCode.VERIFIED;
  }
  console.log('aevesa policy-proof templates (offline Kaptein DENY packs)');
  for (const t of index.templates) {
    console.log(`  ${t.id}`);
    console.log(`    ${t.title}`);
    console.log(`    code: ${t.engine_code}`);
  }
  console.log('');
  console.log('Export: aevesa policy-proof template export <id> --output ./pack');
  return ExitCode.VERIFIED;
}

/**
 * @param {string} templateId
 * @param {{ output?: string; json?: boolean }} opts
 */
export function runPolicyProofTemplateExportCommand(templateId, opts = {}) {
  try {
    const result = exportPolicyProofTemplate(templateId, opts.output || './aevesa-policy-proof-pack');
    if (opts.json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log(`Exported template "${result.templateId}" to ${result.outputDir}`);
      for (const f of result.files) console.log(`  ${f}`);
    }
    return ExitCode.VERIFIED;
  } catch (e) {
    console.error(e instanceof Error ? e.message : String(e));
    return e?.code === 'UNKNOWN_TEMPLATE' ? ExitCode.FILE_ERROR : ExitCode.MISMATCH;
  }
}

export default {
  runPolicyProofTemplateListCommand,
  runPolicyProofTemplateExportCommand,
};
