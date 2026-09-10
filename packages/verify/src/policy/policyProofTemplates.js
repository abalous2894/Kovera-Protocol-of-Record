/**
 * Policy-as-proof downloadable templates (Phase C).
 */

import { readFileSync, copyFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
export const TEMPLATES_ROOT = join(__dirname, '../../templates/policy-proof');

/**
 * @param {string} relativePath
 */
function resolveTemplateFile(relativePath) {
  const resolved = join(TEMPLATES_ROOT, relativePath);
  if (!resolved.startsWith(`${TEMPLATES_ROOT}${sep}`) && resolved !== TEMPLATES_ROOT) {
    const err = new Error('Template path escapes templates root');
    err.code = 'INVALID_TEMPLATE_PATH';
    throw err;
  }
  return resolved;
}

/**
 * @returns {{ schema: string, templates: object[] }}
 */
export function loadPolicyProofTemplateIndex() {
  const raw = readFileSync(join(TEMPLATES_ROOT, 'index.json'), 'utf8');
  return JSON.parse(raw);
}

/**
 * @param {string} templateId
 */
export function resolvePolicyProofTemplate(templateId) {
  const index = loadPolicyProofTemplateIndex();
  const id = String(templateId || '').trim();
  const entry = index.templates.find((t) => t.id === id);
  if (!entry) {
    const err = new Error(`Unknown policy-proof template: ${id}`);
    err.code = 'UNKNOWN_TEMPLATE';
    throw err;
  }
  return { index, entry };
}

/**
 * @param {string} [outputDir]
 * @param {string} [templateId]
 */
export function exportPolicyProofTemplate(templateId, outputDir = '.') {
  const { entry } = resolvePolicyProofTemplate(templateId);
  const out = String(outputDir || '.').trim() || '.';
  mkdirSync(out, { recursive: true });

  const bundleSrc = resolveTemplateFile(entry.bundle);
  const packSrc = resolveTemplateFile(entry.policy_pack);
  const bundleDest = join(out, 'bundle.json');
  const packDest = join(out, entry.policy_pack.includes('/') ? 'kaptein-path-policies-v1.json' : entry.policy_pack);

  copyFileSync(bundleSrc, bundleDest);
  copyFileSync(packSrc, packDest);

  const readme = [
    `Aevesa policy-proof template: ${entry.id}`,
    entry.title,
    '',
    'Verify offline:',
    `  aevesa policy-proof verify ${bundleDest} --summary`,
    `  aevesa verify ${bundleDest} --summary`,
    '',
    `Engine code: ${entry.engine_code}`,
    entry.eu_ai_act_framing ? `EU AI Act: ${entry.eu_ai_act_framing}` : '',
  ]
    .filter(Boolean)
    .join('\n');

  writeFileSync(join(out, 'README.txt'), `${readme}\n`, 'utf8');

  return {
    ok: true,
    templateId: entry.id,
    outputDir: out,
    files: [bundleDest, packDest, join(out, 'README.txt')],
  };
}

export default {
  loadPolicyProofTemplateIndex,
  resolvePolicyProofTemplate,
  exportPolicyProofTemplate,
};
