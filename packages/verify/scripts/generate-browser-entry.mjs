#!/usr/bin/env node
/**
 * Generate packages/verify/src/browserEntry.js from browser-manifest.json (Phase 3 H7).
 * Run: npm run generate:browser-entry --workspace=@aevesa/verify
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(fileURLToPath(import.meta.url));
const manifestPath = path.join(root, '../browser-manifest.json');
const outPath = path.join(root, '../src/browserEntry.js');

const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
const lines = [
  '/**',
  ' * Browser bundle entry — generated from browser-manifest.json.',
  ' * Import subpaths directly (not dist/index.js) so esbuild never pulls node-only CLI/offline exports.',
  ' * Regenerate: npm run generate:browser-entry --workspace=@aevesa/verify',
  ' */',
  '',
];

for (const block of manifest.exports) {
  const names = block.symbols.join(', ');
  if (block.symbols.length === 1) {
    lines.push(`export { ${names} } from '${block.from}';`);
  } else {
    lines.push(`export {`);
    lines.push(`  ${block.symbols.join(',\n  ')},`);
    lines.push(`} from '${block.from}';`);
  }
  lines.push('');
}

fs.writeFileSync(outPath, `${lines.join('\n').trimEnd()}\n`);
console.log(`Wrote ${outPath} (${manifest.exports.length} export blocks)`);
