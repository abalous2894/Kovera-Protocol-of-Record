#!/usr/bin/env node
/**
 * Ensure npm bin entry files use LF (WSL/Windows CRLF breaks #!/usr/bin/env node on Linux).
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));

/** @param {string} rel */
function normalizeLf(rel) {
  const path = join(root, rel);
  let content;
  try {
    content = readFileSync(path, 'utf8');
  } catch {
    return;
  }
  if (!content.includes('\r')) return;
  writeFileSync(path, content.replace(/\r\n/g, '\n').replace(/\r/g, '\n'));
  console.log(`[normalize-publish-lf] ${rel}`);
}

for (const rel of Object.values(pkg.bin ?? {})) {
  normalizeLf(String(rel));
}

console.log('[normalize-publish-lf] done');
