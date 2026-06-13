#!/usr/bin/env node
/**
 * Copy hand-authored .js modules into dist/ (tsc only compiles .ts; see tsconfig exclude).
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(fileURLToPath(import.meta.url));
const pkgRoot = path.join(root, '..');
const srcRoot = path.join(pkgRoot, 'src');

/**
 * @param {string} dir
 * @param {string} rel
 */
function copyStandaloneJs(dir, rel = '') {
  for (const name of fs.readdirSync(dir)) {
    const from = path.join(dir, name);
    const relPath = rel ? path.join(rel, name) : name;
    if (fs.statSync(from).isDirectory()) {
      copyStandaloneJs(from, relPath);
      continue;
    }
    if (!name.endsWith('.js')) continue;
    const tsSibling = from.replace(/\.js$/, '.ts');
    if (fs.existsSync(tsSibling)) continue;

    const to = path.join(pkgRoot, 'dist', relPath);
    fs.mkdirSync(path.dirname(to), { recursive: true });
    fs.copyFileSync(from, to);
  }
}

copyStandaloneJs(srcRoot);

/** Required by dist/index.js — fail build early if copy missed a module */
const required = [
  'dist/liability/intentContextBinding.js',
  'dist/core/intentAlignment.js',
  'dist/ledgerExports.js',
  'dist/offlinePromotionVerifier.js',
];
for (const rel of required) {
  const abs = path.join(pkgRoot, rel);
  if (!fs.existsSync(abs)) {
    console.error(`[copy-core-js] missing required dist file: ${rel}`);
    process.exit(1);
  }
}

console.log('[copy-core-js] standalone .js modules copied to dist/');
