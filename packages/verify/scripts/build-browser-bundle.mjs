#!/usr/bin/env node
import esbuild from 'esbuild';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(fileURLToPath(import.meta.url));
const entry = path.join(root, '../src/browserEntry.js');
const outfile = process.env.AEVESA_VERIFY_BUNDLE_OUTFILE
  ? path.resolve(process.env.AEVESA_VERIFY_BUNDLE_OUTFILE)
  : path.resolve(
      root,
      '../../../sentinul-app-site/src/js/aevesa-verify.bundle.js',
    );

const cryptoShim = path.join(root, '../src/browser/nodeCryptoShim.js');
const bufferInject = path.join(root, '../src/browser/bufferInject.js');

await esbuild.build({
  entryPoints: [entry],
  bundle: true,
  format: 'esm',
  platform: 'browser',
  target: ['es2022'],
  outfile,
  sourcemap: false,
  logLevel: 'info',
  inject: [bufferInject],
  alias: {
    'node:crypto': cryptoShim,
  },
});

console.log(`Wrote ${outfile}`);
