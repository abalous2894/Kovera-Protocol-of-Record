#!/usr/bin/env node
/**
 * Ensures verify-portal intent divergence sample verifies under Tier A rules.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  verifyReceipt,
  computeReceiptDigest,
  verifyReceiptDigestMatch,
} from '../dist/index.js';

const root = path.dirname(fileURLToPath(import.meta.url));
const portalPath = path.resolve(
  root,
  '../../../sentinul-app-site/src/js/liabilityReceiptPortal.js',
);
const src = readFileSync(portalPath, 'utf8');
const match = src.match(/export const KOVERA_INTENT_DIVERGENCE_SAMPLE = (\{[\s\S]*?\n\});/);
if (!match) {
  console.error('Could not extract KOVERA_INTENT_DIVERGENCE_SAMPLE from portal source');
  process.exit(1);
}

const sample = Function(`"use strict"; return (${match[1]});`)();
sample.integrity = {
  receipt_digest: computeReceiptDigest(sample),
  signature_alg: 'none',
  signature: null,
  manifest_signature_jws: null,
};

const digest = verifyReceiptDigestMatch(sample);
const result = verifyReceipt(sample);
if (!digest.ok || !result.isValid) {
  console.error({ digest, result });
  process.exit(1);
}
console.log('verify-portal intent divergence sample OK');
