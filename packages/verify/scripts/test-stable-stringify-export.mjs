#!/usr/bin/env node
/**
 * stableStringify public export + sorted-key determinism smoke.
 */
import { stableStringify } from '../dist/index.js';

const a = stableStringify({ b: 1, a: 2 });
const b = stableStringify({ a: 2, b: 1 });
if (a !== b) {
  console.error('stableStringify not deterministic:', a, b);
  process.exit(1);
}

const nested = stableStringify({ z: [{ y: 1, x: 2 }], a: null });
if (typeof nested !== 'string' || !nested.includes('"a":null')) {
  console.error('unexpected nested output:', nested);
  process.exit(1);
}

console.log('stableStringify export OK');
