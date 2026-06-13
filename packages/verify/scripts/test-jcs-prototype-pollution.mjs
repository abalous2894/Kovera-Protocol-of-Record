#!/usr/bin/env node
/**
 * JCS leaf hardening — null-prototype preimages, forbidden keys, NFKC normalization.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  buildCryptographicReceiptLeaf,
  computeCryptographicReceiptLeafDigest,
  cryptographicReceiptLeafPreimage,
} from '../dist/core/cryptographicReceiptLeaf.js';
import {
  assertNoForbiddenKeys,
  normalizeUnicodeNfkc,
  FORBIDDEN_OBJECT_KEYS,
} from '../dist/core/jcsSafeObject.js';

const baseInput = {
  prevEntryHash: 'GENESIS',
  agentId: 'agent-alpha',
  sessionId: 'sess-001',
  causalParent: 'tool-call-42',
  toolName: 'auditor_scan',
  paramsHash: createHash('sha256').update('{}', 'utf8').digest('hex'),
  mandateVersionHash: createHash('sha256').update('mandate-v3', 'utf8').digest('hex'),
  wallTime: '2026-06-08T12:00:00.000Z',
  logicalSeq: 0,
};

const preimage = cryptographicReceiptLeafPreimage(baseInput);
assert.equal(Object.getPrototypeOf(preimage), null, 'preimage must use null prototype');

for (const forbidden of FORBIDDEN_OBJECT_KEYS) {
  let threw = false;
  try {
    assertNoForbiddenKeys({ [forbidden]: { nested: true } });
  } catch (e) {
    threw = e instanceof TypeError;
    assert.match(String(e.message), new RegExp(forbidden));
  }
  assert.equal(threw, true, `must reject forbidden key ${forbidden}`);
}

let pollutionBlocked = false;
try {
  buildCryptographicReceiptLeaf({
    ...baseInput,
    toolName: 'safe',
    constructor: { polluted: true },
  });
} catch (e) {
  pollutionBlocked = e instanceof TypeError;
}
assert.equal(pollutionBlocked, true, 'leaf builder must reject constructor injection');

const nfkcTool = '\uFB01le_read'; // ﬁ ligature → fi
const normalized = buildCryptographicReceiptLeaf({
  ...baseInput,
  toolName: nfkcTool,
});
assert.equal(normalized.toolName, normalizeUnicodeNfkc(nfkcTool));

const digestA = computeCryptographicReceiptLeafDigest(baseInput);
const digestB = computeCryptographicReceiptLeafDigest({ ...baseInput });
assert.equal(digestA, digestB);

console.log('OK JCS prototype-pollution + NFKC hardening tests');
