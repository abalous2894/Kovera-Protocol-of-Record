#!/usr/bin/env node
/**
 * JCS (RFC 8785) + cryptographic receipt leaf digest tests.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  computeCryptographicReceiptLeafDigest,
  sealCryptographicReceiptLeaf,
  buildCryptographicReceiptLeaf,
} from '../dist/core/cryptographicReceiptLeaf.js';
import { canonicalizeJcs, serializeJcs } from '../dist/core/jcs.js';

assert.equal(canonicalizeJcs({ b: 2, a: 1 }), '{"a":1,"b":2}');
assert.equal(serializeJcs(null), 'null');
assert.equal(serializeJcs(true), 'true');
assert.equal(serializeJcs(-0), '0');

const leafInput = {
  prevEntryHash: 'GENESIS',
  agentId: 'agent-alpha',
  sessionId: 'sess-001',
  causalParent: 'tool-call-42',
  toolName: 'auditor_scan',
  paramsHash: createHash('sha256').update('{}', 'utf8').digest('hex'),
  mandateVersionHash: createHash('sha256').update('mandate-v3', 'utf8').digest('hex'),
  wallTime: '2026-06-08T12:00:00.000Z',
  logicalSeq: 7,
};

const digestA = computeCryptographicReceiptLeafDigest(leafInput);
const digestB = computeCryptographicReceiptLeafDigest({ ...leafInput });
assert.equal(digestA, digestB);
assert.match(digestA, /^[a-f0-9]{64}$/);

const sealed = sealCryptographicReceiptLeaf(leafInput);
assert.equal(sealed.receiptLeafDigest, digestA);
assert.equal(sealed.schema, 'kovera/cryptographic-receipt-leaf/v1');

const tampered = computeCryptographicReceiptLeafDigest({ ...leafInput, logicalSeq: 8 });
assert.notEqual(tampered, digestA);

const rebuilt = buildCryptographicReceiptLeaf(leafInput);
const preimage = canonicalizeJcs({
  schema: rebuilt.schema,
  prevEntryHash: rebuilt.prevEntryHash,
  agentId: rebuilt.agentId,
  sessionId: rebuilt.sessionId,
  causalParent: rebuilt.causalParent,
  toolName: rebuilt.toolName,
  paramsHash: rebuilt.paramsHash,
  mandateVersionHash: rebuilt.mandateVersionHash,
  wallTime: rebuilt.wallTime,
  logicalSeq: rebuilt.logicalSeq,
});
assert.equal(createHash('sha256').update(preimage, 'utf8').digest('hex'), digestA);

console.log('OK jcs + cryptographic receipt leaf tests');
