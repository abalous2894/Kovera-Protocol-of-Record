#!/usr/bin/env node
/**
 * CLI smoke tests for kovera-verify offline receipt leaf verification.
 */
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join as pathJoin } from 'node:path';
import {
  sealCryptographicReceiptLeaf,
  computeCryptographicReceiptLeafDigest,
} from '../dist/core/cryptographicReceiptLeaf.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const cli = pathJoin(__dirname, '..', 'dist', 'kovera-verify.js');

function runCli(args) {
  return spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
}

const leaf1Input = {
  prevEntryHash: 'GENESIS',
  agentId: 'agent-cli-test',
  sessionId: 'sess-cli-001',
  causalParent: 'tool-call-1',
  toolName: 'auditor_scan',
  paramsHash: 'a'.repeat(64),
  mandateVersionHash: 'b'.repeat(64),
  wallTime: '2026-06-08T12:00:00.000Z',
  logicalSeq: 0,
};

const leaf2Input = {
  ...leaf1Input,
  prevEntryHash: computeCryptographicReceiptLeafDigest(leaf1Input),
  causalParent: 'tool-call-2',
  logicalSeq: 1,
};

const sealed1 = sealCryptographicReceiptLeaf(leaf1Input);
const sealed2 = sealCryptographicReceiptLeaf(leaf2Input);

const tmp = mkdtempSync(join(tmpdir(), 'kovera-verify-cli-'));
const receiptPath = join(tmp, 'receipt.json');
const chainDir = join(tmp, 'chain');
mkdirSync(chainDir);

writeFileSync(
  receiptPath,
  JSON.stringify(
    {
      schema: 'liability-receipt/v1',
      receipt_id: '00000000-0000-4000-8000-000000000001',
      receiptLeaf: sealed1,
      receiptLeafDigest: sealed1.receiptLeafDigest,
    },
    null,
    2,
  ),
);

writeFileSync(join(chainDir, '001.json'), JSON.stringify(sealed1, null, 2));
writeFileSync(join(chainDir, '002.json'), JSON.stringify(sealed2, null, 2));

const ok = runCli(['--receipt', receiptPath]);
assert.equal(ok.status, 0, ok.stderr || ok.stdout);
assert.match(ok.stdout, /\[VERIFIED\]/);

const okChain = runCli(['--receipt', join(chainDir, '001.json'), '--chain', chainDir]);
assert.equal(okChain.status, 0, okChain.stderr || okChain.stdout);
assert.match(okChain.stdout, /chain:/);

const tamperedPath = join(tmp, 'tampered.json');
const tampered = structuredClone(sealed1);
tampered.logicalSeq = 99;
writeFileSync(tamperedPath, JSON.stringify(tampered, null, 2));

const bad = runCli(['--receipt', tamperedPath]);
assert.equal(bad.status, 1);
assert.match(bad.stderr, /digest mismatch/i);

const brokenChainPath = join(tmp, 'broken-chain');
mkdirSync(brokenChainPath);
writeFileSync(join(brokenChainPath, 'a.json'), JSON.stringify(sealed1, null, 2));
const brokenSecond = sealCryptographicReceiptLeaf({
  ...leaf2Input,
  prevEntryHash: 'f'.repeat(64),
});
writeFileSync(join(brokenChainPath, 'b.json'), JSON.stringify(brokenSecond, null, 2));

const broken = runCli(['--receipt', join(brokenChainPath, 'a.json'), '--chain', brokenChainPath]);
assert.equal(broken.status, 1);
assert.match(broken.stderr, /chain broken/i);

rmSync(tmp, { recursive: true, force: true });
console.log('OK kovera-verify CLI tests');
