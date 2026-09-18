#!/usr/bin/env node
/**
 * PC-05 optional — embedded issuer_public_key_pem enables offline RS256 verify.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKeyPair, exportSPKI, exportPKCS8, SignJWT, importPKCS8 } from 'jose';

const pkgRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const { verifyReceipt, computeCanonicalReceiptDigest, resolveEmbeddedIssuerPublicKey, sha256HexUtf8 } =
  await import(join(pkgRoot, 'dist/index.js'));

let passed = 0;
function ok(label, cond) {
  assert.equal(cond, true, label);
  passed += 1;
  console.log(`  ✓ ${label}`);
}

console.log('\nEmbedded issuer key — liability receipt RS256 verify\n');

const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });
const spki = await exportSPKI(publicKey);
const pkcs8 = await exportPKCS8(privateKey);

const receipt = {
  schema: 'liability-receipt/v1',
  receipt_id: '00000000-0000-4000-8000-000000000099',
  issued_at: '2026-09-12T12:00:00.000Z',
  issuer: { name: 'Aevesa', product: 'Test', verification_profile: 'aegis/1' },
  session: {
    session_id: 'embedded-key-test',
    correlation_id: 'embedded-key-test',
    vertical: 'enterprise_ops',
    outcome: 'permitted',
    started_at: '2026-09-12T12:00:00.000Z',
    completed_at: '2026-09-12T12:00:00.000Z',
  },
  identity: {
    primary_actor: { agent_id: 'test-agent', actor_class: 'autonomous_agent' },
    authority: { scoped_role: 'SERVER', permission_id: 'test' },
  },
  policy: {
    policy_pack_id: 'test_pack_v1',
    policy_version_hash: sha256HexUtf8('test_pack_v1'),
    decision: 'allow_within_ceiling',
  },
  hitl: { required: false, status: 'not_required' },
  side_effects: {
    action: { tool_name: 'noop', verb: 'read', target_path: '/tmp/x' },
    effect_class: 'data_access',
    summary: 'test',
  },
  proof: {
    ledger_spec: 'aegis/1',
    primary_anchor: {
      entry_hash: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      event_type: 'DELEGATED_ACTION',
      timestamp: '2026-09-12T12:00:00.000Z',
    },
    verification: { status: 'demo', methods: ['embedded_key_test'] },
  },
  diligence_summary: {
    who_acted: 'test',
    what_policy_allowed: 'test',
    what_proof_says: 'test',
  },
  integrity: {
    receipt_digest: '',
    signature_alg: 'none',
    signature: null,
    manifest_signature_jws: null,
  },
};

receipt.integrity.receipt_digest = computeCanonicalReceiptDigest(receipt);
const key = await importPKCS8(pkcs8, 'RS256');
const jws = await new SignJWT({
  typ: 'aevesa-liability-receipt+jws',
  schema: receipt.schema,
  receipt_id: receipt.receipt_id,
  receipt_digest: receipt.integrity.receipt_digest,
})
  .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
  .sign(key);

receipt.integrity.signature_alg = 'RS256';
receipt.integrity.manifest_signature_jws = jws;
receipt.integrity.issuer_public_key_pem = spki.trim();

ok('resolve embedded pem', resolveEmbeddedIssuerPublicKey(receipt.integrity) === spki.trim());
ok('verify without explicit options', verifyReceipt(receipt).isValid === true);
ok('verify fails when embedded pem removed', verifyReceipt({ ...receipt, integrity: { ...receipt.integrity, issuer_public_key_pem: null } }, { skipIntegritySignatureWithoutKey: false }).isValid === false);

console.log(`\n${passed} checks passed.\n`);
