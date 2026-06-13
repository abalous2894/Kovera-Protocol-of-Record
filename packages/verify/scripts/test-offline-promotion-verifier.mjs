import { randomUUID } from 'node:crypto';
import { generateKeyPair, exportSPKI, exportPKCS8, SignJWT, importPKCS8 } from 'jose';
import { verifyPolicyPromotionProof } from '../src/offlinePromotionVerifier.js';

const { privateKey, publicKey } = await generateKeyPair('RS256');
const privatePem = await exportPKCS8(privateKey);
const publicPem = await exportSPKI(publicKey);

const signer = await importPKCS8(privatePem, 'RS256');
const jws = await new SignJWT({
  type: 'KoveraPolicyPromotionLedgerEntry',
  version: '1.0',
  precedent_id: 'precedent_demo123',
  policy_diff_hash: 'a'.repeat(64),
  operator_id: 'gov-officer',
  promoted_at: new Date().toISOString(),
  policy_dialect: 'kovera-rgp/v1',
  tenant_id: 'tenant-demo',
  context_structure_hash: 'abc123def4567890',
  allowed_transitions: ['User.update'],
  sovereignty_law_seal: { digest: 'seal-demo-digest' },
})
  .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
  .setJti(randomUUID())
  .setIssuedAt()
  .setExpirationTime('30d')
  .sign(signer);

const ok = await verifyPolicyPromotionProof(jws, [publicPem]);
if (!ok.verified) {
  console.error('expected verified promotion proof', ok);
  process.exit(1);
}

const bad = await verifyPolicyPromotionProof(jws, ['-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----']);
if (bad.verified) {
  console.error('expected verification failure for untrusted key');
  process.exit(1);
}

console.log('offline promotion verifier OK', ok.promotedPolicy?.policyDialect, ok.promotionJti);

const legacyJws = await new SignJWT({
  type: 'KoveraPolicyPromotionLedgerEntry',
  version: '1.0',
  precedent_id: 'precedent_legacy123',
  policy_diff_hash: 'b'.repeat(64),
  operator_id: 'gov-officer',
  promoted_at: new Date().toISOString(),
  policy_dialect: 'kovera-rgp/v1',
  tenant_id: 'tenant-demo',
  context_structure_hash: 'abc123def4567890',
  allowed_transitions: ['User.update'],
  sovereignty_law_seal: { digest: 'seal-legacy-digest' },
})
  .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
  .sign(signer);

const legacy = await verifyPolicyPromotionProof(legacyJws, [publicPem]);
if (!legacy.verified || !legacy.legacyEnvelope || !legacy.requiresBackgroundRenewal) {
  console.error('expected legacy migration-verified promotion proof', legacy);
  process.exit(1);
}

console.log('legacy migration verifier OK', legacy.promotedPolicy?.precedentId);
