#!/usr/bin/env node
/**
 * Wave 17-D Phase 1 — egress proxy collector envelope offline conformance.
 */
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKeyPair, exportSPKI, exportPKCS8, SignJWT, importPKCS8 } from 'jose';

const verifyRoot = join(dirname(fileURLToPath(import.meta.url)), '..');

const buildVerify = spawnSync('npm', ['run', 'build'], {
  cwd: verifyRoot,
  stdio: 'inherit',
});
if (buildVerify.status !== 0) process.exit(buildVerify.status ?? 1);

const {
  buildEgressProxyAttributionDocument,
  buildEgressProxyCollectorEnvelopeDocument,
  computeEgressProxyCollectorEnvelopeDigest,
  verifyEgressProxyCollectorEnvelope,
  detectEvidenceType,
  EGRESS_PROXY_COLLECTOR_ENVELOPE_SCHEMA,
  EGRESS_PROXY_COLLECTOR_DEFAULT_AUD,
} = await import('@aevesa/verify');

let passed = 0;
function ok(label, cond) {
  if (!cond) {
    console.error(`  ✗ ${label}`);
    process.exit(1);
  }
  passed += 1;
  console.log(`  ✓ ${label}`);
}

async function signEnvelopeDigest(envelopeInput, privateKey, kid) {
  const digest = computeEgressProxyCollectorEnvelopeDigest(envelopeInput);
  return new SignJWT({ envelope_digest: digest })
    .setProtectedHeader({ alg: 'RS256', kid })
    .sign(privateKey);
}

console.log('\nWave 17-D Phase 1 — Egress proxy collector envelope\n');

const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });
const publicPem = await exportSPKI(publicKey);
const privatePkcs8 = await exportPKCS8(privateKey);
const signingKey = await importPKCS8(privatePkcs8, 'RS256');

const feed = buildEgressProxyAttributionDocument({
  session_id: 'sess-collector-phase1',
  run_id: 'run-collector-001',
  attribution_source: 'egress_proxy',
  attribution_timing: 'pre_fetch',
  observed_channels: ['https.outbound'],
  intent_receipt_digest: 'a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456',
  generated_at: '2026-09-13T12:00:00.000Z',
});

const nowSec = Math.floor(Date.parse('2026-09-13T12:00:00.000Z') / 1000);
const envelopeInput = {
  collector_id: 'squid-edge-01',
  iss: 'https://collector.example/spiffe/squid-edge-01',
  aud: EGRESS_PROXY_COLLECTOR_DEFAULT_AUD,
  kid: 'collector-key-1',
  iat: nowSec,
  exp: nowSec + 300,
  jti: 'jti-phase1-fixture-001',
  feed_schema: feed.schema,
  feed_digest: feed.attribution_digest,
};

const signature = await signEnvelopeDigest(envelopeInput, signingKey, envelopeInput.kid);
const envelope = buildEgressProxyCollectorEnvelopeDocument({
  ...envelopeInput,
  signature,
});

ok('schema', envelope.schema === EGRESS_PROXY_COLLECTOR_ENVELOPE_SCHEMA);
ok('envelope_digest present', /^[a-f0-9]{64}$/.test(envelope.envelope_digest));

const verify = verifyEgressProxyCollectorEnvelope(envelope, {
  issuerPublicKey: publicPem,
  feed,
  expectedIss: envelopeInput.iss,
  referenceTimeMs: Date.parse('2026-09-13T12:00:01.000Z'),
});
ok('offline verify ok', verify.ok === true);
ok('signature valid', verify.checks.signatureValid === true);
ok('feed digest matches', verify.checks.feedDigestMatches === true);
ok('freshness valid', verify.checks.freshnessValid === true);

const stale = verifyEgressProxyCollectorEnvelope(envelope, {
  issuerPublicKey: publicPem,
  feed,
  referenceTimeMs: Date.parse('2026-09-13T12:10:00.000Z'),
  maxAgeSec: 300,
});
ok('stale iat fails freshness', stale.checks.freshnessValid === false);
ok('stale envelope not ok', stale.ok === false);

const badSig = buildEgressProxyCollectorEnvelopeDocument({
  ...envelopeInput,
  signature: `${signature.slice(0, -4)}aaaa`,
});
ok(
  'tampered signature fails',
  verifyEgressProxyCollectorEnvelope(badSig, { issuerPublicKey: publicPem, feed }).ok === false,
);

const wrongFeedDigest = buildEgressProxyCollectorEnvelopeDocument({
  ...envelopeInput,
  feed_digest: '0'.repeat(64),
  signature: 'unsigned',
});
ok(
  'wrong feed_digest fails',
  verifyEgressProxyCollectorEnvelope(wrongFeedDigest, { feed }).checks.feedDigestMatches === false,
);

const detect = detectEvidenceType(envelope);
ok('detectEvidenceType collector envelope', detect.kind === 'egress_proxy_collector_envelope');

console.log(`\n${passed} checks passed\n`);
