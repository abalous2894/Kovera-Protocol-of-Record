#!/usr/bin/env node
/**
 * Wave 17-A complement — egress proxy attribution feed conformance (James J-1/J-2).
 */
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const verifyRoot = join(dirname(fileURLToPath(import.meta.url)), '..');

const buildVerify = spawnSync('npm', ['run', 'build'], {
  cwd: verifyRoot,
  stdio: 'inherit',
});
if (buildVerify.status !== 0) process.exit(buildVerify.status ?? 1);

const {
  buildEgressProxyAttributionDocument,
  verifyEgressProxyAttributionBundle,
  detectEvidenceType,
  EGRESS_PROXY_ATTRIBUTION_SCHEMA,
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

console.log('\nWave 17-A — Egress proxy attribution complement conformance\n');

const feed = buildEgressProxyAttributionDocument({
  session_id: 'sess-james-j1-proxy',
  run_id: 'run-sandbox-fetch-001',
  attribution_source: 'sandbox',
  attribution_timing: 'pre_fetch',
  observed_channels: ['https.outbound', 'dns.lookup'],
  intent_receipt_digest: 'a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456',
  registry_manifest_digest: 'fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321',
  proxy_instance_id: 'sandbox-pod-7',
  generated_at: '2026-09-11T00:00:00.000Z',
});

ok('schema', feed.schema === EGRESS_PROXY_ATTRIBUTION_SCHEMA);
ok('run_id present', feed.run_id === 'run-sandbox-fetch-001');
ok('attribution_source sandbox', feed.attribution_source === 'sandbox');

const verify = verifyEgressProxyAttributionBundle(feed);
ok('offline verify ok', verify.ok === true);
ok('digest matches', verify.checks.digestMatches === true);

const missingIntent = buildEgressProxyAttributionDocument({
  session_id: 'sess-james-j1-proxy',
  run_id: 'run-fail-pre-fetch',
  attribution_source: 'egress_proxy',
  attribution_timing: 'pre_fetch',
  observed_channels: ['https.outbound'],
  generated_at: '2026-09-11T00:00:00.000Z',
});
ok('pre_fetch without intent fails', verifyEgressProxyAttributionBundle(missingIntent).ok === false);

const detect = detectEvidenceType(feed);
ok('detectEvidenceType egress_proxy_attribution', detect.kind === 'egress_proxy_attribution');

console.log(`\n${passed} checks passed\n`);
