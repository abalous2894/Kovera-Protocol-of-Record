#!/usr/bin/env node
/**
 * PC-07 — live egress-proxy vendor adapter conformance (James J-1/J-2).
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
  detectEgressProxyVendor,
  buildEgressProxyAttributionFromVendor,
  verifyEgressProxyAttributionBundle,
  observedChannelsFromUrl,
  SQUID_ACCESS_LOG_SCHEMA,
  ENVOY_ACCESS_LOG_SCHEMA,
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

console.log('\nPC-07 — Egress proxy vendor adapter conformance\n');

ok(
  'resolver mirror channel',
  observedChannelsFromUrl('https://registry.npmjs.org/lodash').includes('resolver.mirror'),
);

ok('detect squid schema', detectEgressProxyVendor({ schema: SQUID_ACCESS_LOG_SCHEMA }) === 'squid');
ok('detect envoy schema', detectEgressProxyVendor({ schema: ENVOY_ACCESS_LOG_SCHEMA }) === 'envoy');
ok(
  'detect mitmproxy flow',
  detectEgressProxyVendor({ flow_id: 'f-1', request: { host: 'pypi.org' } }) === 'mitmproxy',
);
ok('header hint zscaler', detectEgressProxyVendor({}, 'zscaler_zia') === 'zscaler_zia');

const intentDigest = 'a'.repeat(64);
const squidAdapted = buildEgressProxyAttributionFromVendor(
  {
    schema: SQUID_ACCESS_LOG_SCHEMA,
    request_id: 'squid-req-001',
    url: 'https://registry.npmjs.org/express/-/express-4.18.0.tgz',
    session_id: 'sess-squid-live',
    intent_receipt_digest: intentDigest,
    timestamp: '2026-09-12T20:00:00.000Z',
    hierarchy_code: 'HIER_DIRECT',
    method: 'GET',
  },
  { vendorHint: 'squid' },
);
ok('squid vendor id', squidAdapted.vendor_adapter_id === 'squid');
ok('squid run_id', squidAdapted.document.run_id === 'squid-req-001');
ok('squid pre_fetch', squidAdapted.document.attribution_timing === 'pre_fetch');
ok(
  'squid verify',
  verifyEgressProxyAttributionBundle(squidAdapted.document).ok === true,
);

const envoyAdapted = buildEgressProxyAttributionFromVendor({
  schema: ENVOY_ACCESS_LOG_SCHEMA,
  request_id: 'envoy-req-99',
  authority: 'pypi.org',
  path: '/simple/requests/',
  upstream_cluster: 'egress_default',
  response_code: 200,
  session_id: 'sess-envoy-live',
});
ok('envoy vendor id', envoyAdapted.vendor_adapter_id === 'envoy');
ok('envoy network_observe default', envoyAdapted.document.attribution_timing === 'network_observe');
ok(
  'envoy cluster channel',
  envoyAdapted.document.observed_channels.some((c) => c.startsWith('envoy.cluster.')),
);

const mitmAdapted = buildEgressProxyAttributionFromVendor({
  schema: 'mitmproxy.flow/v1',
  flow_id: 'flow-abc',
  request: {
    host: 'mirror.internal.corp',
    path: '/artifactory/npm/lodash',
    method: 'CONNECT',
    scheme: 'https',
  },
  session_id: 'sess-mitm-live',
  intent_receipt_digest: intentDigest,
});
ok('mitmproxy vendor id', mitmAdapted.vendor_adapter_id === 'mitmproxy');
ok(
  'mitmproxy resolver channel',
  mitmAdapted.document.observed_channels.includes('resolver.mirror'),
);

console.log(`\n${passed} checks passed\n`);
