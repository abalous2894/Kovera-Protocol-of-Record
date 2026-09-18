import { sha256HexUtf8 } from './sha256.js';
import { stableStringify } from './stableStringify.js';
import {
  buildEgressProxyAttributionDocument,
  type EgressProxyAttributionDocument,
  type EgressProxyAttributionInput,
} from './egressProxyAttribution.js';
import type { AttributionTiming } from './egressAttestationV2.js';

/** Wave 17-A / PC-07 — live egress-proxy vendor wire → aevesa.egress-proxy-attribution/v1 */

export const SQUID_ACCESS_LOG_SCHEMA = 'squid.access-log/v1' as const;
export const ENVOY_ACCESS_LOG_SCHEMA = 'envoy.access-log/v1' as const;
export const MITMPROXY_FLOW_SCHEMA = 'mitmproxy.flow/v1' as const;
export const GENERIC_PROXY_WEBHOOK_SCHEMA = 'aevesa.generic-egress-proxy-webhook/v1' as const;

export const EGRESS_PROXY_VENDOR_ADAPTER_IDS = [
  'squid',
  'envoy',
  'mitmproxy',
  'zscaler_zia',
  'generic',
  'aevesa_native',
] as const;

export type EgressProxyVendorAdapterId = (typeof EGRESS_PROXY_VENDOR_ADAPTER_IDS)[number];

export interface EgressProxyVendorAdaptContext {
  session_id?: string | null;
  intent_receipt_digest?: string | null;
  registry_manifest_digest?: string | null;
  attribution_timing?: AttributionTiming | null;
  proxy_instance_id?: string | null;
  generated_at?: string | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function normalizeHex64(value: unknown): string | null {
  const digest = String(value ?? '').trim().toLowerCase();
  return /^[a-f0-9]{64}$/.test(digest) ? digest : null;
}

function digestJson(value: unknown): string {
  return sha256HexUtf8(stableStringify(value));
}

function firstString(...values: unknown[]): string | null {
  for (const value of values) {
    const s = String(value ?? '').trim();
    if (s) return s;
  }
  return null;
}

export function observedChannelsFromUrl(urlRaw: unknown): string[] {
  const url = String(urlRaw ?? '').trim();
  const channels = new Set<string>(['https.outbound']);
  if (!url) return [...channels];
  try {
    const parsed = new URL(url);
    channels.add(`host.${parsed.hostname}`);
    if (parsed.protocol === 'https:') channels.add('tls.egress');
    if (/registry|npm|pypi|mirror|resolver|artifactory|nexus/i.test(url)) {
      channels.add('resolver.mirror');
      channels.add('dns.lookup');
    }
  } catch {
    if (/registry|npm|pypi|mirror|resolver/i.test(url)) {
      channels.add('resolver.mirror');
      channels.add('dns.lookup');
    }
  }
  return [...channels].slice(0, 32);
}

function resolveRunId(raw: Record<string, unknown>, url: string | null): string {
  const explicit = firstString(
    raw.run_id,
    raw.runId,
    raw.request_id,
    raw.requestId,
    raw.flow_id,
    raw.flowId,
    raw.x_request_id,
    raw.trace_id,
    raw.correlation_id,
  );
  if (explicit) return explicit.slice(0, 256);
  return digestJson({
    schema: 'aevesa.egress-proxy-run-id/v1',
    url: url || null,
    timestamp: firstString(raw.timestamp, raw.time, raw.generated_at, raw.start_time) || null,
    session_id: firstString(raw.session_id, raw.sessionId, raw.sourceContext) || null,
  }).slice(0, 256);
}

function resolveAttributionTiming(
  raw: Record<string, unknown>,
  ctx: EgressProxyVendorAdaptContext,
): AttributionTiming {
  const explicit = firstString(raw.attribution_timing, raw.attributionTiming, ctx.attribution_timing);
  if (
    explicit === 'pre_fetch'
    || explicit === 'post_fetch'
    || explicit === 'runtime_only'
    || explicit === 'network_observe'
  ) {
    return explicit;
  }
  const intent = normalizeHex64(
    raw.intent_receipt_digest ?? raw.intentReceiptDigest ?? ctx.intent_receipt_digest,
  );
  if (intent) return 'pre_fetch';
  return 'network_observe';
}

function mergeContext(
  raw: Record<string, unknown>,
  ctx: EgressProxyVendorAdaptContext,
): EgressProxyAttributionInput {
  const url = firstString(raw.url, raw.request_url, raw.requestUrl, raw.uri, raw.destination);
  const session_id =
    firstString(raw.session_id, raw.sessionId, raw.sourceContext, raw.client_session_id, ctx.session_id) ||
    null;
  const intent_receipt_digest =
    normalizeHex64(raw.intent_receipt_digest ?? raw.intentReceiptDigest ?? ctx.intent_receipt_digest) ||
    null;
  const registry_manifest_digest =
    normalizeHex64(
      raw.registry_manifest_digest ?? raw.registryManifestDigest ?? ctx.registry_manifest_digest,
    ) || null;
  const attribution_timing = resolveAttributionTiming(raw, ctx);
  const proxy_instance_id =
    firstString(
      raw.proxy_instance_id,
      raw.proxyInstanceId,
      raw.instance_id,
      raw.node_id,
      raw.pod_name,
      ctx.proxy_instance_id,
    ) || null;
  const generated_at =
    firstString(raw.generated_at, raw.timestamp, raw.time, raw.start_time, ctx.generated_at) ||
    undefined;

  return {
    session_id,
    run_id: resolveRunId(raw, url),
    attribution_source:
      raw.attribution_source === 'sandbox'
        ? 'sandbox'
        : raw.attribution_source === 'network_observe'
          ? 'network_observe'
          : 'egress_proxy',
    attribution_timing,
    observed_channels: observedChannelsFromUrl(url),
    intent_receipt_digest,
    registry_manifest_digest,
    proxy_instance_id,
    generated_at,
  };
}

export function detectEgressProxyVendor(
  payload: unknown,
  headerHint?: string | null,
): EgressProxyVendorAdapterId {
  const hint = String(headerHint || '').trim().toLowerCase();
  if (hint === 'squid') return 'squid';
  if (hint === 'envoy') return 'envoy';
  if (hint === 'mitmproxy' || hint === 'mitm') return 'mitmproxy';
  if (hint === 'zscaler' || hint === 'zscaler_zia' || hint === 'zia') return 'zscaler_zia';
  if (hint === 'generic') return 'generic';
  if (hint === 'aevesa' || hint === 'aevesa_native') return 'aevesa_native';

  const raw = asRecord(payload);
  if (!raw) return 'generic';
  if (raw.schema === 'aevesa.egress-proxy-attribution/v1') return 'aevesa_native';

  const schema = String(raw.schema || '').trim().toLowerCase();
  if (schema === SQUID_ACCESS_LOG_SCHEMA || schema.startsWith('squid.')) return 'squid';
  if (schema === ENVOY_ACCESS_LOG_SCHEMA || schema.startsWith('envoy.')) return 'envoy';
  if (schema === MITMPROXY_FLOW_SCHEMA || schema.startsWith('mitmproxy.')) return 'mitmproxy';
  if (schema === GENERIC_PROXY_WEBHOOK_SCHEMA) return 'generic';
  if (raw.squid_request_status || raw.hierarchy_code) return 'squid';
  if (raw.authority || raw.upstream_cluster || raw.response_flags) return 'envoy';
  if (raw.flow_id && asRecord(raw.request)) return 'mitmproxy';
  if (raw.zia_transaction_id || raw.ziaTransactionId) return 'zscaler_zia';
  return 'generic';
}

export function normalizeSquidAccessLog(
  payload: unknown,
  ctx: EgressProxyVendorAdaptContext = {},
): EgressProxyAttributionInput {
  const raw = asRecord(payload) || {};
  const url = firstString(raw.url, raw.request_uri, raw.requestUri, raw.uri);
  const merged = mergeContext({ ...raw, url }, ctx);
  return {
    ...merged,
    observed_channels: [
      ...new Set([
        ...merged.observed_channels,
        raw.method ? `http.method.${String(raw.method).toLowerCase()}` : null,
        raw.hierarchy_code ? `squid.hierarchy.${String(raw.hierarchy_code)}` : null,
      ].filter(Boolean) as string[]),
    ].slice(0, 32),
  };
}

export function normalizeEnvoyAccessLog(
  payload: unknown,
  ctx: EgressProxyVendorAdaptContext = {},
): EgressProxyAttributionInput {
  const raw = asRecord(payload) || {};
  const authority = firstString(raw.authority, raw.host, raw.upstream_host);
  const path = firstString(raw.path, raw.request_path);
  const url =
    firstString(raw.url, raw.request_url) ||
    (authority ? `https://${authority}${path || ''}` : null);
  const merged = mergeContext({ ...raw, url }, ctx);
  const cluster = firstString(raw.upstream_cluster, raw.cluster_name);
  return {
    ...merged,
    observed_channels: [
      ...new Set([
        ...merged.observed_channels,
        cluster ? `envoy.cluster.${cluster}` : null,
        raw.response_code != null ? `http.status.${String(raw.response_code)}` : null,
      ].filter(Boolean) as string[]),
    ].slice(0, 32),
  };
}

export function normalizeMitmproxyFlow(
  payload: unknown,
  ctx: EgressProxyVendorAdaptContext = {},
): EgressProxyAttributionInput {
  const raw = asRecord(payload) || {};
  const request = asRecord(raw.request) || {};
  const host = firstString(request.host, request.pretty_host, raw.host);
  const path = firstString(request.path, raw.path);
  const scheme = firstString(request.scheme, raw.scheme) || 'https';
  const url =
    firstString(raw.url, request.url) ||
    (host ? `${scheme}://${host}${path || ''}` : null);
  const merged = mergeContext({ ...raw, url, flow_id: raw.flow_id ?? raw.id }, ctx);
  return {
    ...merged,
    observed_channels: [
      ...new Set([
        ...merged.observed_channels,
        request.method ? `http.method.${String(request.method).toLowerCase()}` : null,
        'mitmproxy.intercept',
      ].filter(Boolean) as string[]),
    ].slice(0, 32),
  };
}

export function normalizeZscalerZiaLog(
  payload: unknown,
  ctx: EgressProxyVendorAdaptContext = {},
): EgressProxyAttributionInput {
  const raw = asRecord(payload) || {};
  const url = firstString(raw.url, raw.destination_url, raw.hostname, raw.domain);
  const merged = mergeContext(
    {
      ...raw,
      url,
      request_id: raw.zia_transaction_id ?? raw.ziaTransactionId ?? raw.transaction_id,
      proxy_instance_id: raw.zia_gateway ?? raw.gateway_name,
    },
    ctx,
  );
  return {
    ...merged,
    attribution_source: 'network_observe',
    observed_channels: [
      ...new Set([
        ...merged.observed_channels,
        raw.action ? `zscaler.action.${String(raw.action).toLowerCase()}` : null,
        raw.policy_name ? 'zscaler.policy.bound' : null,
      ].filter(Boolean) as string[]),
    ].slice(0, 32),
  };
}

export function normalizeGenericProxyWebhook(
  payload: unknown,
  ctx: EgressProxyVendorAdaptContext = {},
): EgressProxyAttributionInput {
  const raw = asRecord(payload) || {};
  const channels = Array.isArray(raw.observed_channels)
    ? raw.observed_channels.map((c) => String(c).trim()).filter(Boolean)
    : observedChannelsFromUrl(firstString(raw.url, raw.destination, raw.host));
  const merged = mergeContext(raw, ctx);
  return {
    ...merged,
    observed_channels: channels.length > 0 ? channels.slice(0, 32) : merged.observed_channels,
    attribution_source:
      raw.attribution_source === 'sandbox'
        ? 'sandbox'
        : raw.attribution_source === 'network_observe'
          ? 'network_observe'
          : merged.attribution_source,
  };
}

export function normalizeEgressProxyVendorPayload(
  vendorId: EgressProxyVendorAdapterId,
  payload: unknown,
  ctx: EgressProxyVendorAdaptContext = {},
): EgressProxyAttributionInput {
  switch (vendorId) {
    case 'squid':
      return normalizeSquidAccessLog(payload, ctx);
    case 'envoy':
      return normalizeEnvoyAccessLog(payload, ctx);
    case 'mitmproxy':
      return normalizeMitmproxyFlow(payload, ctx);
    case 'zscaler_zia':
      return normalizeZscalerZiaLog(payload, ctx);
    case 'aevesa_native':
      return normalizeGenericProxyWebhook(payload, ctx);
    case 'generic':
    default:
      return normalizeGenericProxyWebhook(payload, ctx);
  }
}

export function buildEgressProxyAttributionFromVendor(
  payload: unknown,
  options: EgressProxyVendorAdaptContext & {
    vendor_adapter_id?: EgressProxyVendorAdapterId | null;
    vendorHint?: string | null;
  } = {},
): { vendor_adapter_id: EgressProxyVendorAdapterId; document: EgressProxyAttributionDocument } {
  const raw = asRecord(payload);
  if (raw?.schema === 'aevesa.egress-proxy-attribution/v1' && raw.attribution_digest) {
    return {
      vendor_adapter_id: 'aevesa_native',
      document: raw as unknown as EgressProxyAttributionDocument,
    };
  }

  const vendor_adapter_id =
    options.vendor_adapter_id ||
    detectEgressProxyVendor(payload, options.vendorHint ?? null);
  const input = normalizeEgressProxyVendorPayload(vendor_adapter_id, payload, options);
  return {
    vendor_adapter_id,
    document: buildEgressProxyAttributionDocument(input),
  };
}
