import { sha256HexUtf8 } from './sha256.js';
import { stableStringify } from './stableStringify.js';
import {
  ATTRIBUTION_TIMING_VALUES,
  type AttributionTiming,
} from './egressAttestationV2.js';

/** Wave 17-A complement — sandbox / egress proxy attribution feed (James J-1/J-2). */

export const EGRESS_PROXY_ATTRIBUTION_SCHEMA = 'aevesa.egress-proxy-attribution/v1' as const;
export const EGRESS_PROXY_ATTRIBUTION_SKU = 'aevesa-egress-proxy-attribution-v1' as const;

export const ATTRIBUTION_SOURCE_VALUES = ['egress_proxy', 'sandbox', 'network_observe'] as const;

export type AttributionSource = (typeof ATTRIBUTION_SOURCE_VALUES)[number];

export interface EgressProxyAttributionInput {
  session_id?: string | null;
  run_id: string;
  attribution_source: AttributionSource;
  attribution_timing: AttributionTiming;
  observed_channels: string[];
  intent_receipt_digest?: string | null;
  registry_manifest_digest?: string | null;
  proxy_instance_id?: string | null;
  generated_at?: string;
}

export interface EgressProxyAttributionDocument {
  schema: typeof EGRESS_PROXY_ATTRIBUTION_SCHEMA;
  session_id: string | null;
  run_id: string;
  attribution_source: AttributionSource;
  attribution_timing: AttributionTiming;
  observed_channels: string[];
  intent_receipt_digest: string | null;
  registry_manifest_digest: string | null;
  proxy_instance_id: string | null;
  generated_at: string;
  attribution_digest: string;
}

function normalizeHexDigest(value: unknown): string | null {
  const digest = String(value ?? '').trim().toLowerCase();
  return /^[a-f0-9]{64}$/.test(digest) ? digest : null;
}

function normalizeSessionId(value: unknown): string | null {
  const sessionId = String(value ?? '').trim();
  return sessionId.length > 0 ? sessionId.slice(0, 256) : null;
}

export function buildEgressProxyAttributionPreimage(
  input: EgressProxyAttributionInput & { generated_at: string },
): Omit<EgressProxyAttributionDocument, 'attribution_digest'> {
  return {
    schema: EGRESS_PROXY_ATTRIBUTION_SCHEMA,
    session_id: normalizeSessionId(input.session_id),
    run_id: String(input.run_id || '').trim().slice(0, 256),
    attribution_source: input.attribution_source,
    attribution_timing: input.attribution_timing,
    observed_channels: (input.observed_channels ?? [])
      .map((c) => String(c).trim())
      .filter(Boolean)
      .slice(0, 32),
    intent_receipt_digest: normalizeHexDigest(input.intent_receipt_digest),
    registry_manifest_digest: normalizeHexDigest(input.registry_manifest_digest),
    proxy_instance_id: input.proxy_instance_id
      ? String(input.proxy_instance_id).trim().slice(0, 256)
      : null,
    generated_at: input.generated_at,
  };
}

export function buildEgressProxyAttributionDocument(
  input: EgressProxyAttributionInput,
): EgressProxyAttributionDocument {
  const generated_at = input.generated_at || new Date().toISOString();
  const preimage = buildEgressProxyAttributionPreimage({ ...input, generated_at });
  const attribution_digest = sha256HexUtf8(stableStringify(preimage));
  return { ...preimage, attribution_digest };
}

export function includesAttributionSource(value: unknown): value is AttributionSource {
  return typeof value === 'string' && (ATTRIBUTION_SOURCE_VALUES as readonly string[]).includes(value);
}

export function includesProxyAttributionTiming(value: unknown): value is AttributionTiming {
  return typeof value === 'string' && (ATTRIBUTION_TIMING_VALUES as readonly string[]).includes(value);
}
