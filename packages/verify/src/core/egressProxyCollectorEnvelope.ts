import { sha256HexUtf8 } from './sha256.js';
import { stableStringify } from './stableStringify.js';
import { EGRESS_PROXY_ATTRIBUTION_SCHEMA } from './egressProxyAttribution.js';

/** Wave 17-D Phase 1 — collector-authenticated wrapper for proxy attribution feeds. */
export const EGRESS_PROXY_COLLECTOR_ENVELOPE_SCHEMA =
  'aevesa.egress-proxy-collector-envelope/v1' as const;

export const EGRESS_PROXY_COLLECTOR_ENVELOPE_SKU =
  'aevesa-egress-proxy-collector-envelope-v1' as const;

/** Default bridge audience for collector JWS `aud` claim and envelope field. */
export const EGRESS_PROXY_COLLECTOR_DEFAULT_AUD =
  'aevesa.egress-proxy-collector-ingest/v1' as const;

export const EGRESS_PROXY_COLLECTOR_FEED_SCHEMAS = [
  EGRESS_PROXY_ATTRIBUTION_SCHEMA,
] as const;

export type EgressProxyCollectorFeedSchema =
  (typeof EGRESS_PROXY_COLLECTOR_FEED_SCHEMAS)[number];

export interface EgressProxyCollectorEnvelopeInput {
  collector_id: string;
  iss: string;
  aud?: string;
  kid: string;
  iat: number;
  exp: number;
  jti: string;
  feed_schema: EgressProxyCollectorFeedSchema | string;
  feed_digest: string;
  signature?: string;
}

export interface EgressProxyCollectorEnvelopeDocument {
  schema: typeof EGRESS_PROXY_COLLECTOR_ENVELOPE_SCHEMA;
  collector_id: string;
  iss: string;
  aud: string;
  kid: string;
  iat: number;
  exp: number;
  jti: string;
  feed_schema: string;
  feed_digest: string;
  signature: string;
  envelope_digest: string;
}

function normalizeId(value: unknown, maxLen = 256): string {
  return String(value ?? '').trim().slice(0, maxLen);
}

function normalizeHexDigest(value: unknown): string | null {
  const digest = String(value ?? '').trim().toLowerCase();
  return /^[a-f0-9]{64}$/.test(digest) ? digest : null;
}

export function buildEgressProxyCollectorEnvelopePreimage(
  input: EgressProxyCollectorEnvelopeInput,
): Omit<EgressProxyCollectorEnvelopeDocument, 'envelope_digest' | 'signature'> {
  return {
    schema: EGRESS_PROXY_COLLECTOR_ENVELOPE_SCHEMA,
    collector_id: normalizeId(input.collector_id),
    iss: normalizeId(input.iss, 512),
    aud: normalizeId(input.aud || EGRESS_PROXY_COLLECTOR_DEFAULT_AUD, 512),
    kid: normalizeId(input.kid, 128),
    iat: Number(input.iat),
    exp: Number(input.exp),
    jti: normalizeId(input.jti, 128),
    feed_schema: normalizeId(input.feed_schema || EGRESS_PROXY_ATTRIBUTION_SCHEMA, 128),
    feed_digest: normalizeHexDigest(input.feed_digest) || '',
  };
}

export function computeEgressProxyCollectorEnvelopeDigest(
  input: EgressProxyCollectorEnvelopeInput | EgressProxyCollectorEnvelopeDocument,
): string {
  const preimage = buildEgressProxyCollectorEnvelopePreimage(input);
  return sha256HexUtf8(stableStringify(preimage));
}

/** Build envelope document; supply RS256 JWS in `signature` for verified collector auth. */
export function buildEgressProxyCollectorEnvelopeDocument(
  input: EgressProxyCollectorEnvelopeInput,
): EgressProxyCollectorEnvelopeDocument {
  const envelope_digest = computeEgressProxyCollectorEnvelopeDigest(input);
  const signature = String(input.signature || '').trim();
  return {
    ...buildEgressProxyCollectorEnvelopePreimage(input),
    signature: signature || 'unsigned',
    envelope_digest,
  };
}
