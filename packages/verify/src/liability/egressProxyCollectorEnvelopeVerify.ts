import { createPublicKey, verify as cryptoVerify } from 'node:crypto';
import {
  EGRESS_PROXY_COLLECTOR_ENVELOPE_SCHEMA,
  EGRESS_PROXY_COLLECTOR_ENVELOPE_SKU,
  EGRESS_PROXY_COLLECTOR_DEFAULT_AUD,
  buildEgressProxyCollectorEnvelopePreimage,
  computeEgressProxyCollectorEnvelopeDigest,
  type EgressProxyCollectorEnvelopeDocument,
} from '../core/egressProxyCollectorEnvelope.js';
import {
  EGRESS_PROXY_ATTRIBUTION_SCHEMA,
  buildEgressProxyAttributionPreimage,
} from '../core/egressProxyAttribution.js';
import { sha256HexUtf8 } from '../core/sha256.js';
import { stableStringify } from '../core/stableStringify.js';

export interface EgressProxyCollectorEnvelopeVerifyOptions {
  /** SPKI PEM or JWK JSON for RS256 JWS verify. */
  issuerPublicKey?: string;
  /** Expected `aud` — defaults to EGRESS_PROXY_COLLECTOR_DEFAULT_AUD. */
  expectedAud?: string;
  /** Expected `iss` when pinning collector issuer. */
  expectedIss?: string;
  /** Optional linked feed for feed_digest cross-check. */
  feed?: unknown;
  /** Unix ms reference time for iat/exp window (Phase 2 bridge will enforce). */
  referenceTimeMs?: number;
  /** Max envelope age when referenceTimeMs set (default 300s). */
  maxAgeSec?: number;
  /** Future clock skew allowance when referenceTimeMs set (default 60s). */
  maxFutureSkewSec?: number;
  /** When true, skip RS256 verify (digest/structure only). */
  skipSignatureVerification?: boolean;
}

export interface EgressProxyCollectorEnvelopeVerifyChecks {
  schemaValid: boolean;
  collectorIdPresent: boolean;
  issPresent: boolean;
  audPresent: boolean;
  kidPresent: boolean;
  jtiPresent: boolean;
  iatBeforeExp: boolean;
  envelopeDigestMatches: boolean;
  feedDigestMatches: boolean | null;
  signatureValid: boolean | null;
  audMatches: boolean;
  issMatches: boolean | null;
  freshnessValid: boolean | null;
  profileComplete: boolean;
}

export interface EgressProxyCollectorEnvelopeVerifyResult {
  schema: typeof EGRESS_PROXY_COLLECTOR_ENVELOPE_SCHEMA;
  sku: typeof EGRESS_PROXY_COLLECTOR_ENVELOPE_SKU;
  ok: boolean;
  checks: EgressProxyCollectorEnvelopeVerifyChecks;
  gtmLine: string;
  note: string | null;
}

function decodeBase64Url(input: string): Buffer {
  const padded = input.replace(/-/g, '+').replace(/_/g, '/');
  const pad = padded.length % 4 === 0 ? '' : '='.repeat(4 - (padded.length % 4));
  return Buffer.from(padded + pad, 'base64');
}

function computeFeedDigest(feed: unknown): string | null {
  if (!feed || typeof feed !== 'object') return null;
  const doc = feed as Record<string, unknown>;
  const schema = String(doc.schema || '');
  if (schema === EGRESS_PROXY_ATTRIBUTION_SCHEMA) {
    if (typeof doc.attribution_digest === 'string' && /^[a-f0-9]{64}$/.test(doc.attribution_digest)) {
      return doc.attribution_digest.toLowerCase();
    }
    if (doc.generated_at) {
      try {
        const preimage = buildEgressProxyAttributionPreimage({
          session_id: doc.session_id,
          run_id: doc.run_id,
          attribution_source: doc.attribution_source,
          attribution_timing: doc.attribution_timing,
          observed_channels: doc.observed_channels,
          intent_receipt_digest: doc.intent_receipt_digest,
          registry_manifest_digest: doc.registry_manifest_digest,
          proxy_instance_id: doc.proxy_instance_id,
          generated_at: String(doc.generated_at),
        } as Parameters<typeof buildEgressProxyAttributionPreimage>[0]);
        return sha256HexUtf8(stableStringify(preimage));
      } catch {
        return null;
      }
    }
  }
  return null;
}

function verifyRs256JwsOverDigest(
  jws: string,
  expectedDigest: string,
  issuerPublicKey: string,
): { ok: boolean; error?: string } {
  const parts = jws.split('.');
  if (parts.length !== 3) {
    return { ok: false, error: 'Invalid JWS compact serialization' };
  }
  try {
    const signingInput = Buffer.from(`${parts[0]}.${parts[1]}`, 'utf8');
    const headerJson = JSON.parse(decodeBase64Url(parts[0]).toString('utf8')) as { alg?: string };
    if (headerJson.alg !== 'RS256') {
      return { ok: false, error: 'JWS header alg must be RS256' };
    }
    const sig = decodeBase64Url(parts[2]);
    const key = createPublicKey(
      issuerPublicKey.trim().startsWith('{')
        ? { key: issuerPublicKey, format: 'jwk' }
        : issuerPublicKey,
    );
    const sigOk = cryptoVerify('RSA-SHA256', signingInput, key, sig);
    if (!sigOk) {
      return { ok: false, error: 'RS256 JWS signature mismatch' };
    }
    const payloadJson = decodeBase64Url(parts[1]).toString('utf8');
    const payload = JSON.parse(payloadJson) as { envelope_digest?: string };
    if (String(payload.envelope_digest || '').toLowerCase() !== expectedDigest.toLowerCase()) {
      return { ok: false, error: 'JWS payload envelope_digest does not match envelope' };
    }
    return { ok: true };
  } catch (e) {
    return { ok: false, error: `RS256 verify failed: ${e instanceof Error ? e.message : String(e)}` };
  }
}

export function verifyEgressProxyCollectorEnvelope(
  input: unknown,
  options: EgressProxyCollectorEnvelopeVerifyOptions = {},
): EgressProxyCollectorEnvelopeVerifyResult {
  const doc =
    input != null && typeof input === 'object' && !Array.isArray(input)
      ? (input as EgressProxyCollectorEnvelopeDocument)
      : null;

  const schemaValid = doc?.schema === EGRESS_PROXY_COLLECTOR_ENVELOPE_SCHEMA;
  const collectorIdPresent = Boolean(String(doc?.collector_id || '').trim());
  const issPresent = Boolean(String(doc?.iss || '').trim());
  const audPresent = Boolean(String(doc?.aud || '').trim());
  const kidPresent = Boolean(String(doc?.kid || '').trim());
  const jtiPresent = Boolean(String(doc?.jti || '').trim());
  const iat = Number(doc?.iat);
  const exp = Number(doc?.exp);
  const iatBeforeExp = Number.isFinite(iat) && Number.isFinite(exp) && iat <= exp;

  let envelopeDigestMatches = false;
  if (schemaValid && doc) {
    const expected = computeEgressProxyCollectorEnvelopeDigest(doc);
    envelopeDigestMatches =
      String(doc.envelope_digest || '').toLowerCase() === expected.toLowerCase();
  }

  const expectedAud = options.expectedAud || EGRESS_PROXY_COLLECTOR_DEFAULT_AUD;
  const audMatches = audPresent && String(doc?.aud || '').trim() === expectedAud;

  const expectedIss = options.expectedIss ? String(options.expectedIss).trim() : null;
  const issMatches = expectedIss ? String(doc?.iss || '').trim() === expectedIss : null;

  let feedDigestMatches: boolean | null = null;
  if (options.feed != null) {
    const computed = computeFeedDigest(options.feed);
    feedDigestMatches =
      computed != null &&
      String(doc?.feed_digest || '').toLowerCase() === computed.toLowerCase();
  }

  let signatureValid: boolean | null = null;
  const signature = String(doc?.signature || '').trim();
  if (signature && signature !== 'unsigned') {
    if (options.skipSignatureVerification) {
      signatureValid = true;
    } else if (!options.issuerPublicKey) {
      signatureValid = null;
    } else if (schemaValid && envelopeDigestMatches && doc) {
      const sig = verifyRs256JwsOverDigest(
        signature,
        doc.envelope_digest,
        options.issuerPublicKey,
      );
      signatureValid = sig.ok;
    } else {
      signatureValid = false;
    }
  } else {
    signatureValid = false;
  }

  let freshnessValid: boolean | null = null;
  if (options.referenceTimeMs != null && Number.isFinite(iat) && Number.isFinite(exp)) {
    const maxAgeSec = options.maxAgeSec ?? 300;
    const maxFutureSkewSec = options.maxFutureSkewSec ?? 60;
    const nowSec = Math.floor(options.referenceTimeMs / 1000);
    freshnessValid =
      iat <= nowSec + maxFutureSkewSec &&
      exp >= nowSec &&
      nowSec - iat <= maxAgeSec;
  }

  const profileComplete =
    schemaValid &&
    collectorIdPresent &&
    issPresent &&
    audPresent &&
    kidPresent &&
    jtiPresent &&
    iatBeforeExp &&
    envelopeDigestMatches &&
    audMatches &&
    (issMatches !== false) &&
    (feedDigestMatches !== false) &&
    signatureValid === true &&
    (freshnessValid !== false);

  let note: string | null = null;
  if (!schemaValid) note = `schema must be ${EGRESS_PROXY_COLLECTOR_ENVELOPE_SCHEMA}`;
  else if (!envelopeDigestMatches) note = 'envelope_digest does not match canonical preimage';
  else if (!audMatches) note = `aud must be ${expectedAud}`;
  else if (issMatches === false) note = 'iss does not match expected collector issuer';
  else if (feedDigestMatches === false) note = 'feed_digest does not match linked proxy feed';
  else if (signatureValid === false) note = 'collector RS256 JWS signature invalid or missing';
  else if (freshnessValid === false) note = 'collector envelope outside iat/exp freshness window';
  else if (!iatBeforeExp) note = 'iat must be <= exp';

  return {
    schema: EGRESS_PROXY_COLLECTOR_ENVELOPE_SCHEMA,
    sku: EGRESS_PROXY_COLLECTOR_ENVELOPE_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      collectorIdPresent,
      issPresent,
      audPresent,
      kidPresent,
      jtiPresent,
      iatBeforeExp,
      envelopeDigestMatches,
      feedDigestMatches,
      signatureValid,
      audMatches,
      issMatches,
      freshnessValid,
      profileComplete,
    },
    gtmLine:
      'Collector-authenticated wrapper for egress proxy feeds — proves envelope signed by registered collector, not self-attested bridge ingest alone.',
    note,
  };
}
