import { sha256HexUtf8 } from '../core/sha256.js';
import { stableStringify } from '../core/stableStringify.js';
import {
  EGRESS_PROXY_ATTRIBUTION_SCHEMA,
  EGRESS_PROXY_ATTRIBUTION_SKU,
  buildEgressProxyAttributionPreimage,
  includesAttributionSource,
  includesProxyAttributionTiming,
  type EgressProxyAttributionDocument,
} from '../core/egressProxyAttribution.js';

export interface EgressProxyAttributionVerifyResult {
  schema: typeof EGRESS_PROXY_ATTRIBUTION_SCHEMA;
  sku: typeof EGRESS_PROXY_ATTRIBUTION_SKU;
  ok: boolean;
  checks: {
    schemaValid: boolean;
    runIdPresent: boolean;
    attributionSourceValid: boolean;
    attributionTimingValid: boolean;
    observedChannelsPresent: boolean;
    digestMatches: boolean;
    preFetchIntentBound: boolean;
    profileComplete: boolean;
  };
  gtmLine: string;
  note: string | null;
}

export function verifyEgressProxyAttributionBundle(input: unknown): EgressProxyAttributionVerifyResult {
  const doc =
    input != null && typeof input === 'object' && !Array.isArray(input)
      ? (input as EgressProxyAttributionDocument)
      : null;

  const schemaValid = doc?.schema === EGRESS_PROXY_ATTRIBUTION_SCHEMA;
  const runIdPresent = Boolean(String(doc?.run_id || '').trim());
  const attributionSourceValid = includesAttributionSource(doc?.attribution_source);
  const attributionTimingValid = includesProxyAttributionTiming(doc?.attribution_timing);
  const observedChannelsPresent =
    Array.isArray(doc?.observed_channels) &&
    doc!.observed_channels.length > 0 &&
    doc!.observed_channels.every((item) => typeof item === 'string' && item.trim().length > 0);

  let digestMatches = false;
  if (
    schemaValid &&
    runIdPresent &&
    attributionSourceValid &&
    attributionTimingValid &&
    observedChannelsPresent &&
    doc?.generated_at
  ) {
    const expected = sha256HexUtf8(
      stableStringify(
        buildEgressProxyAttributionPreimage({
          session_id: doc!.session_id,
          run_id: doc!.run_id,
          attribution_source: doc!.attribution_source,
          attribution_timing: doc!.attribution_timing,
          observed_channels: doc!.observed_channels,
          intent_receipt_digest: doc!.intent_receipt_digest ?? null,
          registry_manifest_digest: doc!.registry_manifest_digest ?? null,
          proxy_instance_id: doc!.proxy_instance_id ?? null,
          generated_at: doc!.generated_at,
        }),
      ),
    );
    digestMatches = String(doc!.attribution_digest || '').toLowerCase() === expected;
  }

  const intentDigest = String(doc?.intent_receipt_digest || '').trim().toLowerCase();
  const preFetchIntentBound =
    doc?.attribution_timing !== 'pre_fetch' || /^[a-f0-9]{64}$/.test(intentDigest);

  const profileComplete =
    schemaValid &&
    runIdPresent &&
    attributionSourceValid &&
    attributionTimingValid &&
    observedChannelsPresent &&
    digestMatches &&
    preFetchIntentBound;

  let note: string | null = null;
  if (!schemaValid) note = `schema must be ${EGRESS_PROXY_ATTRIBUTION_SCHEMA}`;
  else if (!digestMatches) note = 'attribution_digest does not match canonical preimage';
  else if (!runIdPresent) note = 'run_id required';
  else if (!attributionSourceValid) note = 'attribution_source invalid';
  else if (!attributionTimingValid) note = 'attribution_timing invalid';
  else if (!observedChannelsPresent) note = 'observed_channels required';
  else if (!preFetchIntentBound) note = 'pre_fetch attribution requires intent_receipt_digest';

  return {
    schema: EGRESS_PROXY_ATTRIBUTION_SCHEMA,
    sku: EGRESS_PROXY_ATTRIBUTION_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      runIdPresent,
      attributionSourceValid,
      attributionTimingValid,
      observedChannelsPresent,
      digestMatches,
      preFetchIntentBound,
      profileComplete,
    },
    gtmLine:
      'Egress proxy or sandbox attributes network/runtime scope; Aevesa notary binds feed into aevesa.egress-attestation/v2 offline.',
    note,
  };
}
