import { sha256HexUtf8 } from '../core/sha256.js';
import { stableStringify } from '../core/stableStringify.js';
import {
  EGRESS_ATTESTATION_MODES,
  EGRESS_ATTESTATION_SCHEMA,
  EGRESS_ATTESTATION_SKU,
  buildEgressAttestationPreimage,
  type EgressAttestationDocument,
  type EgressAttestationMode,
} from '../core/egressAttestation.js';
import {
  EGRESS_ATTESTATION_V2_SCHEMA,
  EGRESS_ATTESTATION_V2_SKU,
  buildEgressAttestationV2Preimage,
  includesAttributionTiming,
  type EgressAttestationV2Document,
} from '../core/egressAttestationV2.js';

export interface EgressAttestationVerifyResult {
  schema: typeof EGRESS_ATTESTATION_SCHEMA | typeof EGRESS_ATTESTATION_V2_SCHEMA;
  sku: typeof EGRESS_ATTESTATION_SKU | typeof EGRESS_ATTESTATION_V2_SKU;
  ok: boolean;
  checks: {
    schemaValid: boolean;
    sessionIdPresent: boolean;
    attestationModeValid: boolean;
    limitationsPresent: boolean;
    digestMatches: boolean;
    mcpSplitHonest: boolean;
    profileComplete: boolean;
    runIdPresent?: boolean;
    attributionTimingValid?: boolean;
    preFetchIntentBound?: boolean;
    attributionProfileComplete?: boolean;
  };
  gtmLine: string;
  note: string | null;
}

const GTM_LINE_V1 =
  'MCP PEP proves tool-path enforcement. Aevesa egress attestation proves observe/intercept boundary separately — offline.';
const GTM_LINE_V2 =
  'Egress attestation v2 binds run_id and attribution_timing (network vs runtime) separately from MCP PEP — offline.';

function includesMode(value: unknown): value is EgressAttestationMode {
  return typeof value === 'string' && (EGRESS_ATTESTATION_MODES as readonly string[]).includes(value);
}

function mcpSplitHonest(mode: unknown, mcpPepBound: unknown): boolean {
  if (mode === 'egress_proxy_split' || mode === 'observe_only') {
    return mcpPepBound === false;
  }
  return true;
}

function limitationsPresent(limitations: unknown): boolean {
  return (
    Array.isArray(limitations) &&
    limitations.length > 0 &&
    limitations.every((item) => typeof item === 'string' && item.trim().length > 0)
  );
}

function verifyEgressAttestationV1(doc: EgressAttestationDocument | null): EgressAttestationVerifyResult {
  const schemaValid = doc?.schema === EGRESS_ATTESTATION_SCHEMA;
  const sessionIdPresent = Boolean(String(doc?.session_id || '').trim());
  const attestationModeValid = includesMode(doc?.attestation_mode);
  const limitsOk = limitationsPresent(doc?.limitations);

  let digestMatches = false;
  if (schemaValid && attestationModeValid && sessionIdPresent && doc?.generated_at) {
    const expected = sha256HexUtf8(
      stableStringify(
        buildEgressAttestationPreimage({
          session_id: doc.session_id,
          attestation_mode: doc.attestation_mode,
          mcp_pep_bound: doc.mcp_pep_bound === true,
          proof_strength_disclosure_digest: doc.proof_strength_disclosure_digest ?? null,
          observed_channels: doc.observed_channels ?? [],
          limitations: doc.limitations ?? [],
          generated_at: doc.generated_at,
        }),
      ),
    );
    digestMatches = String(doc.attestation_digest || '').toLowerCase() === expected;
  }

  const splitHonest = mcpSplitHonest(doc?.attestation_mode, doc?.mcp_pep_bound);
  const profileComplete =
    schemaValid && sessionIdPresent && attestationModeValid && limitsOk && digestMatches && splitHonest;

  let note: string | null = null;
  if (!schemaValid) note = `schema must be ${EGRESS_ATTESTATION_SCHEMA}`;
  else if (!digestMatches) note = 'attestation_digest does not match canonical preimage';
  else if (!splitHonest) note = 'observe_only and egress_proxy_split require mcp_pep_bound false';
  else if (!limitsOk) note = 'limitations array required';

  return {
    schema: EGRESS_ATTESTATION_SCHEMA,
    sku: EGRESS_ATTESTATION_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      sessionIdPresent,
      attestationModeValid,
      limitationsPresent: limitsOk,
      digestMatches,
      mcpSplitHonest: splitHonest,
      profileComplete,
    },
    gtmLine: GTM_LINE_V1,
    note,
  };
}

function verifyEgressAttestationV2(doc: EgressAttestationV2Document | null): EgressAttestationVerifyResult {
  const schemaValid = doc?.schema === EGRESS_ATTESTATION_V2_SCHEMA;
  const sessionIdPresent = Boolean(String(doc?.session_id || '').trim());
  const attestationModeValid = includesMode(doc?.attestation_mode);
  const limitsOk = limitationsPresent(doc?.limitations);
  const runIdPresent = Boolean(String(doc?.run_id || '').trim());
  const attributionTimingValid = includesAttributionTiming(doc?.attribution_timing);

  let digestMatches = false;
  if (
    schemaValid &&
    attestationModeValid &&
    sessionIdPresent &&
    runIdPresent &&
    attributionTimingValid &&
    doc?.generated_at
  ) {
    const expected = sha256HexUtf8(
      stableStringify(
        buildEgressAttestationV2Preimage({
          session_id: doc.session_id,
          attestation_mode: doc.attestation_mode,
          mcp_pep_bound: doc.mcp_pep_bound === true,
          proof_strength_disclosure_digest: doc.proof_strength_disclosure_digest ?? null,
          observed_channels: doc.observed_channels ?? [],
          limitations: doc.limitations ?? [],
          generated_at: doc.generated_at,
          run_id: doc.run_id,
          intent_receipt_digest: doc.intent_receipt_digest ?? null,
          registry_manifest_digest: doc.registry_manifest_digest ?? null,
          attribution_timing: doc.attribution_timing,
        }),
      ),
    );
    digestMatches = String(doc.attestation_digest || '').toLowerCase() === expected;
  }

  const splitHonest = mcpSplitHonest(doc?.attestation_mode, doc?.mcp_pep_bound);
  const intentDigest = String(doc?.intent_receipt_digest || '').trim().toLowerCase();
  const preFetchIntentBound =
    doc?.attribution_timing !== 'pre_fetch' || /^[a-f0-9]{64}$/.test(intentDigest);

  const attributionProfileComplete =
    runIdPresent && attributionTimingValid && preFetchIntentBound;

  const profileComplete =
    schemaValid &&
    sessionIdPresent &&
    attestationModeValid &&
    limitsOk &&
    digestMatches &&
    splitHonest &&
    attributionProfileComplete;

  let note: string | null = null;
  if (!schemaValid) note = `schema must be ${EGRESS_ATTESTATION_V2_SCHEMA}`;
  else if (!digestMatches) note = 'attestation_digest does not match canonical preimage';
  else if (!splitHonest) note = 'observe_only and egress_proxy_split require mcp_pep_bound false';
  else if (!limitsOk) note = 'limitations array required';
  else if (!runIdPresent) note = 'run_id required for v2 attribution';
  else if (!attributionTimingValid) note = 'attribution_timing invalid';
  else if (!preFetchIntentBound) note = 'pre_fetch attribution requires intent_receipt_digest';

  return {
    schema: EGRESS_ATTESTATION_V2_SCHEMA,
    sku: EGRESS_ATTESTATION_V2_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      sessionIdPresent,
      attestationModeValid,
      limitationsPresent: limitsOk,
      digestMatches,
      mcpSplitHonest: splitHonest,
      profileComplete,
      runIdPresent,
      attributionTimingValid,
      preFetchIntentBound,
      attributionProfileComplete,
    },
    gtmLine: GTM_LINE_V2,
    note,
  };
}

export function verifyEgressAttestationBundle(input: unknown): EgressAttestationVerifyResult {
  const doc =
    input != null && typeof input === 'object' && !Array.isArray(input)
      ? (input as Record<string, unknown>)
      : null;

  if (doc?.schema === EGRESS_ATTESTATION_V2_SCHEMA) {
    return verifyEgressAttestationV2(doc as unknown as EgressAttestationV2Document);
  }

  return verifyEgressAttestationV1(doc as unknown as EgressAttestationDocument | null);
}
