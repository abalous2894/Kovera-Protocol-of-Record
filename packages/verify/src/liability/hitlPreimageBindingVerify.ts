import {
  HITL_PREIMAGE_BINDING_SCHEMA,
  HITL_BINDING_RESULTS,
  computeHitlBindingDigestFromFields,
  type HitlBindingResult,
} from '../core/hitlPreimageBinding.js';

export const HITL_PREIMAGE_BINDING_SKU = 'aevesa-hitl-preimage-binding-v1' as const;

export interface HitlPreimageBindingDocument {
  schema?: string;
  session_id?: string;
  approval_request_id?: string;
  human_visible_digest?: string;
  gate_evaluation_digest?: string;
  binding_result?: string;
  binding_digest?: string;
}

export interface HitlPreimageBindingVerifyOptions {
  requireMatch?: boolean;
}

export interface HitlPreimageBindingVerifyChecks {
  schemaValid: boolean;
  sessionIdPresent: boolean;
  digestsPresent: boolean;
  bindingResultValid: boolean;
  bindingDigestMatches: boolean;
  bindingMatch: boolean;
  profileComplete: boolean;
}

export interface HitlPreimageBindingVerifyResult {
  schema: typeof HITL_PREIMAGE_BINDING_SCHEMA;
  sku: typeof HITL_PREIMAGE_BINDING_SKU;
  ok: boolean;
  checks: HitlPreimageBindingVerifyChecks;
  gtmLine: string;
  note: string | null;
}

const HEX64 = /^[a-f0-9]{64}$/;

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

/**
 * Verify HITL semantic binding — human-visible UI vs gate evaluation preimage.
 */
export function verifyHitlPreimageBindingBundle(
  input: unknown,
  options: HitlPreimageBindingVerifyOptions = {},
): HitlPreimageBindingVerifyResult {
  const doc = asRecord(input) as HitlPreimageBindingDocument | null;
  const schemaValid = doc?.schema === HITL_PREIMAGE_BINDING_SCHEMA;
  const session_id = String(doc?.session_id || '').trim();
  const sessionIdPresent = session_id.length > 0;

  const human_visible_digest = String(doc?.human_visible_digest || '').trim().toLowerCase();
  const gate_evaluation_digest = String(doc?.gate_evaluation_digest || '').trim().toLowerCase();
  const digestsPresent =
    HEX64.test(human_visible_digest) && HEX64.test(gate_evaluation_digest);

  const binding_result = String(doc?.binding_result || '').trim() as HitlBindingResult;
  const bindingResultValid = HITL_BINDING_RESULTS.includes(binding_result);

  let bindingDigestMatches = false;
  let bindingMatch = false;
  if (sessionIdPresent && digestsPresent && bindingResultValid) {
    const expectedResult: HitlBindingResult =
      human_visible_digest === gate_evaluation_digest ? 'MATCH' : 'DIVERGENCE';
    bindingMatch = expectedResult === 'MATCH';
    if (binding_result !== expectedResult) {
      bindingDigestMatches = false;
    } else {
      const expectedDigest = computeHitlBindingDigestFromFields({
        session_id,
        approval_request_id: doc?.approval_request_id,
        human_visible_digest,
        gate_evaluation_digest,
        binding_result,
      });
      bindingDigestMatches = Boolean(doc?.binding_digest) && doc!.binding_digest === expectedDigest;
    }
  }

  const requireMatch = options.requireMatch === true;
  const profileComplete =
    schemaValid &&
    sessionIdPresent &&
    digestsPresent &&
    bindingResultValid &&
    bindingDigestMatches &&
    (!requireMatch || bindingMatch);

  let note: string | null = null;
  if (profileComplete) {
    note =
      bindingMatch
        ? 'HITL preimage binding verified — human-visible summary matches gate evaluation'
        : 'HITL preimage binding verified — DIVERGENCE attested for trust-theater incident';
  } else if (!bindingDigestMatches) {
    note = 'binding_digest does not match canonical preimage';
  } else if (requireMatch && !bindingMatch) {
    note = 'HITL binding requires binding_result MATCH';
  } else {
    note = 'HITL preimage binding verification failed';
  }

  return {
    schema: HITL_PREIMAGE_BINDING_SCHEMA,
    sku: HITL_PREIMAGE_BINDING_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      sessionIdPresent,
      digestsPresent,
      bindingResultValid,
      bindingDigestMatches,
      bindingMatch,
      profileComplete,
    },
    gtmLine:
      'HITL vendors log approved. Aevesa proves the human signed the exact execution preimage — offline.',
    note,
  };
}
