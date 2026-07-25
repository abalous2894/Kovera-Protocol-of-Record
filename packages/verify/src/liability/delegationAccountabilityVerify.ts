import { verifyDelegationChain, DELEGATION_CHAIN_SCHEMA } from '../core/delegationChainVerify.js';

export const DELEGATION_ACCOUNTABILITY_SCHEMA = 'aevesa.delegation-accountability/v1' as const;
export const DELEGATION_ACCOUNTABILITY_SKU = 'aevesa-delegation-accountability-v1' as const;

export interface HopLimitEnforcement {
  max_task_hops?: number;
  observed_hops?: number;
  within_limit?: boolean;
  ledger_event_type?: string;
  entry_hash?: string;
}

export interface CascadeRevokeWitness {
  revoked_jti?: string;
  cascade_depth?: number;
  downstream_revoked_count?: number;
  witness_entry_hash?: string;
  witnessed_at?: string;
}

export interface DelegationAccountabilityDocument {
  schema?: string;
  delegation_chain?: unknown;
  hop_limit_enforcement?: HopLimitEnforcement;
  cascade_revoke_witness?: CascadeRevokeWitness;
  owasp_asi_controls?: string[];
}

export interface DelegationAccountabilityVerifyOptions {
  signingSecret?: string;
  requireHopLimitEvidence?: boolean;
  requireCascadeRevokeWitness?: boolean;
}

export interface DelegationAccountabilityVerifyChecks {
  schemaValid: boolean;
  delegationChainVerified: boolean;
  scopeNarrowingProven: boolean;
  originSubPresent: boolean;
  hopLimitWithinPolicy: boolean;
  hopLimitEvidencePresent: boolean;
  cascadeRevokeWitnessed: boolean;
  owaspAsiMapped: boolean;
  profileComplete: boolean;
}

export interface DelegationAccountabilityVerifyResult {
  schema: typeof DELEGATION_ACCOUNTABILITY_SCHEMA;
  sku: typeof DELEGATION_ACCOUNTABILITY_SKU;
  ok: boolean;
  checks: DelegationAccountabilityVerifyChecks;
  delegationVerify: ReturnType<typeof verifyDelegationChain>;
  gtmLine: string;
  note: string | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

const ENTRY_HASH_RE = /^[a-f0-9]{64}$/;

/**
 * Delegation accountability profile — OWASP ASI-03/07/08: monotonic scope narrowing,
 * hop-limit enforcement evidence, and cascade revocation witness.
 */
export function verifyDelegationAccountabilityBundle(
  input: unknown,
  options: DelegationAccountabilityVerifyOptions = {},
): DelegationAccountabilityVerifyResult {
  const doc = asRecord(input) as DelegationAccountabilityDocument | null;
  const schemaValid = doc?.schema === DELEGATION_ACCOUNTABILITY_SCHEMA;

  const chain = doc?.delegation_chain;
  const chainRecord = asRecord(chain);
  const delegationVerify = verifyDelegationChain(chain, {
    signingSecret: options.signingSecret,
  });

  const delegationChainVerified = delegationVerify.ok === true;
  const scopeNarrowingProven =
    delegationChainVerified ||
    (delegationVerify.code !== 'SCOPE_NOT_NARROWED' &&
      delegationVerify.code !== 'TOOLS_NOT_NARROWED');
  const originSubPresent = Boolean(chainRecord?.origin && asRecord(chainRecord.origin)?.origin_sub);

  const hopLimit = asRecord(doc?.hop_limit_enforcement) as HopLimitEnforcement | null;
  const requireHop = options.requireHopLimitEvidence === true;
  const hopLimitEvidencePresent = !requireHop || hopLimit != null;
  const hopLimitWithinPolicy =
    !hopLimit ||
    (hopLimit.within_limit === true &&
      (hopLimit.observed_hops == null ||
        hopLimit.max_task_hops == null ||
        hopLimit.observed_hops <= hopLimit.max_task_hops));

  const cascade = asRecord(doc?.cascade_revoke_witness) as CascadeRevokeWitness | null;
  const requireCascade = options.requireCascadeRevokeWitness === true;
  const cascadeRevokeWitnessed =
    !requireCascade ||
    (Boolean(cascade?.revoked_jti) &&
      (cascade?.downstream_revoked_count ?? 0) >= 0 &&
      (!cascade?.witness_entry_hash || ENTRY_HASH_RE.test(String(cascade.witness_entry_hash))));

  const owaspControls = Array.isArray(doc?.owasp_asi_controls)
    ? doc.owasp_asi_controls.filter((c): c is string => typeof c === 'string')
    : [];
  const owaspAsiMapped =
    owaspControls.length === 0 ||
    owaspControls.some((c) => ['ASI03', 'ASI07', 'ASI08'].includes(c));

  const profileComplete =
    schemaValid &&
    delegationChainVerified &&
    originSubPresent &&
    hopLimitEvidencePresent &&
    hopLimitWithinPolicy &&
    cascadeRevokeWitnessed &&
    owaspAsiMapped;

  const ok = profileComplete;

  let note: string | null = delegationVerify.ok ? null : delegationVerify.code;
  if (ok) {
    note =
      'Delegation accountability verified — scope-narrowed chain with hop-limit and cascade revoke evidence';
  } else if (!delegationChainVerified) {
    note = `Delegation chain verify failed: ${delegationVerify.code}`;
  } else if (!hopLimitWithinPolicy) {
    note = 'Hop limit enforcement evidence shows policy exceeded';
  } else if (!cascadeRevokeWitnessed) {
    note = 'Cascade revocation witness required but missing or invalid';
  } else {
    note = 'Delegation accountability profile verification failed';
  }

  return {
    schema: DELEGATION_ACCOUNTABILITY_SCHEMA,
    sku: DELEGATION_ACCOUNTABILITY_SKU,
    ok,
    checks: {
      schemaValid,
      delegationChainVerified,
      scopeNarrowingProven,
      originSubPresent,
      hopLimitWithinPolicy,
      hopLimitEvidencePresent,
      cascadeRevokeWitnessed,
      owaspAsiMapped,
      profileComplete,
    },
    delegationVerify,
    gtmLine:
      'OWASP ASI-03/07/08 converge on delegation accountability. Aevesa proves monotonic narrowing, hop limits, and cascade revoke — offline.',
    note,
  };
}

export { DELEGATION_CHAIN_SCHEMA };
