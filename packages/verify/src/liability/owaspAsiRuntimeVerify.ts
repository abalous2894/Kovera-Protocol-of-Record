import { verifyCommitGateBundle, PEP_INVARIANT_RECEIPT_BEFORE_ACTION } from './commitGateVerify.js';
import type { ProveBundleVerifyOptions } from './proveBundleVerify.js';
import { verifyReceipt } from './verifyReceipt.js';
import { isDeniedReceiptProfile } from './deniedReceiptProfile.js';

export const OWASP_ASI_RUNTIME_SCHEMA = 'aevesa.owasp-asi-runtime/v1' as const;
export const OWASP_ASI_RUNTIME_SKU = 'aevesa-owasp-asi-runtime-v1' as const;

export interface OwaspAsiRuntimeAttestationDocument {
  schema?: string;
  pep_invariant?: string;
  verifier_separation?: {
    independent_pep?: boolean;
    shared_orchestrator?: boolean;
  };
  execution_context?: {
    agent_id?: string;
    agent_version_hash?: string;
    tool_name?: string;
    tool_hash?: string;
    evaluated_at?: string;
  };
  receipt?: unknown;
  ledger?: {
    eventType?: string;
    entryHash?: string;
  };
  owasp_asi_controls?: string[];
}

export interface OwaspAsiRuntimeVerifyOptions extends ProveBundleVerifyOptions {
  requireVerifierSeparation?: boolean;
}

export interface OwaspAsiRuntimeVerifyChecks {
  schemaValid: boolean;
  pepInvariantPresent: boolean;
  verifierSeparationClaimed: boolean;
  receiptValid: boolean;
  permitOrDenyReceipt: boolean;
  agentIdentityBound: boolean;
  toolHashBound: boolean;
  commitGateAligned: boolean;
  owaspControlsPresent: boolean;
  profileComplete: boolean;
}

export interface OwaspAsiRuntimeVerifyResult {
  schema: typeof OWASP_ASI_RUNTIME_SCHEMA;
  sku: typeof OWASP_ASI_RUNTIME_SKU;
  ok: boolean;
  checks: OwaspAsiRuntimeVerifyChecks;
  gtmLine: string;
  note: string | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

const HASH_RE = /^[a-f0-9]{64}$/;

function resolveReceiptToolHash(receipt: Record<string, unknown> | null): string | null {
  if (!receipt) return null;
  const sideEffects = asRecord(receipt.side_effects);
  const action = sideEffects ? asRecord(sideEffects.action) : null;
  const supplyChain = asRecord(receipt.supply_chain);
  const gateway = asRecord(receipt.gateway_attestation);
  const candidates = [action?.tool_hash, supplyChain?.tool_hash, gateway?.tool_hash];
  for (const candidate of candidates) {
    const normalized = String(candidate || '').trim().toLowerCase();
    if (HASH_RE.test(normalized)) return normalized;
  }
  return null;
}

/**
 * OWASP ASI runtime integrity profile — independent PEP, unconditional permit/deny receipts,
 * agent identity + tool hash at execution time (ASI-02/03/05/10).
 */
export function verifyOwaspAsiRuntimeBundle(
  input: unknown,
  options: OwaspAsiRuntimeVerifyOptions = {},
): OwaspAsiRuntimeVerifyResult {
  const doc = asRecord(input) as OwaspAsiRuntimeAttestationDocument | null;
  const schemaValid = doc?.schema === OWASP_ASI_RUNTIME_SCHEMA;

  const pepInvariantPresent = doc?.pep_invariant === PEP_INVARIANT_RECEIPT_BEFORE_ACTION;

  const separation = asRecord(doc?.verifier_separation);
  const requireSeparation = options.requireVerifierSeparation !== false;
  const verifierSeparationClaimed =
    !requireSeparation ||
    (separation?.independent_pep === true && separation?.shared_orchestrator !== true);

  const receipt = asRecord(doc?.receipt);
  const receiptValid = receipt ? verifyReceipt(receipt, options).isValid === true : false;

  const isDenied = receipt ? isDeniedReceiptProfile(receipt) : false;
  const isPermit =
    receipt &&
    !isDenied &&
    (receipt.policy as { decision?: string })?.decision === 'permit';
  const permitOrDenyReceipt = Boolean(isDenied || isPermit);

  const execCtx = asRecord(doc?.execution_context);
  const identity = receipt ? asRecord(receipt.identity) : null;
  const primaryActor = identity ? asRecord(identity.primary_actor) : null;
  const sideEffects = receipt ? asRecord(receipt.side_effects) : null;
  const action = sideEffects ? asRecord(sideEffects.action) : null;

  const agentIdBound =
    !execCtx?.agent_id ||
    !primaryActor?.agent_id ||
    String(execCtx.agent_id) === String(primaryActor.agent_id);

  const execToolHash = String(execCtx?.tool_hash || '').trim().toLowerCase();
  const execToolName = String(execCtx?.tool_name || '').trim();
  const receiptToolHash = resolveReceiptToolHash(receipt);
  const actionToolName = action ? String(action.tool_name || '').trim() : '';

  const toolHashBound =
    !execCtx?.tool_hash
      ? true
      : HASH_RE.test(execToolHash) &&
        execToolName.length > 0 &&
        actionToolName.length > 0 &&
        execToolName === actionToolName &&
        receiptToolHash != null &&
        execToolHash === receiptToolHash;

  const commitGateAttestation = {
    schema: 'aevesa.commit-gate-attestation/v1',
    pep_invariant: PEP_INVARIANT_RECEIPT_BEFORE_ACTION,
    mode: isDenied ? 'deny_escalation' : 'permit',
    receipt: doc?.receipt,
    ledger: doc?.ledger,
  };
  const commitGate = verifyCommitGateBundle(commitGateAttestation, options);
  const commitGateAligned = commitGate.ok === true;

  const owaspControls = Array.isArray(doc?.owasp_asi_controls)
    ? doc.owasp_asi_controls.filter((c): c is string => typeof c === 'string')
    : [];
  const owaspControlsPresent =
    owaspControls.length >= 1 &&
    owaspControls.some((c) => ['ASI02', 'ASI03', 'ASI05', 'ASI10'].includes(c));

  const versionHashOk =
    !execCtx?.agent_version_hash || HASH_RE.test(String(execCtx.agent_version_hash));

  const profileComplete =
    schemaValid &&
    pepInvariantPresent &&
    verifierSeparationClaimed &&
    receiptValid &&
    permitOrDenyReceipt &&
    agentIdBound &&
    toolHashBound &&
    versionHashOk &&
    commitGateAligned &&
    owaspControlsPresent;

  const ok = profileComplete;

  let note: string | null = commitGate.note;
  if (ok) {
    note = 'OWASP ASI runtime integrity verified — independent PEP with agent/tool-bound execution receipt';
  } else if (!toolHashBound) {
    note = 'OWASP ASI runtime requires execution_context.tool_hash bound to receipt-side tool_hash';
  } else if (!verifierSeparationClaimed) {
    note = 'Runtime integrity requires verifier separation from agent orchestrator';
  } else if (!owaspControlsPresent) {
    note = 'OWASP ASI runtime attestation requires ASI02/03/05/10 control mapping';
  } else if (!commitGateAligned) {
    note = note || 'Commit-gate alignment failed for runtime integrity attestation';
  } else {
    note = note || 'OWASP ASI runtime integrity verification failed';
  }

  return {
    schema: OWASP_ASI_RUNTIME_SCHEMA,
    sku: OWASP_ASI_RUNTIME_SKU,
    ok,
    checks: {
      schemaValid,
      pepInvariantPresent,
      verifierSeparationClaimed,
      receiptValid,
      permitOrDenyReceipt,
      agentIdentityBound: agentIdBound,
      toolHashBound,
      commitGateAligned,
      owaspControlsPresent,
      profileComplete,
    },
    gtmLine:
      'SOC 2 checks install logs. OWASP ASI runtime integrity proves independent PEP enforcement with agent-version-at-call-time receipts.',
    note,
  };
}
