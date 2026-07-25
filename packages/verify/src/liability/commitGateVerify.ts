import type { ProveBundleVerifyOptions, ProveBundleVerifyResult } from './proveBundleVerify.js';
import { verifyProveBundle } from './proveBundleVerify.js';
import {
  isDeniedReceiptProfile,
  validateDeniedReceiptProfile,
  validateScittRefusalAlignment,
} from './deniedReceiptProfile.js';
import { verifyReceipt } from './verifyReceipt.js';

export const COMMIT_GATE_ATTESTATION_SCHEMA = 'aevesa.commit-gate-attestation/v1' as const;
export const COMMIT_GATE_VERIFY_SCHEMA = 'aevesa.commit-gate-verify/v1' as const;
export const COMMIT_GATE_SKU = 'aevesa-commit-gate-v1' as const;
export const PEP_INVARIANT_RECEIPT_BEFORE_ACTION = 'receipt_before_action/v1' as const;

export interface CommitGateAttestationDocument {
  schema?: string;
  pep_invariant?: string;
  mode?: 'permit' | 'deny_escalation';
  receipt?: unknown;
  ledger?: {
    eventType?: string;
    entryHash?: string;
  };
  escalation?: {
    required?: boolean;
    fired?: boolean;
    approver_id?: string | null;
  };
}

export interface CommitGateVerifyOptions extends ProveBundleVerifyOptions {
  /** When true (default), require pep_invariant receipt_before_action/v1 on attestation wrapper */
  requirePepInvariant?: boolean;
}

export interface CommitGateVerifyChecks {
  attestationSchemaValid: boolean;
  pepInvariantPresent: boolean;
  receiptValid: boolean;
  mode: 'permit' | 'deny_escalation' | 'unknown';
  proveBundle: ProveBundleVerifyResult['checks'] | null;
  deniedProfileValid: boolean;
  scittRefusalAligned: boolean;
  escalationDocumented: boolean;
  preExecutionRefusal: boolean;
  profileComplete: boolean;
}

export interface CommitGateVerifyResult {
  schema: typeof COMMIT_GATE_VERIFY_SCHEMA;
  sku: typeof COMMIT_GATE_SKU;
  ok: boolean;
  checks: CommitGateVerifyChecks;
  proveBundle: ProveBundleVerifyResult | null;
  gtmLine: string;
  note: string | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function inferMode(doc: CommitGateAttestationDocument, receipt: Record<string, unknown> | null): CommitGateVerifyChecks['mode'] {
  if (doc.mode === 'permit' || doc.mode === 'deny_escalation') return doc.mode;
  if (receipt && isDeniedReceiptProfile(receipt)) return 'deny_escalation';
  return 'permit';
}

/**
 * Commit-gate / escalation-failure evidence profile — receipt-before-action permit path
 * or pre-execution DENIED refusal with SCITT alignment (carrier escalation-failure evidence).
 */
export function verifyCommitGateBundle(
  input: unknown,
  options: CommitGateVerifyOptions = {},
): CommitGateVerifyResult {
  const doc = asRecord(input) as CommitGateAttestationDocument | null;
  const requirePep = options.requirePepInvariant !== false;

  const attestationSchemaValid = doc?.schema === COMMIT_GATE_ATTESTATION_SCHEMA;
  const modeDeclared = doc?.mode === 'permit' || doc?.mode === 'deny_escalation';
  const pepInvariantPresent =
    !requirePep || doc?.pep_invariant === PEP_INVARIANT_RECEIPT_BEFORE_ACTION;

  const receipt = asRecord(doc?.receipt);
  const receiptVerify = receipt ? verifyReceipt(receipt, options) : { isValid: false };
  const receiptValid = receiptVerify.isValid === true;

  const mode = inferMode(doc || {}, receipt);
  let proveBundle: ProveBundleVerifyResult | null = null;
  let deniedProfileValid = false;
  let scittRefusalAligned = false;
  let escalationDocumented = false;
  let preExecutionRefusal = false;

  if (mode === 'permit' && receipt) {
    proveBundle = verifyProveBundle(receipt, options);
    deniedProfileValid = true;
    scittRefusalAligned = true;
    escalationDocumented = true;
    preExecutionRefusal = true;
  } else if (mode === 'deny_escalation' && receipt) {
    const denied = validateDeniedReceiptProfile(receipt);
    deniedProfileValid = denied.ok === true;
    const scitt = validateScittRefusalAlignment(receipt);
    scittRefusalAligned = scitt.ok === true || scitt.skipped === true;
    const denial = asRecord(receipt.denial);
    const sideEffects = asRecord(receipt.side_effects);
    preExecutionRefusal =
      denial?.pre_execution === true && denial?.execution_occurred === false;
    const escalation = asRecord(doc?.escalation);
    escalationDocumented =
      escalation?.required === true
        ? escalation?.fired === true
        : denial?.denial_stage != null || Boolean(sideEffects?.blocked_reason);
    proveBundle = verifyProveBundle(receipt, { ...options, requireWitnessCosign: false });
  }

  const permitOk =
    mode === 'permit' &&
    proveBundle?.ok === true &&
    proveBundle.checks.receiptValid === true;

  const denyOk =
    mode === 'deny_escalation' &&
    deniedProfileValid &&
    preExecutionRefusal &&
    escalationDocumented;

  const profileComplete =
    attestationSchemaValid &&
    modeDeclared &&
    pepInvariantPresent &&
    receiptValid &&
    (permitOk || denyOk);

  const ok = profileComplete;

  let note: string | null = null;
  if (ok && mode === 'permit') {
    note = 'Commit-gate permit verified — receipt committed before tool execution (receipt_before_action/v1)';
  } else if (ok && mode === 'deny_escalation') {
    note = 'Commit-gate escalation refusal verified — pre-execution DENIED with documented escalation path';
  } else if (!attestationSchemaValid) {
    note = `Commit-gate requires attestation schema ${COMMIT_GATE_ATTESTATION_SCHEMA}`;
  } else if (!modeDeclared) {
    note = 'Commit-gate attestation requires mode permit or deny_escalation';
  } else if (!pepInvariantPresent) {
    note = `Commit-gate requires pep_invariant ${PEP_INVARIANT_RECEIPT_BEFORE_ACTION}`;
  } else if (!receiptValid) {
    note = 'Commit-gate attestation receipt failed cryptographic verify';
  } else if (mode === 'deny_escalation' && !deniedProfileValid) {
    note = 'DENIED receipt profile invalid for escalation evidence';
  } else {
    note = 'Commit-gate profile verification failed';
  }

  return {
    schema: COMMIT_GATE_VERIFY_SCHEMA,
    sku: COMMIT_GATE_SKU,
    ok,
    checks: {
      attestationSchemaValid,
      pepInvariantPresent,
      receiptValid,
      mode,
      proveBundle: proveBundle?.checks ?? null,
      deniedProfileValid,
      scittRefusalAligned,
      escalationDocumented,
      preExecutionRefusal,
      profileComplete,
    },
    proveBundle,
    gtmLine:
      'Carriers price escalation failure. Aevesa proves the commit gate fired — permit before action or pre-execution DENIED with SCITT-aligned refusal evidence.',
    note,
  };
}
