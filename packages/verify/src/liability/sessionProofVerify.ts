import { createHash } from 'node:crypto';
import { stableStringify } from '../core/stableStringify.js';
import { isRecord } from '../core/isRecord.js';
import { verifyPartialPathCommitment, PARTIAL_PATH_SCHEMA } from '../core/partialPath.js';
import { verifyReceipt } from './verifyReceipt.js';
import { verifyReceiptDigestMatch } from './digest.js';
import {
  verifySetCompletenessBundle,
  SET_COMPLETENESS_SCHEMA,
  type SetCompletenessVerifyResult,
} from './setCompletenessVerify.js';
import {
  verifyEvidenceCustodianBundle,
  type EvidenceCustodianVerifyResult,
} from './evidenceCustodianVerify.js';
import { verifyPolicyProofBundle } from '../policy/policyProofVerify.js';
import {
  verifyCapabilityBudgetCommitment,
  verifyBudgetMonotonicityFromPartialSteps,
} from '../policy/capabilityBudget.js';
import {
  verifyPermitExecutionCommitment,
  verifyPartialStepsPermitExecution,
  verifyMemberReceiptsArgsAlignment,
  verifyManifestCustodianCommitment,
  MANIFEST_CUSTODIAN_SCHEMA,
} from '../policy/permitExecutionBinding.js';
import { verifyConstraintClosureBundle } from './constraintClosureVerify.js';

export const SESSION_PROOF_SCHEMA = 'aevesa.compositional-accountability/v1' as const;
export const SESSION_PROOF_SKU = 'aevesa-cap-session-proof-v1' as const;
export const SESSION_PROOF_VERIFY_SCHEMA = 'aevesa.session-proof-verify/v1' as const;

export interface SessionProofBundle {
  schema: typeof SESSION_PROOF_SCHEMA;
  session_id: string;
  manifest: unknown;
  terminal_receipt: unknown;
  member_receipts?: unknown[] | null;
  policy_proof?: unknown | null;
  witness_export?: unknown | null;
  manifest_custodian?: unknown | null;
  constraint_closure?: unknown | null;
  bundle_digest?: string | null;
}

export interface SessionProofVerifyChecks {
  bundleSchemaValid: boolean;
  sessionIdAligned: boolean;
  setCompleteness: boolean;
  terminalReceiptValid: boolean;
  partialPathMembersAligned: boolean;
  capabilityBudgetValid: boolean;
  capabilityMonotonic: boolean;
  permitExecutionValid: boolean;
  memberArgsAligned: boolean;
  manifestCustodianValid: boolean;
  memberReceiptsVerified: boolean;
  policyProofValid: boolean;
  custodianProfileValid: boolean;
  constraintClosureValid: boolean;
  sessionProofComplete: boolean;
}

export interface SessionProofVerifyOptions {
  /** When true (default), verify terminal liability-receipt structure + digest */
  requireTerminalReceipt?: boolean;
  /** When true, require and verify each member_receipt against manifest digests */
  requireMemberReceipts?: boolean;
  /** When true, require policy_proof bundle and verify offline DENY/PERMIT proof */
  requirePolicyProof?: boolean;
  /** When true, verify evidence custodian profile on terminal receipt */
  requireCustodian?: boolean;
  /** When true, require constraint_closure PASS (CAP Phase 4) */
  requireConstraintClosure?: boolean;
  /** Passed through to verifySetCompletenessBundle */
  requirePartialPathAlignment?: boolean;
  /** SPKI PEM for RS256/Ed25519 on terminal + member liability receipts */
  issuerPublicKey?: string | Buffer;
  /** When true and issuerPublicKey absent, verify digests/structure without JWS */
  skipIntegritySignatureWithoutKey?: boolean;
}

export interface SessionProofVerifyResult {
  schema: typeof SESSION_PROOF_VERIFY_SCHEMA;
  sku: typeof SESSION_PROOF_SKU;
  ok: boolean;
  session_proof_complete: boolean;
  checks: SessionProofVerifyChecks;
  set_completeness: SetCompletenessVerifyResult | null;
  custodian: EvidenceCustodianVerifyResult | null;
  gtmLine: string;
  note: string | null;
  errors: string[];
}

const HEX64 = /^[a-f0-9]{64}$/;

function normalizeHex64(v: unknown): string | null {
  const s = String(v ?? '').trim().toLowerCase();
  return HEX64.test(s) ? s : null;
}

function parseBundle(data: unknown): SessionProofBundle | null {
  if (!isRecord(data)) return null;
  if (data.schema !== SESSION_PROOF_SCHEMA) return null;
  const session_id = String(data.session_id || '').trim();
  if (!session_id) return null;
  if (!isRecord(data.manifest) || data.manifest.schema !== SET_COMPLETENESS_SCHEMA) return null;
  if (!isRecord(data.terminal_receipt)) return null;
  return {
    schema: SESSION_PROOF_SCHEMA,
    session_id,
    manifest: data.manifest,
    terminal_receipt: data.terminal_receipt,
    member_receipts: Array.isArray(data.member_receipts) ? data.member_receipts : undefined,
    policy_proof: data.policy_proof ?? undefined,
    witness_export: data.witness_export ?? undefined,
    manifest_custodian: data.manifest_custodian ?? undefined,
    bundle_digest: normalizeHex64(data.bundle_digest) ?? undefined,
  };
}

/**
 * Canonical bundle digest — excludes bundle_digest field.
 */
export function computeSessionProofDigest(bundle: Record<string, unknown>): string {
  const clone = { ...bundle };
  delete clone.bundle_digest;
  delete clone.bundleDigest;
  return createHash('sha256').update(stableStringify(clone), 'utf8').digest('hex');
}

function readSessionIdFromReceipt(receipt: Record<string, unknown>): string | null {
  const session = receipt.session;
  if (!isRecord(session)) return null;
  const sid = String(session.session_id || session.correlation_id || '').trim();
  return sid || null;
}

function checkPartialPathMembersAligned(
  manifest: Record<string, unknown>,
  terminalReceipt: Record<string, unknown>,
): boolean {
  const partialPath = terminalReceipt.partial_path;
  if (!isRecord(partialPath) || partialPath.schema !== PARTIAL_PATH_SCHEMA) return false;
  const ppVerify = verifyPartialPathCommitment(partialPath);
  if (!ppVerify.ok) return false;

  const steps = partialPath.partial_steps;
  if (!Array.isArray(steps) || !Array.isArray(manifest.members)) return false;

  const members = /** @type {Record<string, unknown>[]} */ (manifest.members);
  const sorted = [...members].sort(
    (a, b) => Number(a.step_index) - Number(b.step_index),
  );

  if (steps.length !== sorted.length) return false;

  for (let i = 0; i < steps.length; i += 1) {
    const step = steps[i];
    if (!isRecord(step)) return false;
    const stepEntry = normalizeHex64(step.entry_hash);
    const memberEntry = normalizeHex64(sorted[i]?.entry_hash);
    if (stepEntry && memberEntry && stepEntry !== memberEntry) return false;
  }

  return true;
}

function verifyMemberReceipts(
  manifest: Record<string, unknown>,
  memberReceipts: unknown[],
  receiptOptions: { issuerPublicKey?: string | Buffer; skipIntegritySignatureWithoutKey?: boolean } = {},
): { ok: boolean; errors: string[] } {
  const errors: string[] = [];
  const members = Array.isArray(manifest.members) ? manifest.members : [];
  const declared = Number(manifest.declared_count);

  if (memberReceipts.length !== declared) {
    errors.push(`member_receipts length ${memberReceipts.length} !== declared_count ${declared}`);
    return { ok: false, errors };
  }

  const sortedMembers = [...members].sort(
    (a, b) => Number((a as { step_index: number }).step_index) - Number((b as { step_index: number }).step_index),
  );

  for (let i = 0; i < memberReceipts.length; i += 1) {
    const receipt = memberReceipts[i];
    const structural = verifyReceipt(receipt, receiptOptions);
    if (!structural.isValid) {
      errors.push(`member receipt step ${i}: ${structural.error || 'invalid'}`);
      continue;
    }
    const digestCheck = verifyReceiptDigestMatch(receipt as Record<string, unknown>);
    if (!digestCheck.ok) {
      errors.push(`member receipt step ${i}: digest mismatch`);
      continue;
    }
    const expected = normalizeHex64((sortedMembers[i] as { receipt_digest?: unknown })?.receipt_digest);
    const actual = normalizeHex64(
      (receipt as { integrity?: { receipt_digest?: unknown } })?.integrity?.receipt_digest,
    );
    if (expected && actual && expected !== actual) {
      errors.push(`member receipt step ${i}: digest ${actual} !== manifest ${expected}`);
    }
  }

  return { ok: errors.length === 0, errors };
}

/**
 * Compositional Accountability Protocol (CAP) — offline session proof verification.
 *
 * Orchestrates set-completeness, terminal receipt, partial_path member alignment,
 * optional member receipts, policy proof, and custodian profile checks.
 */
export function verifySessionProof(
  bundleData: unknown,
  options: SessionProofVerifyOptions = {},
): SessionProofVerifyResult {
  const requireTerminal = options.requireTerminalReceipt !== false;
  const requireMembers = options.requireMemberReceipts === true;
  const requirePolicy = options.requirePolicyProof === true;
  const requireCustodian = options.requireCustodian === true;
  const requireConstraintClosure = options.requireConstraintClosure === true;
  const receiptVerifyOptions = {
    issuerPublicKey: options.issuerPublicKey,
    skipIntegritySignatureWithoutKey: options.skipIntegritySignatureWithoutKey === true,
  };

  const errors: string[] = [];
  const bundle = parseBundle(bundleData);
  const bundleSchemaValid = bundle != null;

  if (!bundle) {
    return {
      schema: SESSION_PROOF_VERIFY_SCHEMA,
      sku: SESSION_PROOF_SKU,
      ok: false,
      session_proof_complete: false,
      checks: {
        bundleSchemaValid: false,
        sessionIdAligned: false,
        setCompleteness: false,
        terminalReceiptValid: false,
        partialPathMembersAligned: false,
        capabilityBudgetValid: false,
        capabilityMonotonic: false,
        permitExecutionValid: false,
        memberArgsAligned: false,
        manifestCustodianValid: false,
        memberReceiptsVerified: false,
        policyProofValid: false,
        custodianProfileValid: false,
        constraintClosureValid: false,
        sessionProofComplete: false,
      },
      set_completeness: null,
      custodian: null,
      gtmLine:
        'Receipt protocols prove actions. Aevesa session proofs prove workflows — compositional accountability offline.',
      note: `Invalid ${SESSION_PROOF_SCHEMA} bundle`,
      errors: [`schema must be ${SESSION_PROOF_SCHEMA} with manifest + terminal_receipt`],
    };
  }

  const manifest = bundle.manifest as Record<string, unknown>;
  const terminalReceipt = bundle.terminal_receipt as Record<string, unknown>;

  const manifestSession = String(manifest.session_id || '').trim();
  const receiptSession = readSessionIdFromReceipt(terminalReceipt);
  const sessionIdAligned =
    bundle.session_id === manifestSession &&
    (!receiptSession || bundle.session_id === receiptSession);

  if (!sessionIdAligned) {
    errors.push('session_id mismatch across bundle, manifest, and terminal_receipt');
  }

  const setCompleteness = verifySetCompletenessBundle(manifest, {
    terminalReceipt,
    requirePartialPathAlignment: options.requirePartialPathAlignment !== false,
  });
  const setCompletenessOk = setCompleteness.ok === true;

  let terminalReceiptValid = true;
  if (requireTerminal) {
    const receiptResult = verifyReceipt(terminalReceipt, receiptVerifyOptions);
    terminalReceiptValid = receiptResult.isValid === true;
    if (!terminalReceiptValid) {
      errors.push(receiptResult.error || 'terminal receipt verification failed');
    } else {
      const digestCheck = verifyReceiptDigestMatch(terminalReceipt);
      if (!digestCheck.ok) {
        terminalReceiptValid = false;
        errors.push('terminal receipt digest mismatch');
      }
    }
  }

  const partialPathMembersAligned = checkPartialPathMembersAligned(manifest, terminalReceipt);
  if (!partialPathMembersAligned) {
    errors.push('partial_path.partial_steps entry_hash alignment with manifest members failed');
  }

  let capabilityBudgetValid = true;
  let capabilityMonotonic = true;
  const partialPath = terminalReceipt.partial_path;
  if (isRecord(partialPath) && partialPath.capability_budget != null) {
    const capVerify = verifyCapabilityBudgetCommitment(partialPath.capability_budget);
    capabilityBudgetValid = capVerify.ok === true;
    if (!capabilityBudgetValid) {
      errors.push(`capability_budget: ${capVerify.code}`);
    }
  }
  if (isRecord(partialPath) && Array.isArray(partialPath.partial_steps)) {
    const mono = verifyBudgetMonotonicityFromPartialSteps(
      partialPath.partial_steps as Array<{ tool_name?: string; verdict?: string }>,
    );
    capabilityMonotonic = mono.ok === true;
    if (!capabilityMonotonic) {
      errors.push(mono.message || mono.code || 'capability budget monotonicity failed');
    }
  }

  let permitExecutionValid = true;
  let memberArgsAligned = true;
  if (isRecord(partialPath)) {
    if (partialPath.permit_execution != null) {
      const peVerify = verifyPermitExecutionCommitment(partialPath.permit_execution);
      permitExecutionValid = peVerify.ok === true;
      if (!permitExecutionValid) {
        errors.push(`permit_execution: ${peVerify.code}`);
      }
    }
    if (Array.isArray(partialPath.partial_steps)) {
      const peSteps = verifyPartialStepsPermitExecution(
        partialPath.partial_steps as Array<{
          tool_name?: string;
          args_digest?: string | null;
          binding_digest?: string | null;
        }>,
        partialPath.permit_execution ?? null,
      );
      if (!peSteps.ok) {
        permitExecutionValid = false;
        errors.push(peSteps.code || 'permit execution partial_steps failed');
      }
      if (Array.isArray(bundle.member_receipts) && bundle.member_receipts.length > 0) {
        const argsAlign = verifyMemberReceiptsArgsAlignment(
          partialPath.partial_steps as Array<{ tool_name?: string; args_digest?: string | null }>,
          bundle.member_receipts,
        );
        memberArgsAligned = argsAlign.ok === true;
        if (!memberArgsAligned && Array.isArray(argsAlign.errors)) {
          errors.push(...argsAlign.errors);
        }
      }
    }
  }

  let manifestCustodianValid = true;
  if (bundle.manifest_custodian != null) {
    const manifestRecord = bundle.manifest as Record<string, unknown>;
    const terminalRecord = terminalReceipt as Record<string, unknown>;
    const witnessHash =
      isRecord(terminalRecord.proof) &&
      isRecord((terminalRecord.proof as Record<string, unknown>).primary_anchor)
        ? String(
            ((terminalRecord.proof as Record<string, unknown>).primary_anchor as Record<string, unknown>)
              .entry_hash || '',
          ).toLowerCase() || null
        : null;
    const mc = verifyManifestCustodianCommitment(bundle.manifest_custodian, {
      set_root: String(manifestRecord.set_root || ''),
      session_id: String(manifestRecord.session_id || bundle.session_id),
      witness_entry_hash: witnessHash != null ? String(witnessHash) : null,
    });
    manifestCustodianValid = mc.ok === true;
    if (!manifestCustodianValid) {
      errors.push(`manifest_custodian: ${mc.code}`);
    }
    if (
      isRecord(bundle.manifest_custodian) &&
      bundle.manifest_custodian.schema !== MANIFEST_CUSTODIAN_SCHEMA
    ) {
      manifestCustodianValid = false;
      errors.push('manifest_custodian: invalid schema');
    }
  }

  let memberReceiptsVerified = !requireMembers;
  if (requireMembers) {
    const members = bundle.member_receipts || [];
    const memberCheck = verifyMemberReceipts(manifest, members, receiptVerifyOptions);
    memberReceiptsVerified = memberCheck.ok;
    errors.push(...memberCheck.errors);
  } else if (Array.isArray(bundle.member_receipts) && bundle.member_receipts.length > 0) {
    const memberCheck = verifyMemberReceipts(manifest, bundle.member_receipts, receiptVerifyOptions);
    memberReceiptsVerified = memberCheck.ok;
    if (!memberCheck.ok) errors.push(...memberCheck.errors);
  }

  let policyProofValid = !requirePolicy;
  if (requirePolicy || bundle.policy_proof != null) {
    if (!bundle.policy_proof) {
      policyProofValid = false;
      errors.push('policy_proof required but missing');
    } else {
      const pp = verifyPolicyProofBundle(bundle.policy_proof);
      policyProofValid = pp.ok === true;
      if (!pp.ok && Array.isArray(pp.errors) && pp.errors.length) errors.push(...pp.errors);
    }
  }

  let custodian: EvidenceCustodianVerifyResult | null = null;
  let custodianProfileValid = !requireCustodian;
  if (requireCustodian) {
    custodian = verifyEvidenceCustodianBundle(terminalReceipt);
    custodianProfileValid = custodian.ok === true;
    if (!custodianProfileValid) {
      errors.push(custodian.note || 'custodian profile verification failed');
    }
  }

  let constraintClosureValid = !requireConstraintClosure;
  if (requireConstraintClosure || bundle.constraint_closure != null) {
    if (!bundle.constraint_closure) {
      constraintClosureValid = false;
      errors.push('constraint_closure required but missing');
    } else {
      const cc = verifyConstraintClosureBundle(bundle.constraint_closure, {
        requirePass: requireConstraintClosure,
      });
      constraintClosureValid = cc.ok === true;
      if (!constraintClosureValid && cc.note) {
        errors.push(cc.note);
      }
      const ccSession = String(
        (bundle.constraint_closure as { session_id?: unknown })?.session_id || '',
      ).trim();
      if (ccSession && ccSession !== bundle.session_id) {
        constraintClosureValid = false;
        errors.push('constraint_closure.session_id mismatch with bundle.session_id');
      }
    }
  }

  const sessionProofComplete =
    bundleSchemaValid &&
    sessionIdAligned &&
    setCompletenessOk &&
    terminalReceiptValid &&
    partialPathMembersAligned &&
    capabilityBudgetValid &&
    capabilityMonotonic &&
    permitExecutionValid &&
    memberArgsAligned &&
    manifestCustodianValid &&
    memberReceiptsVerified &&
    policyProofValid &&
    custodianProfileValid &&
    constraintClosureValid;

  let note: string | null = null;
  if (sessionProofComplete) {
    const count = Number(manifest.declared_count);
    const hasMembers =
      Array.isArray(bundle.member_receipts) && bundle.member_receipts.length === count;
    note = hasMembers
      ? `Session proof complete — ${count} hops with full member receipt verification, partial_path alignment, and permit–execution binding.`
      : `Session proof complete — ${count} hops under set_root with terminal receipt and partial_path alignment. Intermediate member receipts require independent verification when not bundled.`;
  } else if (!setCompletenessOk) {
    note = setCompleteness.note;
  } else if (!partialPathMembersAligned) {
    note = 'partial_path partial_steps must align with manifest member entry_hash values';
  } else {
    note = errors[0] || 'Session proof verification failed';
  }

  return {
    schema: SESSION_PROOF_VERIFY_SCHEMA,
    sku: SESSION_PROOF_SKU,
    ok: sessionProofComplete,
    session_proof_complete: sessionProofComplete,
    checks: {
      bundleSchemaValid,
      sessionIdAligned,
      setCompleteness: setCompletenessOk,
      terminalReceiptValid,
      partialPathMembersAligned,
      capabilityBudgetValid,
      capabilityMonotonic,
      permitExecutionValid,
      memberArgsAligned,
      manifestCustodianValid,
      memberReceiptsVerified,
      policyProofValid,
      custodianProfileValid,
      constraintClosureValid,
      sessionProofComplete,
    },
    set_completeness: setCompleteness,
    custodian,
    gtmLine:
      'Receipt protocols prove actions. Aevesa session proofs prove workflows — compositional accountability offline.',
    note,
    errors,
  };
}
