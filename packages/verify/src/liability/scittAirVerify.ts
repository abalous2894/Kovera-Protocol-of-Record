import type { ProveBundleVerifyOptions, ProveBundleVerifyResult } from './proveBundleVerify.js';
import { verifyProveBundle } from './proveBundleVerify.js';
import { verifyReceipt } from './verifyReceipt.js';
import {
  validateScittRefusalAlignment,
  isDeniedReceiptProfile,
} from './deniedReceiptProfile.js';

export const SCITT_AIR_PROFILE = 'SCITT-AIR-draft-alignment-01' as const;
export const SCITT_AIR_VERIFY_SCHEMA = 'aevesa.scitt-air-verify/v1' as const;
export const SCITT_AIR_SKU = 'aevesa-scitt-air-v1' as const;

export interface ScittAirAlignmentBlock {
  profile?: string;
  agent_interaction_record?: {
    agent_id?: string;
    session_id?: string;
    correlation_id?: string;
    action_tool?: string;
    entry_hash?: string;
    issued_at?: string;
    policy_decision?: string;
  };
  evidence_custodian_role?: string;
  compliance_mappings?: string[];
}

export interface ScittAirVerifyOptions extends ProveBundleVerifyOptions {
  requireCustodianRole?: boolean;
  requireWitnessCosign?: boolean;
}

export interface ScittAirVerifyChecks {
  receiptValid: boolean;
  airProfilePresent: boolean;
  airMappingsComplete: boolean;
  agentIdBound: boolean;
  sessionBound: boolean;
  entryHashBound: boolean;
  custodianRolePresent: boolean;
  proveBundle: ProveBundleVerifyResult['checks'];
  scittRefusalAligned: boolean;
  profileComplete: boolean;
}

export interface ScittAirVerifyResult {
  schema: typeof SCITT_AIR_VERIFY_SCHEMA;
  sku: typeof SCITT_AIR_SKU;
  ok: boolean;
  checks: ScittAirVerifyChecks;
  proveBundle: ProveBundleVerifyResult;
  airAlignment: ScittAirAlignmentBlock | null;
  gtmLine: string;
  note: string | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function readAirAlignment(receipt: Record<string, unknown>): ScittAirAlignmentBlock | null {
  const air = asRecord(receipt.air_alignment);
  if (!air) return null;
  const airRecord = asRecord(air.agent_interaction_record);
  return {
    profile: typeof air.profile === 'string' ? air.profile : undefined,
    agent_interaction_record: airRecord
      ? {
          agent_id: typeof airRecord.agent_id === 'string' ? airRecord.agent_id : undefined,
          session_id: typeof airRecord.session_id === 'string' ? airRecord.session_id : undefined,
          correlation_id:
            typeof airRecord.correlation_id === 'string' ? airRecord.correlation_id : undefined,
          action_tool: typeof airRecord.action_tool === 'string' ? airRecord.action_tool : undefined,
          entry_hash: typeof airRecord.entry_hash === 'string' ? airRecord.entry_hash : undefined,
          issued_at: typeof airRecord.issued_at === 'string' ? airRecord.issued_at : undefined,
          policy_decision:
            typeof airRecord.policy_decision === 'string' ? airRecord.policy_decision : undefined,
        }
      : undefined,
    evidence_custodian_role:
      typeof air.evidence_custodian_role === 'string' ? air.evidence_custodian_role : undefined,
    compliance_mappings: Array.isArray(air.compliance_mappings)
      ? air.compliance_mappings.filter((m): m is string => typeof m === 'string')
      : undefined,
  };
}

function bindingMatch(
  airValue: string | undefined,
  receiptValue: string | undefined,
): boolean {
  if (!airValue || !receiptValue) return false;
  return String(airValue).trim() === String(receiptValue).trim();
}

/**
 * SCITT Agent Interaction Record (AIR) draft alignment — independent Evidence Custodian
 * transparency-service mapping on liability-receipt/v1 (EU Art. 12/19, DORA, NIST).
 */
export function validateScittAirAlignment(receipt: Record<string, unknown>): {
  ok: boolean;
  code: string;
  errors?: string[];
} {
  const air = readAirAlignment(receipt);
  if (!air) {
    return { ok: false, code: 'MISSING_AIR_ALIGNMENT' };
  }

  const errors: string[] = [];
  if (air.profile !== SCITT_AIR_PROFILE) errors.push('air_alignment.profile');

  const airRecord = air.agent_interaction_record;
  if (!airRecord) {
    errors.push('air_alignment.agent_interaction_record');
  } else {
    const identity = asRecord(receipt.identity);
    const primaryActor = asRecord(identity?.primary_actor);
    const session = asRecord(receipt.session);
    const policy = asRecord(receipt.policy);
    const sideEffects = asRecord(receipt.side_effects);
    const action = asRecord(sideEffects?.action);
    const proof = asRecord(receipt.proof);
    const anchor = asRecord(proof?.primary_anchor);

    if (!bindingMatch(airRecord.agent_id, String(primaryActor?.agent_id || ''))) {
      errors.push('agent_id binding');
    }
    if (!bindingMatch(airRecord.session_id, String(session?.session_id || ''))) {
      errors.push('session_id binding');
    }
    if (
      airRecord.entry_hash &&
      anchor?.entry_hash &&
      !bindingMatch(airRecord.entry_hash, String(anchor.entry_hash))
    ) {
      errors.push('entry_hash binding');
    }
    if (
      airRecord.action_tool &&
      action?.tool_name &&
      !bindingMatch(airRecord.action_tool, String(action.tool_name))
    ) {
      errors.push('action_tool binding');
    }
    if (
      airRecord.policy_decision &&
      policy?.decision &&
      !bindingMatch(airRecord.policy_decision, String(policy.decision))
    ) {
      errors.push('policy_decision binding');
    }
    if (airRecord.issued_at && receipt.issued_at) {
      if (!bindingMatch(airRecord.issued_at, String(receipt.issued_at))) {
        errors.push('issued_at binding');
      }
    }
  }

  if (!air.evidence_custodian_role) {
    errors.push('air_alignment.evidence_custodian_role');
  }

  if (errors.length) {
    return { ok: false, code: 'SCITT_AIR_ALIGNMENT_INVALID', errors };
  }

  return { ok: true, code: 'SCITT_AIR_ALIGNMENT_VALID' };
}

export function applyScittAirAlignment(receipt: Record<string, unknown>): Record<string, unknown> {
  const identity = asRecord(receipt.identity);
  const primaryActor = asRecord(identity?.primary_actor);
  const session = asRecord(receipt.session);
  const policy = asRecord(receipt.policy);
  const sideEffects = asRecord(receipt.side_effects);
  const action = asRecord(sideEffects?.action);
  const proof = asRecord(receipt.proof);
  const anchor = asRecord(proof?.primary_anchor);

  const next = { ...receipt };
  next.air_alignment = {
    profile: SCITT_AIR_PROFILE,
    agent_interaction_record: {
      agent_id: primaryActor?.agent_id ?? null,
      session_id: session?.session_id ?? null,
      correlation_id: session?.correlation_id ?? null,
      action_tool: action?.tool_name ?? null,
      entry_hash: anchor?.entry_hash ?? null,
      issued_at: receipt.issued_at ?? null,
      policy_decision: policy?.decision ?? null,
    },
    evidence_custodian_role: 'transparency_service',
    compliance_mappings: [
      'EU AI Act Art. 12',
      'EU AI Act Art. 19',
      'DORA ICT risk logging',
      'NIST AI RMF MEASURE-2',
    ],
  };
  return next;
}

/**
 * SCITT AIR profile verify — receipt crypto + AIR field bindings + optional witness cosign.
 */
export function verifyScittAirBundle(
  receiptData: unknown,
  options: ScittAirVerifyOptions = {},
): ScittAirVerifyResult {
  const requireCustodian = options.requireCustodianRole !== false;
  const requireWitness = options.requireWitnessCosign === true;

  const receipt = asRecord(receiptData);
  const receiptValid = receipt ? verifyReceipt(receipt, options).isValid === true : false;

  const airAlignment = receipt ? readAirAlignment(receipt) : null;
  const airValidation = receipt ? validateScittAirAlignment(receipt) : { ok: false, code: 'NO_RECEIPT' };

  const airProfilePresent = airAlignment?.profile === SCITT_AIR_PROFILE;
  const airMappingsComplete = airValidation.ok === true;
  const airRecord = airAlignment?.agent_interaction_record;

  const identity = receipt ? asRecord(receipt.identity) : null;
  const primaryActor = identity ? asRecord(identity.primary_actor) : null;
  const session = receipt ? asRecord(receipt.session) : null;
  const proof = receipt ? asRecord(receipt.proof) : null;
  const anchor = proof ? asRecord(proof.primary_anchor) : null;

  const agentIdBound = bindingMatch(airRecord?.agent_id, String(primaryActor?.agent_id || ''));
  const sessionBound = bindingMatch(airRecord?.session_id, String(session?.session_id || ''));
  const entryHashBound = bindingMatch(airRecord?.entry_hash, String(anchor?.entry_hash || ''));

  const custodianRolePresent =
    !requireCustodian || airAlignment?.evidence_custodian_role === 'transparency_service';

  const proveBundle = verifyProveBundle(receiptData, {
    ...options,
    requireWitnessCosign: requireWitness,
  });

  const scittRefusal =
    receipt && isDeniedReceiptProfile(receipt)
      ? validateScittRefusalAlignment(receipt)
      : { ok: true, skipped: true };
  const scittRefusalAligned = scittRefusal.ok === true || scittRefusal.skipped === true;

  const profileComplete =
    receiptValid &&
    airProfilePresent &&
    airMappingsComplete &&
    agentIdBound &&
    sessionBound &&
    entryHashBound &&
    custodianRolePresent &&
    proveBundle.checks.receiptValid === true &&
    scittRefusalAligned &&
    (!requireWitness ||
      (proveBundle.checks.witnessCosignProvided === true &&
        proveBundle.checks.witnessCosignStructureValid === true));

  const ok = profileComplete;

  let note: string | null = proveBundle.note;
  if (ok) {
    note = 'SCITT AIR draft alignment verified — Agent Interaction Record bound to liability receipt with custodian role';
  } else if (!airProfilePresent) {
    note = `SCITT AIR requires air_alignment.profile ${SCITT_AIR_PROFILE}`;
  } else if (!airMappingsComplete) {
    note = `SCITT AIR alignment invalid: ${airValidation.code}`;
  } else if (requireWitness && proveBundle.checks.witnessCosignProvided !== true) {
    note = 'SCITT AIR profile requires independent witness cosign on material actions';
  } else {
    note = note || 'SCITT AIR profile verification failed';
  }

  return {
    schema: SCITT_AIR_VERIFY_SCHEMA,
    sku: SCITT_AIR_SKU,
    ok,
    checks: {
      receiptValid,
      airProfilePresent,
      airMappingsComplete,
      agentIdBound,
      sessionBound,
      entryHashBound,
      custodianRolePresent,
      proveBundle: proveBundle.checks,
      scittRefusalAligned,
      profileComplete,
    },
    proveBundle,
    airAlignment,
    gtmLine:
      'Art. 12 wants tamper-evident agent logs. SCITT AIR + independent custodian is the verify pattern auditors are converging on.',
    note,
  };
}
