import { isRecord } from '../core/isRecord.js';
import { isCapExportEnvelopeStale } from './capExportGatePolicy.js';
import {
  evaluateClosureShipGate,
  CLOSURE_SHIP_GATE_SCHEMA,
  SESSION_COMPOSITION_CLOSURE_SCHEMA,
  type ClosureShipGateResult,
  type SessionCompositionClosure,
} from './sessionCompositionClosure.js';

/** Single integrator gate — stale export policy + closure-derived ship gate (James Sep 2026). */
export const CAP_EXPORT_CARRIER_HANDOFF_SCHEMA = 'aevesa.cap-export-carrier-handoff/v1' as const;

export type CapExportCarrierHandoffRefusalReason =
  | 'stale_export_gate_policy'
  | 'missing_composition_closure'
  | 'closure_ship_gate_mismatch'
  | 'missing_closure_ship_gate'
  | 'ship_gate_blocked';

export interface CapExportCarrierHandoffEvaluation {
  schema: typeof CAP_EXPORT_CARRIER_HANDOFF_SCHEMA;
  carrier_handoff_allowed: boolean;
  refused: boolean;
  reason: CapExportCarrierHandoffRefusalReason | null;
  export_gate_stale: boolean;
  closure_ship_gate: ClosureShipGateResult | null;
  note: string;
}

function readCompositionClosure(body: Record<string, unknown>): SessionCompositionClosure | null {
  const raw = body.composition_closure;
  if (!isRecord(raw) || raw.schema !== SESSION_COMPOSITION_CLOSURE_SCHEMA) {
    return null;
  }
  return raw as unknown as SessionCompositionClosure;
}

function readClosureShipGate(body: Record<string, unknown>): ClosureShipGateResult | null {
  const raw = body.closure_ship_gate;
  if (!isRecord(raw) || raw.schema !== CLOSURE_SHIP_GATE_SCHEMA) return null;
  return raw as unknown as ClosureShipGateResult;
}

function gatesMateriallyMismatch(
  supplied: ClosureShipGateResult,
  derived: ClosureShipGateResult,
): boolean {
  return (
    supplied.blocked !== derived.blocked ||
    supplied.carrier_submission_ready !== derived.carrier_submission_ready
  );
}

function refuseMissingClosure(detail: string): CapExportCarrierHandoffEvaluation {
  return {
    schema: CAP_EXPORT_CARRIER_HANDOFF_SCHEMA,
    carrier_handoff_allowed: false,
    refused: true,
    reason: 'missing_composition_closure',
    export_gate_stale: false,
    closure_ship_gate: evaluateClosureShipGate(null),
    note: detail,
  };
}

/**
 * Fail-closed carrier handoff gate for cached cap-bundle bodies.
 * Derives ship gate from composition_closure — never trusts pasted gate fields alone.
 */
export function evaluateCapExportCarrierHandoff(body: unknown): CapExportCarrierHandoffEvaluation {
  const export_gate_stale = isCapExportEnvelopeStale(body);
  if (export_gate_stale) {
    return {
      schema: CAP_EXPORT_CARRIER_HANDOFF_SCHEMA,
      carrier_handoff_allowed: false,
      refused: true,
      reason: 'stale_export_gate_policy',
      export_gate_stale: true,
      closure_ship_gate: null,
      note:
        'Cap-bundle export_gate_policy missing or below min_supported_version — re-fetch before carrier handoff.',
    };
  }

  if (!isRecord(body)) {
    return refuseMissingClosure('Cap-bundle body is not an object.');
  }

  const closure = readCompositionClosure(body);
  if (!closure) {
    return refuseMissingClosure(
      'composition_closure absent or invalid — do not infer carrier readiness from closure_ship_gate or rollup alone.',
    );
  }

  const derivedGate = evaluateClosureShipGate(closure);
  const suppliedGate = readClosureShipGate(body);
  if (suppliedGate && gatesMateriallyMismatch(suppliedGate, derivedGate)) {
    return {
      schema: CAP_EXPORT_CARRIER_HANDOFF_SCHEMA,
      carrier_handoff_allowed: false,
      refused: true,
      reason: 'closure_ship_gate_mismatch',
      export_gate_stale: false,
      closure_ship_gate: derivedGate,
      note:
        'Supplied closure_ship_gate contradicts composition_closure-derived gate — possible tampered cache; re-fetch.',
    };
  }

  if (derivedGate.blocked === true || derivedGate.carrier_submission_ready !== true) {
    return {
      schema: CAP_EXPORT_CARRIER_HANDOFF_SCHEMA,
      carrier_handoff_allowed: false,
      refused: true,
      reason: 'ship_gate_blocked',
      export_gate_stale: false,
      closure_ship_gate: derivedGate,
      note: derivedGate.note || 'Carrier submission blocked by closure-derived ship gate.',
    };
  }

  return {
    schema: CAP_EXPORT_CARRIER_HANDOFF_SCHEMA,
    carrier_handoff_allowed: true,
    refused: false,
    reason: null,
    export_gate_stale: false,
    closure_ship_gate: derivedGate,
    note: 'Carrier handoff allowed — export gate fresh and closure-derived ship gate clear.',
  };
}
