import {
  CONSTRAINT_CLOSURE_SCHEMA,
  RECOMPOSITION_RESULTS,
  evaluateConstraintClosure,
  type GenesisConstraint,
  type ConstraintOp,
} from '../core/constraintClosure.js';

export const CONSTRAINT_CLOSURE_SKU = 'aevesa-constraint-closure-v1' as const;

export interface ConstraintClosureDocument {
  schema?: string;
  session_id?: string;
  genesis_constraints?: GenesisConstraint[];
  terminal_state?: Record<string, unknown>;
  terminal_state_digest?: string;
  recomposition_result?: string;
  failed_constraints?: string[];
  evaluated_at_edge?: number;
  closure_digest?: string;
}

export interface ConstraintClosureVerifyOptions {
  requirePass?: boolean;
}

export interface ConstraintClosureVerifyChecks {
  schemaValid: boolean;
  sessionIdPresent: boolean;
  constraintsPresent: boolean;
  terminalStatePresent: boolean;
  recompositionResultValid: boolean;
  closureDigestMatches: boolean;
  recompositionPass: boolean;
  profileComplete: boolean;
}

export interface ConstraintClosureVerifyResult {
  schema: typeof CONSTRAINT_CLOSURE_SCHEMA;
  sku: typeof CONSTRAINT_CLOSURE_SKU;
  ok: boolean;
  checks: ConstraintClosureVerifyChecks;
  gtmLine: string;
  note: string | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function parseConstraints(raw: unknown): GenesisConstraint[] {
  if (!Array.isArray(raw)) return [];
  const out: GenesisConstraint[] = [];
  for (const item of raw) {
    const rec = asRecord(item);
    if (!rec) continue;
    const id = String(rec.id || '').trim();
    const op = String(rec.op || '').trim() as ConstraintOp;
    if (!id) continue;
    out.push({ id, op, value: rec.value });
  }
  return out;
}

/**
 * Verify constraint closure — CAP Phase 4 / AEG Source C terminal recomposition proof.
 */
export function verifyConstraintClosureBundle(
  input: unknown,
  options: ConstraintClosureVerifyOptions = {},
): ConstraintClosureVerifyResult {
  const doc = asRecord(input) as ConstraintClosureDocument | null;
  const schemaValid = doc?.schema === CONSTRAINT_CLOSURE_SCHEMA;
  const session_id = String(doc?.session_id || '').trim();
  const sessionIdPresent = session_id.length > 0;

  const genesis_constraints = parseConstraints(doc?.genesis_constraints);
  const constraintsPresent = genesis_constraints.length > 0;
  const terminal_state =
    doc?.terminal_state && typeof doc.terminal_state === 'object' && !Array.isArray(doc.terminal_state)
      ? (doc.terminal_state as Record<string, unknown>)
      : {};
  const terminalStatePresent = Object.keys(terminal_state).length > 0;

  const recomposition_result = String(doc?.recomposition_result || '').trim();
  const recompositionResultValid = RECOMPOSITION_RESULTS.includes(
    recomposition_result as 'PASS' | 'FAIL',
  );

  let closureDigestMatches = false;
  let recompositionPass = false;
  if (sessionIdPresent && constraintsPresent && terminalStatePresent) {
    const evalResult = evaluateConstraintClosure({
      session_id,
      genesis_constraints,
      terminal_state,
      evaluated_at_edge: doc?.evaluated_at_edge,
    });
    closureDigestMatches = Boolean(doc?.closure_digest) && doc!.closure_digest === evalResult.closure_digest;
    recompositionPass = evalResult.recomposition_result === 'PASS';
    if (recompositionResultValid && recomposition_result !== evalResult.recomposition_result) {
      closureDigestMatches = false;
    }
  }

  const requirePass = options.requirePass === true;
  const profileComplete =
    schemaValid &&
    sessionIdPresent &&
    constraintsPresent &&
    terminalStatePresent &&
    recompositionResultValid &&
    closureDigestMatches &&
    (!requirePass || recompositionPass);

  let note: string | null = null;
  if (profileComplete) {
    note =
      recompositionPass
        ? 'Constraint closure verified — all genesis constraints satisfied at terminal edge'
        : 'Constraint closure verified — recomposition failure attributed with offline proof';
  } else if (!closureDigestMatches) {
    note = 'closure_digest does not match genesis constraints + terminal state';
  } else if (requirePass && !recompositionPass) {
    note = 'Constraint closure requires recomposition_result PASS';
  } else {
    note = 'Constraint closure profile verification failed';
  }

  return {
    schema: CONSTRAINT_CLOSURE_SCHEMA,
    sku: CONSTRAINT_CLOSURE_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      sessionIdPresent,
      constraintsPresent,
      terminalStatePresent,
      recompositionResultValid,
      closureDigestMatches,
      recompositionPass,
      profileComplete,
    },
    gtmLine:
      'Locally valid hops, globally invalid session. Aevesa constraint closure proves genesis constraints at the irreversible boundary.',
    note,
  };
}
