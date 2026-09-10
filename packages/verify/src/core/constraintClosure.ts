import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';

export const CONSTRAINT_CLOSURE_SCHEMA = 'aevesa.constraint-closure/v1' as const;

export const CONSTRAINT_OPS = ['eq', 'lte', 'gte', 'lt', 'gt', 'in'] as const;
export type ConstraintOp = (typeof CONSTRAINT_OPS)[number];

export const RECOMPOSITION_RESULTS = ['PASS', 'FAIL'] as const;
export type RecompositionResult = (typeof RECOMPOSITION_RESULTS)[number];

export interface GenesisConstraint {
  id: string;
  op: ConstraintOp;
  value: unknown;
}

export interface ConstraintClosureInput {
  session_id: string;
  genesis_constraints: GenesisConstraint[];
  terminal_state: Record<string, unknown>;
  evaluated_at_edge?: number;
}



function compareConstraint(op: ConstraintOp, actual: unknown, expected: unknown): boolean {
  if (actual === undefined || actual === null) return false;
  switch (op) {
    case 'eq':
      return String(actual) === String(expected);
    case 'lte':
      return Number(actual) <= Number(expected);
    case 'gte':
      return Number(actual) >= Number(expected);
    case 'lt':
      return Number(actual) < Number(expected);
    case 'gt':
      return Number(actual) > Number(expected);
    case 'in':
      return Array.isArray(expected) && expected.map(String).includes(String(actual));
    default:
      return false;
  }
}

/**
 * Evaluate genesis constraints against terminal session state (AEG Source C — recomposition).
 */
export function evaluateConstraintClosure(input: ConstraintClosureInput): {
  recomposition_result: RecompositionResult;
  failed_constraints: string[];
  terminal_state_digest: string;
  closure_digest: string;
} {
  const terminal_state_digest = sha256HexUtf8(
    stableStringify(input.terminal_state ?? {}),
  );

  const failed_constraints: string[] = [];
  for (const c of input.genesis_constraints || []) {
    const actual = input.terminal_state?.[c.id];
    if (!compareConstraint(c.op, actual, c.value)) {
      failed_constraints.push(c.id);
    }
  }

  const recomposition_result: RecompositionResult =
    failed_constraints.length === 0 ? 'PASS' : 'FAIL';

  const preimage = {
    schema: CONSTRAINT_CLOSURE_SCHEMA,
    session_id: String(input.session_id).trim(),
    genesis_constraints: [...(input.genesis_constraints || [])].sort((a, b) =>
      a.id.localeCompare(b.id),
    ),
    terminal_state_digest,
    recomposition_result,
    failed_constraints: [...failed_constraints].sort(),
    evaluated_at_edge: input.evaluated_at_edge ?? 5,
  };

  return {
    recomposition_result,
    failed_constraints,
    terminal_state_digest,
    closure_digest: sha256HexUtf8(stableStringify(preimage)),
  };
}

export function buildConstraintClosureDocument(
  input: ConstraintClosureInput,
): Record<string, unknown> {
  const evalResult = evaluateConstraintClosure(input);
  return {
    schema: CONSTRAINT_CLOSURE_SCHEMA,
    session_id: String(input.session_id).trim(),
    genesis_constraints: input.genesis_constraints,
    terminal_state: input.terminal_state,
    terminal_state_digest: evalResult.terminal_state_digest,
    recomposition_result: evalResult.recomposition_result,
    failed_constraints: evalResult.failed_constraints,
    evaluated_at_edge: input.evaluated_at_edge ?? 5,
    closure_digest: evalResult.closure_digest,
  };
}
