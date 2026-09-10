import {
  EXECUTION_SURFACE_COMPLETENESS_SCHEMA,
  SURFACE_COMPLETENESS_RESULTS,
  evaluateExecutionSurfaceCompleteness,
  type ExecutionSurfaceDeclaration,
  type ExecutionSurfaceObservation,
  type SurfaceCompletenessResult,
} from '../core/executionSurfaceCompleteness.js';

export const EXECUTION_SURFACE_COMPLETENESS_SKU =
  'aevesa-execution-surface-completeness-v1' as const;

export interface ExecutionSurfaceCompletenessDocument {
  schema?: string;
  session_id?: string;
  execution_surfaces?: ExecutionSurfaceDeclaration[];
  observations?: ExecutionSurfaceObservation[];
  surface_completeness_root?: string;
  completeness_result?: string;
  overflow_surfaces?: string[];
  undeclared_surfaces?: string[];
  completeness_digest?: string;
}

export interface ExecutionSurfaceCompletenessVerifyOptions {
  requireComplete?: boolean;
}

export interface ExecutionSurfaceCompletenessVerifyChecks {
  schemaValid: boolean;
  sessionIdPresent: boolean;
  surfacesDeclared: boolean;
  observationsPresent: boolean;
  completenessResultValid: boolean;
  completenessDigestMatches: boolean;
  surfaceComplete: boolean;
  profileComplete: boolean;
}

export interface ExecutionSurfaceCompletenessVerifyResult {
  schema: typeof EXECUTION_SURFACE_COMPLETENESS_SCHEMA;
  sku: typeof EXECUTION_SURFACE_COMPLETENESS_SKU;
  ok: boolean;
  checks: ExecutionSurfaceCompletenessVerifyChecks;
  gtmLine: string;
  note: string | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function parseSurfaces(raw: unknown): ExecutionSurfaceDeclaration[] {
  if (!Array.isArray(raw)) return [];
  const out: ExecutionSurfaceDeclaration[] = [];
  for (const item of raw) {
    const rec = asRecord(item);
    if (!rec) continue;
    const surface = String(rec.surface || '').trim();
    if (!surface) continue;
    out.push({ surface, declared_count: Number(rec.declared_count) || 0 });
  }
  return out;
}

function parseObservations(raw: unknown): ExecutionSurfaceObservation[] {
  if (!Array.isArray(raw)) return [];
  const out: ExecutionSurfaceObservation[] = [];
  for (const item of raw) {
    const rec = asRecord(item);
    if (!rec) continue;
    const surface = String(rec.surface || '').trim();
    if (!surface) continue;
    out.push({ surface, observed_count: Number(rec.observed_count) || 0 });
  }
  return out;
}

/**
 * Verify execution surface completeness — negative-space session surface proof.
 */
export function verifyExecutionSurfaceCompletenessBundle(
  input: unknown,
  options: ExecutionSurfaceCompletenessVerifyOptions = {},
): ExecutionSurfaceCompletenessVerifyResult {
  const doc = asRecord(input) as ExecutionSurfaceCompletenessDocument | null;
  const schemaValid = doc?.schema === EXECUTION_SURFACE_COMPLETENESS_SCHEMA;
  const session_id = String(doc?.session_id || '').trim();
  const sessionIdPresent = session_id.length > 0;

  const execution_surfaces = parseSurfaces(doc?.execution_surfaces);
  const surfacesDeclared = execution_surfaces.length > 0;
  const observations = parseObservations(doc?.observations);
  const observationsPresent = observations.length > 0;

  const completeness_result = String(doc?.completeness_result || '').trim() as SurfaceCompletenessResult;
  const completenessResultValid = SURFACE_COMPLETENESS_RESULTS.includes(completeness_result);

  let completenessDigestMatches = false;
  let surfaceComplete = false;
  if (sessionIdPresent && surfacesDeclared) {
    const evalResult = evaluateExecutionSurfaceCompleteness({
      session_id,
      execution_surfaces,
      observations,
    });
    completenessDigestMatches =
      Boolean(doc?.completeness_digest) && doc!.completeness_digest === evalResult.completeness_digest;
    surfaceComplete = evalResult.completeness_result === 'COMPLETE';
    if (completenessResultValid && completeness_result !== evalResult.completeness_result) {
      completenessDigestMatches = false;
    }
  }

  const requireComplete = options.requireComplete === true;
  const profileComplete =
    schemaValid &&
    sessionIdPresent &&
    surfacesDeclared &&
    observationsPresent &&
    completenessResultValid &&
    completenessDigestMatches &&
    (!requireComplete || surfaceComplete);

  let note: string | null = null;
  if (profileComplete) {
    note = surfaceComplete
      ? 'Execution surface completeness verified — no undeclared surfaces in session'
      : `Execution surface completeness verified — ${completeness_result} attested offline`;
  } else if (!completenessDigestMatches) {
    note = 'completeness_digest does not match declared surfaces + observations';
  } else if (requireComplete && !surfaceComplete) {
    note = 'Execution surface completeness requires completeness_result COMPLETE';
  } else {
    note = 'Execution surface completeness verification failed';
  }

  return {
    schema: EXECUTION_SURFACE_COMPLETENESS_SCHEMA,
    sku: EXECUTION_SURFACE_COMPLETENESS_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      sessionIdPresent,
      surfacesDeclared,
      observationsPresent,
      completenessResultValid,
      completenessDigestMatches,
      surfaceComplete,
      profileComplete,
    },
    gtmLine:
      'Set-completeness proves hops. Aevesa surface completeness proves no parallel exfiltration channel — offline.',
    note,
  };
}
