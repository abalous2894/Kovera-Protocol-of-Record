import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';

export const EXECUTION_SURFACE_COMPLETENESS_SCHEMA =
  'aevesa.execution-surface-completeness/v1' as const;

export const SURFACE_COMPLETENESS_RESULTS = [
  'COMPLETE',
  'SURFACE_OVERFLOW',
  'UNDECLARED_SURFACE',
] as const;

export type SurfaceCompletenessResult = (typeof SURFACE_COMPLETENESS_RESULTS)[number];

export interface ExecutionSurfaceDeclaration {
  surface: string;
  declared_count: number;
}

export interface ExecutionSurfaceObservation {
  surface: string;
  observed_count: number;
}

export interface ExecutionSurfaceCompletenessInput {
  session_id: string;
  execution_surfaces: ExecutionSurfaceDeclaration[];
  observations: ExecutionSurfaceObservation[];
}



/**
 * Negative-space completeness — prove no undeclared execution surface was used.
 */
export function evaluateExecutionSurfaceCompleteness(
  input: ExecutionSurfaceCompletenessInput,
): {
  completeness_result: SurfaceCompletenessResult;
  overflow_surfaces: string[];
  undeclared_surfaces: string[];
  surface_completeness_root: string;
  completeness_digest: string;
} {
  const declared = new Map<string, number>();
  for (const d of input.execution_surfaces || []) {
    const surface = String(d.surface || '').trim();
    if (!surface) continue;
    declared.set(surface, Number(d.declared_count) || 0);
  }

  const observed = new Map<string, number>();
  for (const o of input.observations || []) {
    const surface = String(o.surface || '').trim();
    if (!surface) continue;
    observed.set(surface, (observed.get(surface) || 0) + (Number(o.observed_count) || 0));
  }

  const overflow_surfaces: string[] = [];
  const undeclared_surfaces: string[] = [];

  for (const [surface, obsCount] of observed) {
    if (!declared.has(surface)) {
      undeclared_surfaces.push(surface);
    } else if (obsCount > (declared.get(surface) ?? 0)) {
      overflow_surfaces.push(surface);
    }
  }

  let completeness_result: SurfaceCompletenessResult = 'COMPLETE';
  if (undeclared_surfaces.length > 0) {
    completeness_result = 'UNDECLARED_SURFACE';
  } else if (overflow_surfaces.length > 0) {
    completeness_result = 'SURFACE_OVERFLOW';
  }

  const sortedDeclared = [...(input.execution_surfaces || [])]
    .map((d) => ({
      surface: String(d.surface).trim(),
      declared_count: Number(d.declared_count) || 0,
    }))
    .sort((a, b) => a.surface.localeCompare(b.surface));

  const surface_completeness_root = sha256HexUtf8(
    stableStringify({
      schema: EXECUTION_SURFACE_COMPLETENESS_SCHEMA,
      session_id: String(input.session_id).trim(),
      execution_surfaces: sortedDeclared,
    }),
  );

  const completeness_digest = sha256HexUtf8(
    stableStringify({
      schema: EXECUTION_SURFACE_COMPLETENESS_SCHEMA,
      session_id: String(input.session_id).trim(),
      surface_completeness_root,
      completeness_result,
      overflow_surfaces: [...overflow_surfaces].sort(),
      undeclared_surfaces: [...undeclared_surfaces].sort(),
      observations: [...observed.entries()]
        .map(([surface, observed_count]) => ({ surface, observed_count }))
        .sort((a, b) => a.surface.localeCompare(b.surface)),
    }),
  );

  return {
    completeness_result,
    overflow_surfaces,
    undeclared_surfaces,
    surface_completeness_root,
    completeness_digest,
  };
}

export function buildExecutionSurfaceCompletenessDocument(
  input: ExecutionSurfaceCompletenessInput,
): Record<string, unknown> {
  const evalResult = evaluateExecutionSurfaceCompleteness(input);
  const observations = [...(input.observations || [])]
    .map((o) => ({
      surface: String(o.surface).trim(),
      observed_count: Number(o.observed_count) || 0,
    }))
    .sort((a, b) => a.surface.localeCompare(b.surface));

  return {
    schema: EXECUTION_SURFACE_COMPLETENESS_SCHEMA,
    session_id: String(input.session_id).trim(),
    execution_surfaces: input.execution_surfaces,
    observations,
    surface_completeness_root: evalResult.surface_completeness_root,
    completeness_result: evalResult.completeness_result,
    overflow_surfaces: evalResult.overflow_surfaces,
    undeclared_surfaces: evalResult.undeclared_surfaces,
    completeness_digest: evalResult.completeness_digest,
  };
}
