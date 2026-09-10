import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';
import {
  buildExecutionSurfaceCompletenessDocument,
  evaluateExecutionSurfaceCompleteness,
  EXECUTION_SURFACE_COMPLETENESS_SCHEMA,
  type ExecutionSurfaceCompletenessInput,
} from './executionSurfaceCompleteness.js';
import {
  CHANNEL_PROVENANCE_SCHEMA,
  computeChannelProvenanceDigest,
  type ChannelProvenanceSource,
} from './channelProvenance.js';

export const PROVABLE_EXECUTION_BOUNDARY_SCHEMA =
  'aevesa.provable-execution-boundary/v1' as const;

export const BOUNDARY_SCOPES = ['session_governed', 'decision_window'] as const;
export type BoundaryScope = (typeof BOUNDARY_SCOPES)[number];

export const BOUNDARY_RESULTS = [
  'COMPLETE',
  'SURFACE_GAP',
  'CHANNEL_GAP',
  'BOUNDARY_MISMATCH',
  'COMPOSITION_MISMATCH',
] as const;

export type BoundaryResult = (typeof BOUNDARY_RESULTS)[number];

export interface DeclaredBoundary {
  /** Execution surfaces included in the governed boundary claim (sorted at verify time). */
  surfaces: string[];
  /** Optional channel source_ids that must appear in channel_provenance.sources. */
  channel_source_ids?: string[];
}

export interface ProvableExecutionBoundaryEvaluateInput {
  session_id: string;
  boundary_scope: BoundaryScope;
  declared_boundary: DeclaredBoundary;
  /** Pre-built channel provenance document, if any. */
  channel_provenance?: Record<string, unknown> | null;
  /** Pre-built or raw execution surface completeness document / input. */
  execution_surface_completeness: Record<string, unknown> | ExecutionSurfaceCompletenessInput;
  /** When true, missing channel_provenance yields CHANNEL_GAP. */
  require_channel_provenance?: boolean;
}



function sortSurfaces(surfaces: string[]): string[] {
  return [...new Set(surfaces.map((s) => String(s).trim()).filter(Boolean))].sort((a, b) =>
    a.localeCompare(b),
  );
}

function normalizeDeclaredBoundary(raw: DeclaredBoundary): DeclaredBoundary {
  return {
    surfaces: sortSurfaces(raw.surfaces || []),
    ...(raw.channel_source_ids?.length
      ? { channel_source_ids: sortSurfaces(raw.channel_source_ids) }
      : {}),
  };
}

function surfacesFromExecutionDoc(doc: Record<string, unknown>): string[] {
  const raw = doc.execution_surfaces;
  if (!Array.isArray(raw)) return [];
  const surfaces: string[] = [];
  for (const item of raw) {
    if (item && typeof item === 'object' && !Array.isArray(item)) {
      const surface = String((item as Record<string, unknown>).surface || '').trim();
      if (surface) surfaces.push(surface);
    }
  }
  return sortSurfaces(surfaces);
}

function channelSourceIdsFromDoc(doc: Record<string, unknown> | null | undefined): string[] {
  if (!doc) return [];
  const raw = doc.sources;
  if (!Array.isArray(raw)) return [];
  const ids: string[] = [];
  for (const item of raw) {
    if (item && typeof item === 'object' && !Array.isArray(item)) {
      const id = String((item as Record<string, unknown>).source_id || '').trim();
      if (id) ids.push(id);
    }
  }
  return sortSurfaces(ids);
}

function resolveExecutionSurfaceDocument(
  input: Record<string, unknown> | ExecutionSurfaceCompletenessInput,
): Record<string, unknown> {
  if (
    input &&
    typeof input === 'object' &&
    (input as Record<string, unknown>).schema === EXECUTION_SURFACE_COMPLETENESS_SCHEMA
  ) {
    return input as Record<string, unknown>;
  }
  return buildExecutionSurfaceCompletenessDocument(input as ExecutionSurfaceCompletenessInput);
}

function computePebRoot(input: {
  session_id: string;
  boundary_scope: BoundaryScope;
  declared_boundary: DeclaredBoundary;
  channel_provenance_digest: string | null;
  surface_completeness_root: string;
}): string {
  return sha256HexUtf8(
    stableStringify({
      schema: PROVABLE_EXECUTION_BOUNDARY_SCHEMA,
      session_id: String(input.session_id).trim(),
      boundary_scope: input.boundary_scope,
      declared_boundary: normalizeDeclaredBoundary(input.declared_boundary),
      channel_provenance_digest: input.channel_provenance_digest,
      surface_completeness_root: input.surface_completeness_root,
    }),
  );
}

/**
 * Evaluate a provable execution boundary — composes channel provenance + surface completeness.
 */
export function evaluateProvableExecutionBoundary(
  input: ProvableExecutionBoundaryEvaluateInput,
): {
  boundary_result: BoundaryResult;
  boundary_mismatch_surfaces: string[];
  missing_channel_source_ids: string[];
  session_ids_aligned: boolean;
  surface_completeness_root: string;
  channel_provenance_digest: string | null;
  peb_root: string;
  peb_digest: string;
  execution_surface_completeness: Record<string, unknown>;
} {
  const session_id = String(input.session_id).trim();
  const boundary_scope = input.boundary_scope;
  const declared_boundary = normalizeDeclaredBoundary(input.declared_boundary);

  const execution_surface_completeness = resolveExecutionSurfaceDocument(
    input.execution_surface_completeness,
  );
  const surfaceSessionId = String(execution_surface_completeness.session_id || '').trim();
  const channelDoc = input.channel_provenance ?? null;
  const channelSessionId = channelDoc ? String(channelDoc.session_id || '').trim() : session_id;

  const session_ids_aligned =
    surfaceSessionId === session_id && (!channelDoc || channelSessionId === session_id);

  const executionDeclaredSurfaces = surfacesFromExecutionDoc(execution_surface_completeness);
  const boundary_mismatch_surfaces = declared_boundary.surfaces.filter(
    (s) => !executionDeclaredSurfaces.includes(s),
  );
  const boundarySurfacesMatch =
    declared_boundary.surfaces.length > 0 &&
    declared_boundary.surfaces.length === executionDeclaredSurfaces.length &&
    declared_boundary.surfaces.every((s, i) => s === executionDeclaredSurfaces[i]);

  const surfaceEval = evaluateExecutionSurfaceCompleteness({
    session_id: surfaceSessionId,
    execution_surfaces: (execution_surface_completeness.execution_surfaces || []) as ExecutionSurfaceCompletenessInput['execution_surfaces'],
    observations: (execution_surface_completeness.observations || []) as ExecutionSurfaceCompletenessInput['observations'],
  });

  let channel_provenance_digest: string | null = null;
  if (channelDoc && Array.isArray(channelDoc.sources)) {
    channel_provenance_digest = computeChannelProvenanceDigest({
      session_id: channelSessionId,
      decision_id: channelDoc.decision_id as string | undefined,
      sources: channelDoc.sources as ChannelProvenanceSource[],
    });
  }

  const missing_channel_source_ids =
    declared_boundary.channel_source_ids?.filter(
      (id) => !channelSourceIdsFromDoc(channelDoc).includes(id),
    ) ?? [];

  let channelOk = true;
  if (input.require_channel_provenance && !channelDoc) {
    channelOk = false;
  } else if (channelDoc) {
    channelOk =
      channelDoc.schema === CHANNEL_PROVENANCE_SCHEMA &&
      Boolean(channel_provenance_digest) &&
      String(channelDoc.channel_provenance_digest || '').toLowerCase() === channel_provenance_digest;
  }

  let boundary_result: BoundaryResult = 'COMPLETE';
  if (!session_ids_aligned) {
    boundary_result = 'COMPOSITION_MISMATCH';
  } else if (!boundarySurfacesMatch || boundary_mismatch_surfaces.length > 0) {
    boundary_result = 'BOUNDARY_MISMATCH';
  } else if (surfaceEval.completeness_result !== 'COMPLETE') {
    boundary_result = 'SURFACE_GAP';
  } else if (!channelOk || missing_channel_source_ids.length > 0) {
    boundary_result = 'CHANNEL_GAP';
  }

  const surface_completeness_root = String(
    execution_surface_completeness.surface_completeness_root || surfaceEval.surface_completeness_root,
  );

  const peb_root = computePebRoot({
    session_id,
    boundary_scope,
    declared_boundary,
    channel_provenance_digest,
    surface_completeness_root,
  });

  const peb_digest = sha256HexUtf8(
    stableStringify({
      schema: PROVABLE_EXECUTION_BOUNDARY_SCHEMA,
      session_id,
      boundary_scope,
      declared_boundary,
      boundary_result,
      boundary_mismatch_surfaces: [...boundary_mismatch_surfaces].sort(),
      missing_channel_source_ids: [...missing_channel_source_ids].sort(),
      channel_provenance_digest,
      surface_completeness_root,
      completeness_result: surfaceEval.completeness_result,
      completeness_digest: surfaceEval.completeness_digest,
      peb_root,
    }),
  );

  return {
    boundary_result,
    boundary_mismatch_surfaces,
    missing_channel_source_ids,
    session_ids_aligned,
    surface_completeness_root,
    channel_provenance_digest,
    peb_root,
    peb_digest,
    execution_surface_completeness,
  };
}

export function buildProvableExecutionBoundaryDocument(
  input: ProvableExecutionBoundaryEvaluateInput,
): Record<string, unknown> {
  const evalResult = evaluateProvableExecutionBoundary(input);
  const declared_boundary = normalizeDeclaredBoundary(input.declared_boundary);

  return {
    schema: PROVABLE_EXECUTION_BOUNDARY_SCHEMA,
    session_id: String(input.session_id).trim(),
    boundary_scope: input.boundary_scope,
    declared_boundary,
    ...(input.channel_provenance ? { channel_provenance: input.channel_provenance } : {}),
    execution_surface_completeness: evalResult.execution_surface_completeness,
    channel_provenance_digest: evalResult.channel_provenance_digest,
    surface_completeness_root: evalResult.surface_completeness_root,
    boundary_result: evalResult.boundary_result,
    boundary_mismatch_surfaces: evalResult.boundary_mismatch_surfaces,
    missing_channel_source_ids: evalResult.missing_channel_source_ids,
    peb_root: evalResult.peb_root,
    peb_digest: evalResult.peb_digest,
  };
}
