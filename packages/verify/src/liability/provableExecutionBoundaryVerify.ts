import {
  PROVABLE_EXECUTION_BOUNDARY_SCHEMA,
  BOUNDARY_RESULTS,
  BOUNDARY_SCOPES,
  evaluateProvableExecutionBoundary,
  type BoundaryResult,
  type BoundaryScope,
  type DeclaredBoundary,
} from '../core/provableExecutionBoundary.js';
import { verifyChannelProvenanceBundle } from './channelProvenanceVerify.js';
import { verifyExecutionSurfaceCompletenessBundle } from './executionSurfaceCompletenessVerify.js';

export const PROVABLE_EXECUTION_BOUNDARY_SKU = 'aevesa-provable-execution-boundary-v1' as const;

export interface ProvableExecutionBoundaryDocument {
  schema?: string;
  session_id?: string;
  boundary_scope?: string;
  declared_boundary?: DeclaredBoundary;
  channel_provenance?: Record<string, unknown>;
  execution_surface_completeness?: Record<string, unknown>;
  channel_provenance_digest?: string | null;
  surface_completeness_root?: string;
  boundary_result?: string;
  boundary_mismatch_surfaces?: string[];
  missing_channel_source_ids?: string[];
  peb_root?: string;
  peb_digest?: string;
}

export interface ProvableExecutionBoundaryVerifyOptions {
  /** Require boundary_result === COMPLETE */
  requireComplete?: boolean;
  /** Require embedded channel_provenance present and valid */
  requireChannelProvenance?: boolean;
  /** Pass-through: require environmental channel source */
  requireEnvironmentalSource?: boolean;
  /** Require nested execution surface completeness COMPLETE */
  requireSurfaceComplete?: boolean;
}

export interface ProvableExecutionBoundaryVerifyChecks {
  schemaValid: boolean;
  sessionIdPresent: boolean;
  boundaryScopeValid: boolean;
  declaredBoundaryPresent: boolean;
  executionSurfacePresent: boolean;
  boundaryResultValid: boolean;
  pebRootMatches: boolean;
  pebDigestMatches: boolean;
  sessionIdsAligned: boolean;
  channelProvenanceVerified: boolean;
  executionSurfaceVerified: boolean;
  boundaryComplete: boolean;
  profileComplete: boolean;
}

export interface ProvableExecutionBoundaryVerifyResult {
  schema: typeof PROVABLE_EXECUTION_BOUNDARY_SCHEMA;
  sku: typeof PROVABLE_EXECUTION_BOUNDARY_SKU;
  ok: boolean;
  checks: ProvableExecutionBoundaryVerifyChecks;
  gtmLine: string;
  note: string | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function parseDeclaredBoundary(raw: unknown): DeclaredBoundary | null {
  const rec = asRecord(raw);
  if (!rec) return null;
  const surfaces = Array.isArray(rec.surfaces)
    ? rec.surfaces.map((s) => String(s).trim()).filter(Boolean)
    : [];
  if (!surfaces.length) return null;
  const channel_source_ids = Array.isArray(rec.channel_source_ids)
    ? rec.channel_source_ids.map((s) => String(s).trim()).filter(Boolean)
    : undefined;
  return { surfaces, ...(channel_source_ids?.length ? { channel_source_ids } : {}) };
}

/**
 * Verify provable execution boundary bundle — Wave 7 Track A composition profile.
 */
export function verifyProvableExecutionBoundaryBundle(
  input: unknown,
  options: ProvableExecutionBoundaryVerifyOptions = {},
): ProvableExecutionBoundaryVerifyResult {
  const doc = asRecord(input) as ProvableExecutionBoundaryDocument | null;
  const schemaValid = doc?.schema === PROVABLE_EXECUTION_BOUNDARY_SCHEMA;

  const session_id = String(doc?.session_id || '').trim();
  const sessionIdPresent = session_id.length > 0;

  const boundary_scope = String(doc?.boundary_scope || '').trim() as BoundaryScope;
  const boundaryScopeValid = BOUNDARY_SCOPES.includes(boundary_scope);

  const declared_boundary = parseDeclaredBoundary(doc?.declared_boundary);
  const declaredBoundaryPresent = declared_boundary != null;

  const execution_surface_completeness = asRecord(doc?.execution_surface_completeness);
  const executionSurfacePresent = execution_surface_completeness != null;

  const boundary_result = String(doc?.boundary_result || '').trim() as BoundaryResult;
  const boundaryResultValid = BOUNDARY_RESULTS.includes(boundary_result);

  let pebRootMatches = false;
  let pebDigestMatches = false;
  let sessionIdsAligned = false;
  let channelProvenanceVerified = true;
  let executionSurfaceVerified = false;
  let boundaryComplete = false;

  if (sessionIdPresent && declared_boundary && execution_surface_completeness && boundaryScopeValid) {
    const requireChannel = options.requireChannelProvenance === true;
    const evalResult = evaluateProvableExecutionBoundary({
      session_id,
      boundary_scope,
      declared_boundary,
      channel_provenance: doc?.channel_provenance ?? null,
      execution_surface_completeness,
      require_channel_provenance: requireChannel,
    });

    pebRootMatches = Boolean(doc?.peb_root) && doc!.peb_root === evalResult.peb_root;
    pebDigestMatches = Boolean(doc?.peb_digest) && doc!.peb_digest === evalResult.peb_digest;
    sessionIdsAligned = evalResult.session_ids_aligned;
    boundaryComplete = evalResult.boundary_result === 'COMPLETE';

    if (boundaryResultValid && boundary_result !== evalResult.boundary_result) {
      pebDigestMatches = false;
    }

    if (doc?.channel_provenance) {
      const channelResult = verifyChannelProvenanceBundle(doc.channel_provenance, {
        requireEnvironmentalSource: options.requireEnvironmentalSource === true,
      });
      channelProvenanceVerified = channelResult.ok === true;
    } else if (requireChannel) {
      channelProvenanceVerified = false;
    }

    const surfaceResult = verifyExecutionSurfaceCompletenessBundle(execution_surface_completeness, {
      requireComplete: options.requireSurfaceComplete === true,
    });
    executionSurfaceVerified = surfaceResult.ok === true;
  } else if (options.requireChannelProvenance) {
    channelProvenanceVerified = false;
  }

  const requireComplete = options.requireComplete === true;
  const profileComplete =
    schemaValid &&
    sessionIdPresent &&
    boundaryScopeValid &&
    declaredBoundaryPresent &&
    executionSurfacePresent &&
    boundaryResultValid &&
    pebRootMatches &&
    pebDigestMatches &&
    sessionIdsAligned &&
    channelProvenanceVerified &&
    executionSurfaceVerified &&
    (!requireComplete || boundaryComplete);

  let note: string | null = null;
  if (profileComplete) {
    note = boundaryComplete
      ? 'Provable execution boundary verified — governed session boundary complete offline'
      : `Provable execution boundary verified — ${boundary_result} attested offline`;
  } else if (!pebDigestMatches) {
    note = 'peb_digest does not match composed channel + surface preimage';
  } else if (!sessionIdsAligned) {
    note = 'session_id mismatch between PEB and nested channel/surface documents';
  } else if (!channelProvenanceVerified) {
    note = 'Embedded channel_provenance missing or failed verification';
  } else if (!executionSurfaceVerified) {
    note = 'Embedded execution_surface_completeness failed verification';
  } else if (requireComplete && !boundaryComplete) {
    note = 'Provable execution boundary requires boundary_result COMPLETE';
  } else {
    note = 'Provable execution boundary verification failed';
  }

  return {
    schema: PROVABLE_EXECUTION_BOUNDARY_SCHEMA,
    sku: PROVABLE_EXECUTION_BOUNDARY_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      sessionIdPresent,
      boundaryScopeValid,
      declaredBoundaryPresent,
      executionSurfacePresent,
      boundaryResultValid,
      pebRootMatches,
      pebDigestMatches,
      sessionIdsAligned,
      channelProvenanceVerified,
      executionSurfaceVerified,
      boundaryComplete,
      profileComplete,
    },
    gtmLine:
      'Cyera maps what AI can touch. Aevesa proves what executed — and whether your governed session boundary was complete, offline.',
    note,
  };
}
