import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';

/** Wave 9 Track Q — memory state commitment on material-action liability receipts (ASI06). */

export const MEMORY_COMMITMENT_SCHEMA = 'aevesa.memory-commitment/v1' as const;

export const MEMORY_COMMITMENT_SKU = 'aevesa-memory-commitment-v1' as const;

export const MEMORY_COMMITMENT_KINDS = [
  'memory_root',
  'vector_store_snapshot',
  'episodic_store',
] as const;

export type MemoryCommitmentKind = (typeof MEMORY_COMMITMENT_KINDS)[number];

export const MEMORY_ABSENT_REASONS = [
  'no_episodic_store_bound',
  'non_material_action',
  'provider_unavailable',
  'memory_gate_disabled',
] as const;

export type MemoryAbsentReason = (typeof MEMORY_ABSENT_REASONS)[number];

export interface MemoryCommitmentInput {
  present: boolean;
  memory_root_hash?: string | null;
  vector_store_id?: string | null;
  commitment_kind?: MemoryCommitmentKind | null;
  captured_at?: string | null;
  session_id?: string | null;
  tool_name?: string | null;
  entry_count?: number | null;
  provider_id?: string | null;
  absent_reason?: MemoryAbsentReason | string | null;
}



/** Merkle-style root over sorted episodic content hashes for a session snapshot. */
export function computeMemoryRootFromContentHashes(contentHashes: string[]): string {
  const sorted = [...contentHashes]
    .map((h) => String(h || '').trim().toLowerCase())
    .filter((h) => /^[a-f0-9]{64}$/.test(h))
    .sort();
  return sha256HexUtf8(sorted.join('|'));
}

export function buildMemoryCommitmentPreimage(
  input: MemoryCommitmentInput,
): Record<string, unknown> {
  const provider_id = String(input.provider_id || 'aevesa.inprocess').trim() || 'aevesa.inprocess';

  if (input.present === true) {
    const memory_root_hash = String(input.memory_root_hash || '')
      .trim()
      .toLowerCase();
    const commitment_kind =
      input.commitment_kind === 'memory_root' || input.commitment_kind === 'vector_store_snapshot'
        ? input.commitment_kind
        : 'episodic_store';

    return {
      schema: MEMORY_COMMITMENT_SCHEMA,
      present: true,
      memory_root_hash,
      vector_store_id: input.vector_store_id ?? null,
      commitment_kind,
      captured_at: input.captured_at ?? null,
      session_id: input.session_id ?? null,
      tool_name: input.tool_name ?? null,
      entry_count: input.entry_count ?? 0,
      provider_id,
    };
  }

  return {
    schema: MEMORY_COMMITMENT_SCHEMA,
    present: false,
    absent_reason: input.absent_reason ?? 'no_episodic_store_bound',
    session_id: input.session_id ?? null,
    tool_name: input.tool_name ?? null,
    provider_id,
  };
}

export function buildMemoryCommitmentDocument(input: MemoryCommitmentInput) {
  const preimage = buildMemoryCommitmentPreimage(input);
  const commitment_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    commitment_digest,
  };
}

/**
 * @param {unknown} raw
 * @returns {Record<string, unknown> | null}
 */
export function canonicalizeMemoryCommitmentForDigest(raw: unknown): Record<string, unknown> | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const src = raw as Record<string, unknown>;
  if (src.schema !== MEMORY_COMMITMENT_SCHEMA) return null;

  const digest = String(src.commitment_digest || '')
    .trim()
    .toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(digest)) return null;

  const present = src.present === true;
  if (present) {
    const memory_root_hash = String(src.memory_root_hash || '')
      .trim()
      .toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(memory_root_hash)) return null;
    return {
      schema: MEMORY_COMMITMENT_SCHEMA,
      present: true,
      memory_root_hash,
      commitment_digest: digest,
    };
  }

  return {
    schema: MEMORY_COMMITMENT_SCHEMA,
    present: false,
    absent_reason: src.absent_reason ?? null,
    commitment_digest: digest,
  };
}
