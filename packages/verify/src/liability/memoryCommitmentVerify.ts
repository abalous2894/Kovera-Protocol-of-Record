import { sha256HexUtf8 } from '../core/sha256.js';
import { MEMORY_COMMITMENT_SCHEMA, buildMemoryCommitmentPreimage, type MemoryCommitmentInput } from '../core/memoryCommitment.js';
import { stableStringify } from '../core/stableStringify.js';

export interface MemoryCommitmentVerifyResult {
  ok: boolean;
  code: string;
  expected?: string;
  got?: string;
  present?: boolean;
  memoryRootHash?: string | null;
}

/**
 * Offline verify for aevesa.memory-commitment/v1 blocks on liability receipts.
 */
export function verifyMemoryCommitment(commitment: unknown): MemoryCommitmentVerifyResult {
  if (!commitment || typeof commitment !== 'object' || Array.isArray(commitment)) {
    return { ok: false, code: 'INVALID_MEMORY_COMMITMENT' };
  }

  const block = commitment as Record<string, unknown>;
  if (block.schema !== MEMORY_COMMITMENT_SCHEMA) {
    return { ok: false, code: 'INVALID_MEMORY_COMMITMENT_SCHEMA' };
  }

  const stored = String(block.commitment_digest || '').toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(stored)) {
    return { ok: false, code: 'MISSING_COMMITMENT_DIGEST' };
  }

  const present = block.present === true;
  const preimage = buildMemoryCommitmentPreimage(block as unknown as MemoryCommitmentInput);
  const expected = sha256HexUtf8(stableStringify(preimage));
  if (expected !== stored) {
    return {
      ok: false,
      code: 'MEMORY_COMMITMENT_DIGEST_MISMATCH',
      expected,
      got: stored,
      present,
      memoryRootHash: present ? String(block.memory_root_hash || '').toLowerCase() : null,
    };
  }

  if (present) {
    const root = String(block.memory_root_hash || '').toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(root)) {
      return { ok: false, code: 'MISSING_MEMORY_ROOT_HASH', present: true };
    }
    return { ok: true, code: 'MEMORY_COMMITMENT_VERIFIED', present: true, memoryRootHash: root };
  }

  const absentReason = block.absent_reason;
  if (absentReason == null || String(absentReason).trim() === '') {
    return { ok: false, code: 'MISSING_ABSENT_REASON', present: false };
  }

  return { ok: true, code: 'MEMORY_COMMITMENT_ABSENT_MARKED', present: false, memoryRootHash: null };
}

export function buildMemoryCommitmentProofSteps(receipt: {
  memory_commitment?: unknown;
  side_effects?: { effect_class?: string; action?: { tool_name?: string } };
}) {
  const commitment = receipt?.memory_commitment;
  const verify = verifyMemoryCommitment(commitment);
  const present = (commitment as { present?: boolean } | undefined)?.present === true;

  return [
    {
      key: 'memory_commitment_schema',
      label: 'Memory commitment extension (aevesa.memory-commitment/v1)',
      ok: Boolean(commitment && typeof commitment === 'object'),
      detail: (commitment as { schema?: string } | undefined)?.schema || 'missing',
    },
    {
      key: 'memory_commitment_digest',
      label: 'Commitment digest binds memory root or honest absent marker',
      ok: verify.ok === true,
      detail: verify.ok ? verify.code : verify.code,
    },
    {
      key: 'memory_root_hash',
      label: present
        ? 'Memory root hash captured at material-action intercept'
        : 'Honest absent marker (no episodic store bound or non-material action)',
      ok: present ? verify.ok === true && Boolean(verify.memoryRootHash) : verify.ok === true,
      detail: present
        ? verify.memoryRootHash || 'missing'
        : String((commitment as { absent_reason?: string } | undefined)?.absent_reason || 'absent'),
    },
    {
      key: 'material_action_context',
      label: 'Receipt side effect class supports ASI06 post-mortem narrative',
      ok: Boolean(receipt?.side_effects?.effect_class && receipt.side_effects.effect_class !== 'none'),
      detail: receipt?.side_effects?.action?.tool_name || receipt?.side_effects?.effect_class || 'unknown',
    },
  ];
}
