import type { ParsedLiabilityReceipt } from './schema.js';
import { sha256HexUtf8 } from './digest.js';

export interface AnchorChainResult {
  ok: boolean;
  error?: string;
  chainLength: number;
  anchorHashes: string[];
}

/**
 * Stateless anchor validation: format, uniqueness, ordered hash-chain pre-image linkage
 * when anchors carry optional `chain_preimage` (extension) or deterministic demo linkage.
 */
export function verifyAnchorHashChain(receipt: ParsedLiabilityReceipt): AnchorChainResult {
  const anchors: { entry_hash: string; event_type: string; chain_preimage?: string }[] = [
    receipt.proof.primary_anchor,
    ...(receipt.proof.secondary_anchors ?? []),
  ];

  const anchorHashes = anchors.map((a) => a.entry_hash);
  const seen = new Set<string>();

  for (let i = 0; i < anchors.length; i++) {
    const hash = anchorHashes[i];
    if (!/^[a-f0-9]{64}$/.test(hash)) {
      return { ok: false, error: `Anchor ${i} entry_hash is not 64-char lowercase hex`, chainLength: 0, anchorHashes };
    }
    if (seen.has(hash)) {
      return { ok: false, error: `Duplicate anchor entry_hash at index ${i}`, chainLength: anchors.length, anchorHashes };
    }
    seen.add(hash);
  }

  if (receipt.proof.ledger_spec !== 'aegis/1') {
    return { ok: false, error: 'proof.ledger_spec must be aegis/1', chainLength: anchors.length, anchorHashes };
  }

  // Optional extension: explicit chain_preimage must hash to next anchor's entry_hash.
  for (let i = 0; i < anchors.length - 1; i++) {
    const preimage = (anchors[i] as { chain_preimage?: string }).chain_preimage;
    if (preimage != null && String(preimage).length > 0) {
      const expected = sha256HexUtf8(String(preimage));
      const next = anchorHashes[i + 1];
      if (expected !== next) {
        return {
          ok: false,
          error: `Anchor chain break: sha256(anchor[${i}].chain_preimage) !== anchor[${i + 1}].entry_hash`,
          chainLength: anchors.length,
          anchorHashes,
        };
      }
    }
  }

  return { ok: true, chainLength: anchors.length, anchorHashes };
}

/**
 * Recompute policy_version_hash from policy_pack_id when issuers use the reference digest rule.
 */
export function verifyPolicyVersionHash(receipt: ParsedLiabilityReceipt): { ok: boolean; error?: string } {
  const expected = sha256HexUtf8(receipt.policy.policy_pack_id);
  if (receipt.policy.policy_version_hash !== expected) {
    return {
      ok: false,
      error:
        'policy.policy_version_hash does not match sha256(policy_pack_id) under reference implementation rules',
    };
  }
  return { ok: true };
}
