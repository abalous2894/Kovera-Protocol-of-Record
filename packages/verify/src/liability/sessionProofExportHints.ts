import { isRecord } from '../core/isRecord.js';

export const SESSION_PROOF_EXPORT_HINTS_SCHEMA = 'aevesa.session-proof-export-hints/v1' as const;

export interface SessionProofExportHints {
  schema: typeof SESSION_PROOF_EXPORT_HINTS_SCHEMA;
  require_member_receipt_verification: boolean;
  member_receipts_bundled: boolean;
  member_receipt_count: number;
  declared_count: number;
  notes: string[];
}

export interface SessionProofExportHintsInput {
  declared_count?: number | null;
  member_receipts?: unknown[] | null;
  manifest?: unknown;
}

function declaredCountFromManifest(manifest: unknown): number | null {
  if (!isRecord(manifest)) return null;
  const count = Number(manifest.declared_count);
  return Number.isFinite(count) && count >= 0 ? count : null;
}

/**
 * Diligence-kit hints — set complete ≠ per-hop receipt verification when members not bundled.
 */
export function buildSessionProofExportHints(
  input: SessionProofExportHintsInput,
): SessionProofExportHints {
  const declared =
    input.declared_count ??
    declaredCountFromManifest(input.manifest) ??
    (Array.isArray(input.member_receipts) ? input.member_receipts.length : 0);
  const memberCount = Array.isArray(input.member_receipts) ? input.member_receipts.length : 0;
  const member_receipts_bundled = declared > 0 && memberCount === declared;
  const require_member_receipt_verification = declared > 0 && !member_receipts_bundled;

  const notes: string[] = [];
  if (require_member_receipt_verification) {
    notes.push(
      'requireMemberReceiptVerification: manifest + terminal receipt verify set integrity only — auditors must verify each members[].receipt_digest independently or bundle member_receipts[] for offline per-hop verify.',
    );
  } else if (member_receipts_bundled) {
    notes.push(
      'Full member_receipts[] bundled — use verifySessionProof with requireMemberReceipts for per-hop offline verification and chain enforcement rollup.',
    );
  }

  return {
    schema: SESSION_PROOF_EXPORT_HINTS_SCHEMA,
    require_member_receipt_verification,
    member_receipts_bundled,
    member_receipt_count: memberCount,
    declared_count: declared,
    notes,
  };
}
