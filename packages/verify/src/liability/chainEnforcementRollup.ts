import { isRecord } from '../core/isRecord.js';
import {
  ENFORCEMENT_MODES,
  type EnforcementMode,
} from '../core/proofStrengthDisclosure.js';
import { verifyProofStrengthDisclosure } from './proofStrengthDisclosureVerify.js';

export const CHAIN_ENFORCEMENT_ROLLUP_SCHEMA = 'aevesa.chain-enforcement-rollup/v1' as const;
export const CHAIN_ENFORCEMENT_ROLLUP_SKU = 'aevesa-chain-enforcement-rollup-v1' as const;

export type ChainEnforcementMode = EnforcementMode | 'mixed' | 'unknown';

export type HopEnforcementSource = 'member_receipt' | 'partial_step';

export interface HopEnforcementEntry {
  hop_index: number;
  enforcement_mode: EnforcementMode | 'unknown';
  source: HopEnforcementSource;
  /** When source is member_receipt — true only after crypto verify against manifest */
  member_verified?: boolean;
}

export interface ChainEnforcementRollupManifestMember {
  step_index?: number;
  entry_hash?: string;
}

export interface ChainEnforcementRollupInput {
  member_receipts?: unknown[] | null;
  partial_steps?: unknown[] | null;
  /**
   * partial_steps win over member_receipt at the same hop_index only when verified true (Wave 16-A / PC-01).
   */
  member_receipt_verified_by_hop?: Record<number, boolean> | boolean[] | null;
  /** Align truncated partial_steps window hops to manifest step_index via entry_hash (PC-12). */
  manifest_members?: ChainEnforcementRollupManifestMember[] | null;
}

export interface ChainEnforcementRollupResult {
  schema: typeof CHAIN_ENFORCEMENT_ROLLUP_SCHEMA;
  sku: typeof CHAIN_ENFORCEMENT_ROLLUP_SKU;
  chain_enforcement_mode: ChainEnforcementMode;
  uniformly_enforced: boolean;
  weakest_link_index: number | null;
  hop_modes: HopEnforcementEntry[];
  note: string;
}

function parseEnforcementMode(value: unknown): EnforcementMode | 'unknown' {
  const mode = String(value || '').trim();
  if ((ENFORCEMENT_MODES as readonly string[]).includes(mode)) {
    return mode as EnforcementMode;
  }
  return 'unknown';
}

function verifiedEnforcementFromDisclosure(doc: unknown): EnforcementMode | 'unknown' {
  if (!isRecord(doc)) return 'unknown';
  const verify = verifyProofStrengthDisclosure(doc);
  if (!verify.ok) return 'unknown';
  return parseEnforcementMode(doc.enforcement_mode);
}

function extractEnforcementFromReceipt(receipt: unknown): EnforcementMode | 'unknown' {
  if (!isRecord(receipt)) return 'unknown';
  const direct = receipt.proof_strength_disclosure;
  if (isRecord(direct)) {
    return verifiedEnforcementFromDisclosure(direct);
  }
  const governance = receipt.governance;
  if (isRecord(governance) && isRecord(governance.proof_strength_disclosure)) {
    return verifiedEnforcementFromDisclosure(governance.proof_strength_disclosure);
  }
  return 'unknown';
}

function extractEnforcementFromPartialStep(step: unknown): EnforcementMode | 'unknown' {
  if (!isRecord(step)) return 'unknown';
  if (step.enforcement_mode != null) {
    return parseEnforcementMode(step.enforcement_mode);
  }
  return 'unknown';
}

function hopVerified(
  hopIndex: number,
  verifiedByHop: Record<number, boolean> | boolean[] | null | undefined,
): boolean {
  if (!verifiedByHop) return false;
  if (Array.isArray(verifiedByHop)) return verifiedByHop[hopIndex] === true;
  return verifiedByHop[hopIndex] === true;
}

function mergeHopModes(entries: HopEnforcementEntry[]): HopEnforcementEntry[] {
  const byIndex = new Map<number, HopEnforcementEntry>();
  for (const entry of entries) {
    const existing = byIndex.get(entry.hop_index);
    if (!existing) {
      byIndex.set(entry.hop_index, entry);
      continue;
    }
    // Path-bound partial_steps beat member receipt only when that hop was crypto-verified (PC-01).
    if (entry.source === 'partial_step' && existing.source === 'member_receipt') {
      if (existing.member_verified === true) {
        byIndex.set(entry.hop_index, entry);
      }
      continue;
    }
    if (existing.source === 'partial_step' && entry.source === 'member_receipt') {
      if (entry.member_verified === true) {
        byIndex.set(entry.hop_index, entry);
      }
      continue;
    }
    if (existing.enforcement_mode === 'unknown' && entry.enforcement_mode !== 'unknown') {
      byIndex.set(entry.hop_index, entry);
    }
  }
  return [...byIndex.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([, entry]) => entry);
}

function deriveChainMode(hopModes: HopEnforcementEntry[]): ChainEnforcementMode {
  const known = hopModes
    .map((h) => h.enforcement_mode)
    .filter((m): m is EnforcementMode => m === 'enforced' || m === 'audit_only');
  if (known.length === 0) return 'unknown';
  const hasEnforced = known.includes('enforced');
  const hasAuditOnly = known.includes('audit_only');
  if (hasEnforced && hasAuditOnly) return 'mixed';
  if (hasAuditOnly) return 'audit_only';
  return 'enforced';
}

const HEX64 = /^[a-f0-9]{64}$/;

function normalizeEntryHash(value: unknown): string | null {
  const s = String(value ?? '').trim().toLowerCase();
  return HEX64.test(s) ? s : null;
}

/**
 * Prefer absolute step_index; when only window-relative index exists, align via manifest entry_hash (PC-12).
 */
function resolvePartialStepHopIndex(
  step: Record<string, unknown>,
  manifestMembers: ChainEnforcementRollupManifestMember[] | null | undefined,
): number | null {
  const stepIndex = Number(step.step_index);
  if (Number.isInteger(stepIndex) && stepIndex >= 0) return stepIndex;

  const entryHash = normalizeEntryHash(step.entry_hash);
  if (entryHash && Array.isArray(manifestMembers)) {
    const match = manifestMembers.find(
      (m) => normalizeEntryHash(m.entry_hash) === entryHash,
    );
    if (match != null && Number.isInteger(Number(match.step_index)) && Number(match.step_index) >= 0) {
      return Number(match.step_index);
    }
  }

  const index = Number(step.index);
  if (Number.isInteger(index) && index >= 0) return index;
  return null;
}

function weakestLinkIndex(hopModes: HopEnforcementEntry[]): number | null {
  const auditOnly = hopModes.filter((h) => h.enforcement_mode === 'audit_only');
  if (auditOnly.length === 0) return null;
  return auditOnly[0]?.hop_index ?? null;
}

function buildNote(
  chainMode: ChainEnforcementMode,
  uniformlyEnforced: boolean,
  weakestIndex: number | null,
): string {
  if (chainMode === 'unknown') {
    return 'Per-hop enforcement_mode not disclosed — set completeness does not imply uniform enforcement.';
  }
  if (uniformlyEnforced) {
    return 'All disclosed hops are enforced — session chain meets uniform pre-execution enforcement.';
  }
  if (chainMode === 'mixed' && weakestIndex != null) {
    return `Mixed enforcement — hop ${weakestIndex} is audit_only (weakest link). Set complete does not imply uniform enforcement.`;
  }
  if (chainMode === 'audit_only') {
    return 'Chain is audit_only — observe path only; do not treat as pre-execution enforced permit.';
  }
  return 'Chain enforcement rollup computed from member receipts and partial_steps.';
}

/**
 * Weakest-link rollup for multi-hop sessions (James-inspired composition semantics).
 * Set completeness proves manifest integrity; this proves enforcement uniformity.
 */
export function rollupChainEnforcement(
  input: ChainEnforcementRollupInput,
): ChainEnforcementRollupResult {
  const collected: HopEnforcementEntry[] = [];
  const verifiedByHop = input.member_receipt_verified_by_hop;

  if (Array.isArray(input.member_receipts)) {
    input.member_receipts.forEach((receipt, hopIndex) => {
      collected.push({
        hop_index: hopIndex,
        enforcement_mode: extractEnforcementFromReceipt(receipt),
        source: 'member_receipt',
        member_verified: hopVerified(hopIndex, verifiedByHop),
      });
    });
  }

  if (Array.isArray(input.partial_steps)) {
    for (const step of input.partial_steps) {
      if (!isRecord(step)) continue;
      const hopIndex = resolvePartialStepHopIndex(step, input.manifest_members);
      if (hopIndex == null || hopIndex < 0) continue;
      const memberVerified = hopVerified(hopIndex, verifiedByHop);
      const hasMemberAtHop =
        Array.isArray(input.member_receipts) && input.member_receipts[hopIndex] != null;
      const mode = extractEnforcementFromPartialStep(step);
      collected.push({
        hop_index: hopIndex,
        enforcement_mode:
          hasMemberAtHop && !memberVerified ? 'unknown' : mode,
        source: 'partial_step',
      });
    }
  }

  const hop_modes = mergeHopModes(collected);
  const chain_enforcement_mode = deriveChainMode(hop_modes);
  const uniformly_enforced =
    chain_enforcement_mode === 'enforced' &&
    hop_modes.length > 0 &&
    hop_modes.every((h) => h.enforcement_mode === 'enforced');
  const weakest_link_index = weakestLinkIndex(hop_modes);
  const note = buildNote(chain_enforcement_mode, uniformly_enforced, weakest_link_index);

  return {
    schema: CHAIN_ENFORCEMENT_ROLLUP_SCHEMA,
    sku: CHAIN_ENFORCEMENT_ROLLUP_SKU,
    chain_enforcement_mode,
    uniformly_enforced,
    weakest_link_index,
    hop_modes,
    note,
  };
}
