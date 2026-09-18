import { createHash } from 'node:crypto';
import { stableStringify } from '../core/stableStringify.js';
import { isRecord } from '../core/isRecord.js';
import type { ChainEnforcementRollupResult } from './chainEnforcementRollup.js';
import {
  buildSessionCompositionGuidance,
  type SessionCompositionGuidance,
} from './sessionCompositionGuidance.js';
import type { SessionProofExportHints } from './sessionProofExportHints.js';
import type { ChannelProvenanceContentBindingReport } from './channelProvenanceContentBinding.js';
import { verifyChannelProvenanceBundle } from './channelProvenanceVerify.js';

export const SESSION_COMPOSITION_CLOSURE_SCHEMA = 'aevesa.session-composition-closure/v1' as const;
export const SESSION_COMPOSITION_CLOSURE_SKU = 'aevesa-session-composition-closure-v1' as const;

export const RECEIPT_PRESENCE_KINDS = ['bundled', 'digest_only', 'absent'] as const;
export type ReceiptPresenceKind = (typeof RECEIPT_PRESENCE_KINDS)[number];

export const RECEIPT_VERIFY_PROFILES = [
  'member_receipt_verified',
  'digest_only',
  'not_verified',
] as const;
export type ReceiptVerifyProfile = (typeof RECEIPT_VERIFY_PROFILES)[number];

export const CLOSURE_VERDICTS = [
  'carrier_review_ready',
  'member_verification_required',
  'mixed_enforcement_disclosed',
  'digest_only_submission',
] as const;
export type ClosureVerdict = (typeof CLOSURE_VERDICTS)[number];

export const CHAIN_ENFORCEMENT_ROLLUP_SCOPES = ['enforcement_only'] as const;
export type ChainEnforcementRollupScope = (typeof CHAIN_ENFORCEMENT_ROLLUP_SCOPES)[number];

export interface ChannelProvenanceAdvisory {
  digest_only_delegated_source_ids: string[];
  carrier_channel_ready: boolean;
  advisory_note: string | null;
  content_binding_report: ChannelProvenanceContentBindingReport | null;
}

export interface ChainEnforcementAdvisory {
  rollup_scope: ChainEnforcementRollupScope;
  /** False when rollup shows enforcement but receipt_presence has digest-only, absent, or unverified hops (James J-6). */
  chain_enforcement_qualified: boolean;
  weakest_receipt_hop_index: number | null;
  advisory_note: string | null;
}

export interface HopReceiptPresence {
  hop_index: number;
  step_index: number;
  presence: ReceiptPresenceKind;
  receipt_digest: string | null;
  verify_profile: ReceiptVerifyProfile;
}

export interface SessionCompositionClosureInput {
  set_completeness_ok: boolean;
  manifest: unknown;
  member_receipts?: unknown[] | null;
  member_receipt_verified_by_hop?: Record<number, boolean> | boolean[] | null;
}

export interface SessionCompositionClosure {
  schema: typeof SESSION_COMPOSITION_CLOSURE_SCHEMA;
  sku: typeof SESSION_COMPOSITION_CLOSURE_SKU;
  closure_verdict: ClosureVerdict;
  carrier_review_ready: boolean;
  receipt_presence: HopReceiptPresence[];
  chain_enforcement: ChainEnforcementRollupResult | null;
  chain_enforcement_advisory: ChainEnforcementAdvisory;
  channel_provenance_advisory: ChannelProvenanceAdvisory | null;
  composition_guidance: SessionCompositionGuidance;
  export_hints: SessionProofExportHints | null;
  set_completeness_ok: boolean;
  closure_digest: string;
  note: string;
}

export const CLOSURE_SHIP_GATE_SCHEMA = 'aevesa.closure-ship-gate/v1' as const;

/** James J-6 operational gate — carrier/MGA submit must read closure, not rollup alone. */
export interface ClosureShipGateResult {
  schema: typeof CLOSURE_SHIP_GATE_SCHEMA;
  carrier_submission_ready: boolean;
  blocked: boolean;
  closure_verdict: ClosureVerdict | null;
  chain_enforcement_qualified: boolean | null;
  /** True when rollup shows enforcement but closure is not carrier-ready (James acceptance test). */
  rollup_alone_ship_risk: boolean;
  /**
   * PC-16 — integrators must not infer carrier readiness from `chain_enforcement` alone when false.
   * True only when `carrier_submission_ready` (closure + qualified rollup align).
   */
  rollup_carrier_inference_allowed: boolean;
  note: string | null;
}

const ROLLUP_ENFORCEMENT_MODES_FOR_SHIP = new Set(['enforced', 'audit_only', 'mixed']);

/**
 * Operational ship gate for carrier/MGA submission (James Sep 2026 acceptance test).
 * Set integrity + rollup must not substitute for `carrier_review_ready`.
 */
export function evaluateClosureShipGate(
  closure: SessionCompositionClosure | null | undefined,
): ClosureShipGateResult {
  if (!closure || closure.schema !== SESSION_COMPOSITION_CLOSURE_SCHEMA) {
    return {
      schema: CLOSURE_SHIP_GATE_SCHEMA,
      carrier_submission_ready: false,
      blocked: true,
      closure_verdict: null,
      chain_enforcement_qualified: null,
      rollup_alone_ship_risk: true,
      rollup_carrier_inference_allowed: false,
      note:
        'composition_closure absent — do not ship on set integrity or chain enforcement rollup alone',
    };
  }

  const carrierReady = closure.carrier_review_ready === true;
  const qualified = closure.chain_enforcement_advisory?.chain_enforcement_qualified === true;
  const rollupMode = closure.chain_enforcement?.chain_enforcement_mode ?? 'unknown';
  const rollupShowsEnforcement = ROLLUP_ENFORCEMENT_MODES_FOR_SHIP.has(String(rollupMode));
  const rollupAloneShipRisk =
    !carrierReady &&
    rollupShowsEnforcement &&
    closure.chain_enforcement_advisory?.chain_enforcement_qualified === false;

  const carrierSubmissionReady = carrierReady && qualified;
  const blocked = !carrierSubmissionReady;

  let note: string | null = null;
  if (rollupAloneShipRisk) {
    note =
      'James J-6 acceptance test: closure is not carrier-ready but rollup shows enforcement — do not ship on rollup badge alone; read composition_closure.';
  } else if (blocked) {
    note = `Carrier submission blocked — closure_verdict: ${closure.closure_verdict}. ${closure.note || ''}`.trim();
  }

  return {
    schema: CLOSURE_SHIP_GATE_SCHEMA,
    carrier_submission_ready: carrierSubmissionReady,
    blocked,
    closure_verdict: closure.closure_verdict,
    chain_enforcement_qualified: closure.chain_enforcement_advisory?.chain_enforcement_qualified ?? null,
    rollup_alone_ship_risk: rollupAloneShipRisk,
    rollup_carrier_inference_allowed: carrierSubmissionReady,
    note,
  };
}

const HEX64 = /^[a-f0-9]{64}$/;

function normalizeHex64(v: unknown): string | null {
  const s = String(v ?? '').trim().toLowerCase();
  return HEX64.test(s) ? s : null;
}

function hopVerified(
  hopIndex: number,
  verifiedByHop: Record<number, boolean> | boolean[] | null | undefined,
): boolean {
  if (!verifiedByHop) return false;
  if (Array.isArray(verifiedByHop)) return verifiedByHop[hopIndex] === true;
  return verifiedByHop[hopIndex] === true;
}

function manifestMembers(manifest: unknown): Array<{ step_index: number; receipt_digest: string | null }> {
  if (!isRecord(manifest) || !Array.isArray(manifest.members)) return [];
  return manifest.members
    .map((m) => {
      if (!isRecord(m)) return null;
      const step_index = Number(m.step_index);
      if (!Number.isInteger(step_index) || step_index < 0) return null;
      return {
        step_index,
        receipt_digest: normalizeHex64(m.receipt_digest),
      };
    })
    .filter((m): m is { step_index: number; receipt_digest: string | null } => m != null)
    .sort((a, b) => a.step_index - b.step_index);
}

/**
 * Per-hop receipt presence for counsel — bundled vs digest-only vs absent (James J-3).
 */
export function buildReceiptPresence(input: SessionCompositionClosureInput): HopReceiptPresence[] {
  const members = manifestMembers(input.manifest);
  const receipts = Array.isArray(input.member_receipts) ? input.member_receipts : [];
  const verifiedByHop = input.member_receipt_verified_by_hop;

  return members.map((member, hopIndex) => {
    const receipt = receipts[hopIndex];
    const hasBody = receipt != null && isRecord(receipt);
    const verified = hopVerified(hopIndex, verifiedByHop);

    if (hasBody && verified) {
      return {
        hop_index: hopIndex,
        step_index: member.step_index,
        presence: 'bundled' as const,
        receipt_digest: member.receipt_digest,
        verify_profile: 'member_receipt_verified' as const,
      };
    }
    if (hasBody && !verified) {
      return {
        hop_index: hopIndex,
        step_index: member.step_index,
        presence: 'bundled' as const,
        receipt_digest: member.receipt_digest,
        verify_profile: 'not_verified' as const,
      };
    }
    if (member.receipt_digest) {
      return {
        hop_index: hopIndex,
        step_index: member.step_index,
        presence: 'digest_only' as const,
        receipt_digest: member.receipt_digest,
        verify_profile: 'digest_only' as const,
      };
    }
    return {
      hop_index: hopIndex,
      step_index: member.step_index,
      presence: 'absent' as const,
      receipt_digest: null,
      verify_profile: 'not_verified' as const,
    };
  });
}

export function deriveClosureVerdict(input: {
  set_completeness_ok: boolean;
  receipt_presence: HopReceiptPresence[];
  chain_enforcement: ChainEnforcementRollupResult | null;
  export_hints: SessionProofExportHints | null;
}): ClosureVerdict {
  const { receipt_presence, chain_enforcement, export_hints } = input;

  if (receipt_presence.some((h) => h.presence === 'absent' || h.presence === 'digest_only')) {
    return 'digest_only_submission';
  }
  if (
    receipt_presence.some((h) => h.verify_profile !== 'member_receipt_verified') ||
    export_hints?.require_member_receipt_verification === true
  ) {
    return 'member_verification_required';
  }
  const mode = chain_enforcement?.chain_enforcement_mode;
  if (mode === 'mixed' || mode === 'audit_only') {
    return 'mixed_enforcement_disclosed';
  }
  if (
    input.set_completeness_ok &&
    chain_enforcement?.uniformly_enforced === true &&
    receipt_presence.length > 0 &&
    receipt_presence.every((h) => h.presence === 'bundled' && h.verify_profile === 'member_receipt_verified')
  ) {
    return 'carrier_review_ready';
  }
  return 'member_verification_required';
}

const ROLLUP_ENFORCEMENT_MODES = new Set(['enforced', 'audit_only', 'mixed']);

/**
 * Cross-bind enforcement rollup with receipt_presence — rollup does not inherit verification state (PC-15 / J-6).
 */
export function buildChainEnforcementAdvisory(input: {
  receipt_presence: HopReceiptPresence[];
  chain_enforcement: ChainEnforcementRollupResult | null;
  require_member_receipt_verification?: boolean;
}): ChainEnforcementAdvisory {
  const digestOrAbsent = input.receipt_presence.filter(
    (h) => h.presence === 'digest_only' || h.presence === 'absent',
  );
  const unverifiedBundled = input.receipt_presence.filter(
    (h) => h.presence === 'bundled' && h.verify_profile !== 'member_receipt_verified',
  );
  const receiptGap = digestOrAbsent.length > 0 || unverifiedBundled.length > 0;
  const weakestReceiptHop =
    digestOrAbsent[0]?.hop_index ?? unverifiedBundled[0]?.hop_index ?? null;

  const chainMode = input.chain_enforcement?.chain_enforcement_mode ?? 'unknown';
  const rollupShowsEnforcement = ROLLUP_ENFORCEMENT_MODES.has(chainMode);
  const qualified = !(receiptGap && rollupShowsEnforcement);

  let advisory_note: string | null = null;
  if (!qualified) {
    advisory_note =
      'Chain enforcement rollup reflects weakest enforcement hop only — it does not inherit receipt verification state. ' +
      `Hop ${weakestReceiptHop ?? '?'} is digest-only, absent, or unverified; requireMemberReceipts and composition_closure govern carrier readiness, not rollup alone.`;
  } else if (input.require_member_receipt_verification === true && receiptGap) {
    advisory_note =
      'Member receipt verification required — rollup scope is enforcement-only and does not substitute for bundled member verify.';
  }

  return {
    rollup_scope: 'enforcement_only',
    chain_enforcement_qualified: qualified,
    weakest_receipt_hop_index: weakestReceiptHop,
    advisory_note,
  };
}

function closureNote(verdict: ClosureVerdict, chain: ChainEnforcementRollupResult | null): string {
  switch (verdict) {
    case 'carrier_review_ready':
      return 'All hops bundled and verified with uniformly enforced chain — carrier diligence may proceed on closure block.';
    case 'member_verification_required':
      return 'Set integrity verified — per-hop member receipt verification required before carrier submission.';
    case 'mixed_enforcement_disclosed':
      return `Mixed or audit-only enforcement disclosed${chain?.weakest_link_index != null ? ` (weakest link hop ${chain.weakest_link_index})` : ''} — evaluate chain separately from terminal receipt.`;
    case 'digest_only_submission':
      return 'Digest-only or absent member receipts — hash manifest integrity only; do not treat as carrier-ready session proof.';
    default:
      return 'Composition closure computed.';
  }
}

function computeClosureDigest(closure: Omit<SessionCompositionClosure, 'closure_digest'>): string {
  const preimage = stableStringify({
    schema: closure.schema,
    closure_verdict: closure.closure_verdict,
    set_completeness_ok: closure.set_completeness_ok,
    receipt_presence: closure.receipt_presence,
    chain_enforcement_mode: closure.chain_enforcement?.chain_enforcement_mode ?? null,
    uniformly_enforced: closure.chain_enforcement?.uniformly_enforced ?? null,
    require_member_receipt_verification:
      closure.export_hints?.require_member_receipt_verification ?? null,
    chain_enforcement_qualified: closure.chain_enforcement_advisory.chain_enforcement_qualified,
    rollup_scope: closure.chain_enforcement_advisory.rollup_scope,
    weakest_receipt_hop_index: closure.chain_enforcement_advisory.weakest_receipt_hop_index,
    ...(closure.channel_provenance_advisory?.digest_only_delegated_source_ids?.length
      ? {
          channel_digest_only_delegated:
            closure.channel_provenance_advisory.digest_only_delegated_source_ids,
        }
      : {}),
  });
  return createHash('sha256').update(preimage, 'utf8').digest('hex');
}

export function buildChannelProvenanceAdvisory(
  channelProvenance: unknown,
): ChannelProvenanceAdvisory | null {
  if (channelProvenance == null) return null;
  const verified = verifyChannelProvenanceBundle(channelProvenance);
  const report = verified.content_binding_report;
  if (!report) return null;

  let advisory_note: string | null = null;
  if (report.has_digest_only_delegated) {
    advisory_note =
      `Delegated authority source(s) digest-only: ${report.digest_only_delegated_source_ids.join(', ')} — mandate content not bound at capture; downgrade session closure.`;
  }

  return {
    digest_only_delegated_source_ids: report.digest_only_delegated_source_ids,
    carrier_channel_ready: report.carrier_channel_ready,
    advisory_note,
    content_binding_report: report,
  };
}

function applyChannelProvenanceClosureDowngrade(
  verdict: ClosureVerdict,
  channelAdvisory: ChannelProvenanceAdvisory | null,
): ClosureVerdict {
  if (!channelAdvisory?.digest_only_delegated_source_ids.length) return verdict;
  if (
    verdict === 'carrier_review_ready' ||
    verdict === 'mixed_enforcement_disclosed' ||
    verdict === 'member_verification_required'
  ) {
    return 'digest_only_submission';
  }
  return verdict;
}

export interface BuildSessionCompositionClosureInput extends SessionCompositionClosureInput {
  chain_enforcement: ChainEnforcementRollupResult | null;
  export_hints: SessionProofExportHints | null;
  channel_provenance?: unknown | null;
}

/**
 * Wave 16-A — single closure block for CAP exports (James J-3/J-4).
 */
export function buildSessionCompositionClosure(
  input: BuildSessionCompositionClosureInput,
): SessionCompositionClosure {
  const receipt_presence = buildReceiptPresence(input);
  const composition_guidance = buildSessionCompositionGuidance({
    chain_enforcement: input.chain_enforcement,
    export_hints: input.export_hints,
  });
  const channel_provenance_advisory = buildChannelProvenanceAdvisory(input.channel_provenance);
  let closure_verdict = deriveClosureVerdict({
    set_completeness_ok: input.set_completeness_ok,
    receipt_presence,
    chain_enforcement: input.chain_enforcement,
    export_hints: input.export_hints,
  });
  closure_verdict = applyChannelProvenanceClosureDowngrade(
    closure_verdict,
    channel_provenance_advisory,
  );
  const chain_enforcement_advisory = buildChainEnforcementAdvisory({
    receipt_presence,
    chain_enforcement: input.chain_enforcement,
    require_member_receipt_verification:
      input.export_hints?.require_member_receipt_verification === true,
  });
  let note = closureNote(closure_verdict, input.chain_enforcement);
  if (channel_provenance_advisory?.advisory_note && closure_verdict === 'digest_only_submission') {
    note = `${note} ${channel_provenance_advisory.advisory_note}`;
  }

  const withoutDigest: Omit<SessionCompositionClosure, 'closure_digest'> = {
    schema: SESSION_COMPOSITION_CLOSURE_SCHEMA,
    sku: SESSION_COMPOSITION_CLOSURE_SKU,
    closure_verdict,
    carrier_review_ready: closure_verdict === 'carrier_review_ready',
    receipt_presence,
    chain_enforcement: input.chain_enforcement,
    chain_enforcement_advisory,
    channel_provenance_advisory,
    composition_guidance,
    export_hints: input.export_hints,
    set_completeness_ok: input.set_completeness_ok,
    note,
  };

  return {
    ...withoutDigest,
    closure_digest: computeClosureDigest(withoutDigest),
  };
}

export function verifySessionCompositionClosure(
  closure: unknown,
  expected?: BuildSessionCompositionClosureInput & {
    chain_enforcement: ChainEnforcementRollupResult | null;
    export_hints: SessionProofExportHints | null;
  },
): { ok: boolean; errors: string[] } {
  const errors: string[] = [];
  if (!isRecord(closure)) {
    return { ok: false, errors: ['closure must be an object'] };
  }
  if (closure.schema !== SESSION_COMPOSITION_CLOSURE_SCHEMA) {
    errors.push(`schema must be ${SESSION_COMPOSITION_CLOSURE_SCHEMA}`);
  }
  if (!CLOSURE_VERDICTS.includes(closure.closure_verdict as ClosureVerdict)) {
    errors.push('invalid closure_verdict');
  }
  if (expected) {
    const recomputed = buildSessionCompositionClosure(expected);
    if (closure.closure_digest !== recomputed.closure_digest) {
      errors.push('closure_digest mismatch — tamper or stale export');
    }
    if (closure.closure_verdict !== recomputed.closure_verdict) {
      errors.push('closure_verdict mismatch');
    }
  }
  return { ok: errors.length === 0, errors };
}
