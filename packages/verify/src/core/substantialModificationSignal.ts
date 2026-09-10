import { sha256HexUtf8 } from './sha256.js';
import { stableStringify } from './stableStringify.js';
import type { ComposedMemberRef } from './deployerLogCustodyPack.js';
import {
  ADAPTATION_OPERATOR_ROLES,
  type AdaptationDriftBreach,
  type AdaptationOperatorRole,
} from './declaredAdaptationEnvelope.js';

/** Track AE PR3 — substantial modification breach pack (replayable receipts). */

export const SUBSTANTIAL_MODIFICATION_SIGNAL_SCHEMA =
  'aevesa.substantial-modification-signal/v1' as const;

export const SUBSTANTIAL_MODIFICATION_SIGNAL_SKU =
  'aevesa-substantial-modification-signal-v1' as const;

export interface ProviderSignalFraming {
  pack_kind: 'provider';
  eu_art_43_4_signal: {
    envelope_breach: boolean;
    pre_determined_change_exceeded: boolean;
    art_49_reregistration_hint: string;
  };
  eu_art_25_provider_context?: {
    technical_documentation_update_recommended: boolean;
  };
  owasp_level_3_governance?: {
    drift_outside_declared_envelope: boolean;
  };
}

export interface DeployerSignalFraming {
  pack_kind: 'deployer';
  eu_art_26_monitoring_signal: {
    post_market_drift_detected: boolean;
    monitoring_obligation_evidence: boolean;
  };
  naic_exhibit_c_drift?: {
    drift_signal_for_examiner: boolean;
  };
  owasp_level_3_governance?: {
    drift_outside_declared_envelope: boolean;
  };
}

export type SubstantialModificationSignalFraming = ProviderSignalFraming | DeployerSignalFraming;

export interface SubstantialModificationSignalInput {
  organization_id: string;
  system_id: string;
  operator_role: AdaptationOperatorRole;
  generated_at?: string;
  envelope_digest: string;
  envelope_entry_hash?: string | null;
  drift_witness_entry_hash?: string | null;
  drift_status: 'breach';
  breaches: AdaptationDriftBreach[];
  runtime_snapshot_digest: string;
  contributing_entry_hashes?: string[];
  composed_members: ComposedMemberRef[];
  regulatory_framing: SubstantialModificationSignalFraming;
  signal_entry_hash?: string | null;
  disclaimer?: string;
}

function normalizeHex64(value: unknown): string | null {
  const s = String(value || '').trim().toLowerCase();
  return /^[a-f0-9]{64}$/.test(s) ? s : null;
}

function sortEntryHashes(hashes: string[] | undefined): string[] {
  return [...(hashes || [])]
    .map((h) => String(h || '').trim().toLowerCase())
    .filter((h) => /^[a-f0-9]{64}$/.test(h))
    .sort();
}

function normalizeComposedMembers(members: ComposedMemberRef[]): Record<string, unknown>[] {
  return [...(members || [])]
    .map((m) => ({
      member_schema: String(m.member_schema || '').trim(),
      member_digest: normalizeHex64(m.member_digest) || String(m.member_digest || '').trim().toLowerCase(),
      verify_ok: m.verify_ok === true,
      label: String(m.label || '').trim(),
      ...(m.entry_count != null ? { entry_count: Number(m.entry_count) } : {}),
    }))
    .filter((m) => m.member_schema.length > 0 && m.member_digest.length > 0)
    .sort((a, b) => String(a.member_schema).localeCompare(String(b.member_schema)));
}

function normalizeBreaches(breaches: AdaptationDriftBreach[]): Record<string, unknown>[] {
  return [...(breaches || [])]
    .map((b) => ({
      kind: b.kind,
      ...(b.field ? { field: String(b.field) } : {}),
      ...(b.metric_id ? { metric_id: String(b.metric_id) } : {}),
      ...(b.expected != null ? { expected: b.expected } : {}),
      ...(b.observed != null ? { observed: b.observed } : {}),
      ...(b.breach_action ? { breach_action: b.breach_action } : {}),
    }))
    .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
}

/**
 * Build role-specific regulatory framing from breach facts (Amendment A1).
 */
export function buildSubstantialModificationSignalFraming(input: {
  operator_role: AdaptationOperatorRole;
  breach_count: number;
  regulatory_framings?: string[];
}): SubstantialModificationSignalFraming {
  const breached = input.breach_count > 0;
  const role = input.operator_role;
  const framings = new Set((input.regulatory_framings || []).map(String));

  if (role === 'deployer') {
    return {
      pack_kind: 'deployer',
      eu_art_26_monitoring_signal: {
        post_market_drift_detected: breached,
        monitoring_obligation_evidence: true,
      },
      ...(framings.has('naic_exhibit_c_drift')
        ? { naic_exhibit_c_drift: { drift_signal_for_examiner: breached } }
        : {}),
      ...(framings.has('owasp_level_3_governance')
        ? { owasp_level_3_governance: { drift_outside_declared_envelope: breached } }
        : {}),
    };
  }

  return {
    pack_kind: 'provider',
    eu_art_43_4_signal: {
      envelope_breach: breached,
      pre_determined_change_exceeded: breached,
      art_49_reregistration_hint:
        'EU database re-registration under Art. 49 may apply — technical evidence signal only, not legal classification.',
    },
    eu_art_25_provider_context: {
      technical_documentation_update_recommended: breached,
    },
    ...(framings.has('owasp_level_3_governance')
      ? { owasp_level_3_governance: { drift_outside_declared_envelope: breached } }
      : {}),
  };
}

/**
 * Amendment A1 — provider and deployer breach packs must not share the same primary framing block.
 */
export function validateSubstantialModificationSignalFraming(input: {
  operator_role?: string;
  regulatory_framing?: SubstantialModificationSignalFraming | null;
}): { valid: boolean; code: string | null } {
  const role = String(input.operator_role || '').trim();
  const framing = input.regulatory_framing;
  if (!ADAPTATION_OPERATOR_ROLES.includes(role as AdaptationOperatorRole)) {
    return { valid: false, code: 'OPERATOR_ROLE_INVALID' };
  }
  if (!framing || typeof framing !== 'object') {
    return { valid: false, code: 'REGULATORY_FRAMING_REQUIRED' };
  }
  if (role === 'provider' && framing.pack_kind !== 'provider') {
    return { valid: false, code: 'PROVIDER_PACK_FRAMING_MISMATCH' };
  }
  if (role === 'deployer' && framing.pack_kind !== 'deployer') {
    return { valid: false, code: 'DEPLOYER_PACK_FRAMING_MISMATCH' };
  }
  if (role === 'deployer' && 'eu_art_43_4_signal' in framing) {
    return { valid: false, code: 'DEPLOYER_ART43_SIGNAL_INVALID' };
  }
  if (role === 'provider' && 'eu_art_26_monitoring_signal' in framing) {
    return { valid: false, code: 'PROVIDER_ART26_SIGNAL_INVALID' };
  }
  return { valid: true, code: null };
}

export function buildSubstantialModificationSignalPreimage(
  input: SubstantialModificationSignalInput,
): Record<string, unknown> {
  const generated_at = input.generated_at || new Date(0).toISOString();
  return {
    schema: SUBSTANTIAL_MODIFICATION_SIGNAL_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    system_id: String(input.system_id || '').trim(),
    operator_role: input.operator_role,
    generated_at,
    envelope_digest: normalizeHex64(input.envelope_digest) || String(input.envelope_digest || '').trim(),
    envelope_entry_hash: input.envelope_entry_hash ? normalizeHex64(input.envelope_entry_hash) : null,
    drift_witness_entry_hash: input.drift_witness_entry_hash
      ? normalizeHex64(input.drift_witness_entry_hash)
      : null,
    drift_status: 'breach',
    breaches: normalizeBreaches(input.breaches || []),
    runtime_snapshot_digest:
      normalizeHex64(input.runtime_snapshot_digest) || String(input.runtime_snapshot_digest || '').trim(),
    contributing_entry_hashes: sortEntryHashes(input.contributing_entry_hashes),
    composed_members: normalizeComposedMembers(input.composed_members || []),
    regulatory_framing: input.regulatory_framing,
    disclaimer:
      input.disclaimer
      || 'Substantial modification signal evidence only — not legal advice, conformity certification, or CE marking.',
  };
}

export function buildSubstantialModificationSignalDocument(input: SubstantialModificationSignalInput) {
  const generated_at = input.generated_at || new Date().toISOString();
  const preimage = buildSubstantialModificationSignalPreimage({ ...input, generated_at });
  const signal_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    signal_entry_hash: input.signal_entry_hash ?? null,
    signal_digest,
  };
}
