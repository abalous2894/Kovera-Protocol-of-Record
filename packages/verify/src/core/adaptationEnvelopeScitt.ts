/** Track P9 — SCITT draft alignment for declared adaptation envelope lifecycle artifacts. */

export const SCITT_ADAPTATION_ENVELOPE_PROFILE = 'SCITT-adaptation-envelope-draft-01' as const;

export const SCITT_ADAPTATION_BREACH_PROFILE = 'SCITT-adaptation-breach-draft-01' as const;

export const SCITT_ADAPTATION_ENVELOPE_REFERENCE = 'draft-noa-scitt-ai-agent-receipt-01' as const;

export const SCITT_ADAPTATION_BREACH_REFERENCE = 'draft-emirdag-scitt-ai-agent-execution' as const;

export const AEVESA_ADAPTATION_ENVELOPE_STATEMENT_TYPE =
  'https://aevesa.com/statement/adaptation-envelope-mint/v1' as const;

export const AEVESA_SUBSTANTIAL_MODIFICATION_STATEMENT_TYPE =
  'https://aevesa.com/statement/substantial-modification-signal/v1' as const;

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function isHex64(value: unknown): boolean {
  return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
}

/**
 * Additive SCITT alignment block — does not participate in envelope_digest preimage.
 */
export function applyAdaptationEnvelopeScittAlignment(
  doc: Record<string, unknown>,
  context: { entry_hash?: string | null } = {},
): Record<string, unknown> {
  const bounds = asRecord(doc.bounds);
  return {
    ...doc,
    scitt_alignment: {
      profile: SCITT_ADAPTATION_ENVELOPE_PROFILE,
      mapping_version: '1.0',
      reference: SCITT_ADAPTATION_ENVELOPE_REFERENCE,
      scitt_statement_type: AEVESA_ADAPTATION_ENVELOPE_STATEMENT_TYPE,
      lifecycle_record: {
        agent_system_id: doc.system_id ?? null,
        organization_id: doc.organization_id ?? null,
        operator_role: doc.operator_role ?? null,
        declared_at: doc.declared_at ?? null,
        envelope_digest: doc.envelope_digest ?? null,
        entry_hash: context.entry_hash ?? doc.envelope_entry_hash ?? null,
        policy_hash: bounds?.policy_hash ?? null,
        tool_catalog_fingerprint: bounds?.tool_catalog_fingerprint ?? null,
      },
      evidence_custodian_role: 'transparency_service',
      compliance_mappings: [
        'EU AI Act Art. 43(4) pre-determined changes',
        'EU AI Act Art. 12 logging substrate',
        'RFC 9943 SCITT architecture',
        'OWASP Agentic AI Security v2.01 Level 3',
      ],
      mapped_fields: [
        'agent_system_id',
        'organization_id',
        'envelope_digest',
        'entry_hash',
        'policy_hash',
        'tool_catalog_fingerprint',
        'declared_at',
      ],
    },
  };
}

/**
 * Additive SCITT alignment for substantial modification breach packs.
 */
export function applySubstantialModificationScittAlignment(
  doc: Record<string, unknown>,
  context: { entry_hash?: string | null } = {},
): Record<string, unknown> {
  return {
    ...doc,
    scitt_alignment: {
      profile: SCITT_ADAPTATION_BREACH_PROFILE,
      mapping_version: '1.0',
      reference: SCITT_ADAPTATION_BREACH_REFERENCE,
      scitt_statement_type: AEVESA_SUBSTANTIAL_MODIFICATION_STATEMENT_TYPE,
      adaptation_breach_record: {
        agent_system_id: doc.system_id ?? null,
        organization_id: doc.organization_id ?? null,
        operator_role: doc.operator_role ?? null,
        envelope_digest: doc.envelope_digest ?? null,
        drift_status: doc.drift_status ?? null,
        signal_digest: doc.signal_digest ?? null,
        entry_hash: context.entry_hash ?? doc.signal_entry_hash ?? null,
        drift_witness_entry_hash: doc.drift_witness_entry_hash ?? null,
      },
      evidence_custodian_role: 'transparency_service',
      compliance_mappings: [
        'EU AI Act Art. 43(4) substantial modification signal',
        'EU AI Act Art. 49 database re-registration hint',
        'RFC 9943 SCITT architecture',
      ],
      mapped_fields: [
        'agent_system_id',
        'envelope_digest',
        'signal_digest',
        'entry_hash',
        'drift_witness_entry_hash',
      ],
    },
  };
}

export function validateAdaptationEnvelopeScittAlignment(block: unknown): {
  ok: boolean;
  code: string | null;
  errors: string[];
} {
  const errors: string[] = [];
  const alignment = asRecord(block);
  if (!alignment) {
    return { ok: false, code: 'SCITT_ALIGNMENT_MISSING', errors: ['scitt_alignment block required'] };
  }
  if (alignment.profile !== SCITT_ADAPTATION_ENVELOPE_PROFILE) {
    errors.push(`profile must be ${SCITT_ADAPTATION_ENVELOPE_PROFILE}`);
  }
  const lifecycle = asRecord(alignment.lifecycle_record);
  if (!lifecycle) {
    errors.push('lifecycle_record required');
  } else {
    if (!String(lifecycle.agent_system_id || '').trim()) errors.push('agent_system_id required');
    if (!isHex64(lifecycle.envelope_digest)) errors.push('envelope_digest must be sha256 hex');
    if (lifecycle.entry_hash != null && !isHex64(lifecycle.entry_hash)) {
      errors.push('entry_hash must be sha256 hex when present');
    }
  }
  if (alignment.evidence_custodian_role !== 'transparency_service') {
    errors.push('evidence_custodian_role must be transparency_service');
  }
  if (errors.length) {
    return { ok: false, code: 'SCITT_ADAPTATION_ENVELOPE_ALIGNMENT_INVALID', errors };
  }
  return { ok: true, code: 'SCITT_ADAPTATION_ENVELOPE_ALIGNMENT_VALID', errors: [] };
}

export function validateSubstantialModificationScittAlignment(block: unknown): {
  ok: boolean;
  code: string | null;
  errors: string[];
} {
  const errors: string[] = [];
  const alignment = asRecord(block);
  if (!alignment) {
    return { ok: false, code: 'SCITT_ALIGNMENT_MISSING', errors: ['scitt_alignment block required'] };
  }
  if (alignment.profile !== SCITT_ADAPTATION_BREACH_PROFILE) {
    errors.push(`profile must be ${SCITT_ADAPTATION_BREACH_PROFILE}`);
  }
  const breach = asRecord(alignment.adaptation_breach_record);
  if (!breach) {
    errors.push('adaptation_breach_record required');
  } else {
    if (!String(breach.agent_system_id || '').trim()) errors.push('agent_system_id required');
    if (!isHex64(breach.envelope_digest)) errors.push('envelope_digest must be sha256 hex');
    if (!isHex64(breach.signal_digest)) errors.push('signal_digest must be sha256 hex');
    if (breach.drift_status !== 'breach') errors.push('drift_status must be breach');
  }
  if (alignment.evidence_custodian_role !== 'transparency_service') {
    errors.push('evidence_custodian_role must be transparency_service');
  }
  if (errors.length) {
    return { ok: false, code: 'SCITT_ADAPTATION_BREACH_ALIGNMENT_INVALID', errors };
  }
  return { ok: true, code: 'SCITT_ADAPTATION_BREACH_ALIGNMENT_VALID', errors: [] };
}
