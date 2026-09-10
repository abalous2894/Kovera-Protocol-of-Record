import { sha256HexUtf8 } from '../core/sha256.js';
import { REASONING_BASELINE_RECEIPT_SCHEMA, buildReasoningBaselinePreimage } from '../core/reasoningBaselineReceipt.js';
import { stableStringify } from '../core/stableStringify.js';
import type {
  ReasoningBaselineSnapshot,
  ReasoningMaterialDecision,
} from '../core/reasoningBaselineReceipt.js';

export const REASONING_BASELINE_RECEIPT_SKU = 'aevesa-reasoning-baseline-receipt-v1' as const;

const HEX64 = /^[a-f0-9]{64}$/;
const FORBIDDEN_KEYS =
  /^(chain_of_thought|reasoning_trace|llm_output|prompt|raw_payload|user_message|assistant_message|model_rationale)$/i;

export interface ReasoningBaselineReceiptVerifyChecks {
  schemaValid: boolean;
  sessionIdPresent: boolean;
  organizationIdPresent: boolean;
  receiptDigestMatches: boolean;
  baselineDigestValid: boolean;
  materialDecisionsPresent: boolean;
  baselinePointersConsistent: boolean;
  deviationsWellFormed: boolean;
  reasoningSafeSurface: boolean;
  profileComplete: boolean;
}

export interface ReasoningBaselineReceiptVerifyResult {
  schema: typeof REASONING_BASELINE_RECEIPT_SCHEMA;
  sku: typeof REASONING_BASELINE_RECEIPT_SKU;
  ok: boolean;
  checks: ReasoningBaselineReceiptVerifyChecks;
  materialDecisionCount: number;
  deviationCount: number;
  gtmLine: string;
  note: string | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function hasForbiddenKeys(value: unknown, depth = 0): boolean {
  if (depth > 8 || value == null) return false;
  if (Array.isArray(value)) {
    return value.some((v) => hasForbiddenKeys(v, depth + 1));
  }
  if (typeof value !== 'object') return false;
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (FORBIDDEN_KEYS.test(key)) return true;
    if (hasForbiddenKeys(child, depth + 1)) return true;
  }
  return false;
}

function parseBaseline(raw: unknown): ReasoningBaselineSnapshot | null {
  const b = asRecord(raw);
  if (!b) return null;
  return {
    baseline_id: String(b.baseline_id || '').trim(),
    baseline_kind:
      b.baseline_kind === 'institutional_playbook' ? 'institutional_playbook' : 'policy_ontology',
    baseline_digest: String(b.baseline_digest || '').trim().toLowerCase(),
    ontology_version: String(b.ontology_version || '').trim(),
    regulatory_frame:
      b.regulatory_frame === 'SR_11_7' ||
      b.regulatory_frame === 'ECOA' ||
      b.regulatory_frame === 'EU_AI_ACT' ||
      b.regulatory_frame === 'GENERIC'
        ? b.regulatory_frame
        : null,
    captured_at: String(b.captured_at || ''),
    term_set_digest:
      b.term_set_digest != null ? String(b.term_set_digest).trim().toLowerCase() : null,
  };
}

function parseDecisions(raw: unknown): ReasoningMaterialDecision[] {
  if (!Array.isArray(raw)) return [];
  return raw.map((row, index) => {
    const d = asRecord(row);
    const dev = asRecord(d?.deviation);
    return {
      sequence: Number(d?.sequence ?? index + 1),
      entry_hash: String(d?.entry_hash || '').trim().toLowerCase(),
      tool_name: String(d?.tool_name || '').trim(),
      decision_at: String(d?.decision_at || ''),
      baseline_pointer: String(d?.baseline_pointer || '').trim().toLowerCase(),
      deviation: {
        declared: dev?.declared === true,
        deviation_class:
          dev?.deviation_class === 'term_substitution' ||
          dev?.deviation_class === 'policy_exception' ||
          dev?.deviation_class === 'ontology_drift'
            ? dev.deviation_class
            : null,
        deviation_digest:
          dev?.deviation_digest != null ? String(dev.deviation_digest).trim().toLowerCase() : null,
        declared_term: dev?.declared_term != null ? String(dev.declared_term).trim() : null,
      },
    };
  });
}

/**
 * Verify reasoning baseline receipt — institutional baseline hash + material decision pointers.
 * Does not judge model quality; proves which baseline governed each material tool decision.
 */
export function verifyReasoningBaselineReceipt(input: unknown): ReasoningBaselineReceiptVerifyResult {
  const doc = asRecord(input);
  const schemaValid = doc?.schema === REASONING_BASELINE_RECEIPT_SCHEMA;

  const session_id = String(doc?.session_id || '').trim();
  const sessionIdPresent = session_id.length > 0;

  const organization_id = String(doc?.organization_id || '').trim();
  const organizationIdPresent = organization_id.length > 0;

  const baseline = parseBaseline(doc?.baseline);
  const baselineDigestValid =
    baseline != null &&
    baseline.baseline_id.length > 0 &&
    HEX64.test(baseline.baseline_digest) &&
    baseline.ontology_version.length > 0;

  const material_decisions = parseDecisions(doc?.material_decisions);
  const materialDecisionsPresent = material_decisions.length > 0;

  let baselinePointersConsistent = false;
  let deviationsWellFormed = true;
  let deviationCount = 0;

  if (baselineDigestValid && materialDecisionsPresent) {
    baselinePointersConsistent = material_decisions.every((d) => {
      if (!HEX64.test(d.entry_hash) || !d.tool_name) return false;
      if (d.deviation.declared) {
        deviationCount += 1;
        if (!d.deviation.deviation_class || !HEX64.test(String(d.deviation.deviation_digest || ''))) {
          deviationsWellFormed = false;
          return false;
        }
        return (
          HEX64.test(d.baseline_pointer) &&
          d.baseline_pointer !== baseline!.baseline_digest
        );
      }
      return d.baseline_pointer === baseline!.baseline_digest;
    });
  }

  let receiptDigestMatches = false;
  if (schemaValid && baseline && doc) {
    const preimage = buildReasoningBaselinePreimage({
      session_id,
      organization_id,
      minted_at: String(doc.minted_at || ''),
      baseline,
      material_decisions,
      receipt_entry_hashes: Array.isArray(doc.receipt_entry_hashes)
        ? doc.receipt_entry_hashes.map(String)
        : [],
      liability_receipt_profile:
        doc.liability_receipt_profile === 'PERMITTED' ||
        doc.liability_receipt_profile === 'DENIED' ||
        doc.liability_receipt_profile === 'HITL_RELEASED'
          ? doc.liability_receipt_profile
          : null,
      verify_manifest: asRecord(doc.verify_manifest) as never,
      non_goals: Array.isArray(doc.non_goals) ? doc.non_goals.map(String) : [],
    });
    const expected = sha256HexUtf8(stableStringify(preimage));
    receiptDigestMatches = String(doc.receipt_digest || '').trim().toLowerCase() === expected;
  }

  const reasoningSafeSurface =
    !hasForbiddenKeys(doc) &&
    (Array.isArray(doc?.receipt_entry_hashes) ? doc.receipt_entry_hashes : []).every((h) =>
      HEX64.test(String(h)),
    );

  const profileComplete =
    schemaValid &&
    sessionIdPresent &&
    organizationIdPresent &&
    receiptDigestMatches &&
    baselineDigestValid &&
    materialDecisionsPresent &&
    baselinePointersConsistent &&
    deviationsWellFormed &&
    reasoningSafeSurface;

  let note: string | null = null;
  if (!schemaValid) note = `schema must be ${REASONING_BASELINE_RECEIPT_SCHEMA}`;
  else if (!baselineDigestValid) note = 'baseline.baseline_digest and ontology_version required';
  else if (!materialDecisionsPresent) note = 'at least one material_decisions row required';
  else if (!baselinePointersConsistent) {
    note =
      'aligned decisions must reference baseline_digest; declared deviations must use distinct baseline_pointer';
  } else if (!deviationsWellFormed) {
    note = 'declared deviations require deviation_class and deviation_digest (hash-only attestation)';
  } else if (!receiptDigestMatches) note = 'receipt_digest does not match canonical preimage';
  else if (!reasoningSafeSurface) {
    note = 'forbidden reasoning/LLM content keys or invalid receipt entry hash';
  }

  return {
    schema: REASONING_BASELINE_RECEIPT_SCHEMA,
    sku: REASONING_BASELINE_RECEIPT_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      sessionIdPresent,
      organizationIdPresent,
      receiptDigestMatches,
      baselineDigestValid,
      materialDecisionsPresent,
      baselinePointersConsistent,
      deviationsWellFormed,
      reasoningSafeSurface,
      profileComplete,
    },
    materialDecisionCount: material_decisions.length,
    deviationCount,
    gtmLine:
      'Access control says the agent could act. Aevesa receipts which institutional baseline it acted against.',
    note,
  };
}
