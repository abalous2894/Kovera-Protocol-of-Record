import { sha256HexUtf8 } from './sha256.js';
import { stableStringify } from './stableStringify.js';

/** Track AE — Declared Adaptation Envelope (Art. 43(4) pre-determined changes; draft until design partner review). */

export const DECLARED_ADAPTATION_ENVELOPE_SCHEMA =
  'aevesa.declared-adaptation-envelope/v1-draft' as const;

export const DECLARED_ADAPTATION_ENVELOPE_SKU =
  'aevesa-declared-adaptation-envelope-v1-draft' as const;

export const ADAPTATION_OPERATOR_ROLES = ['provider', 'deployer'] as const;
export type AdaptationOperatorRole = (typeof ADAPTATION_OPERATOR_ROLES)[number];

/** Amendment A2 — one schema, multiple regulatory framings (sorted in preimage). */
export const ADAPTATION_REGULATORY_FRAMINGS = [
  'eu_art_43_4_envelope',
  'eu_art_26_monitoring',
  'naic_exhibit_c_drift',
  'owasp_level_3_governance',
] as const;
export type AdaptationRegulatoryFraming = (typeof ADAPTATION_REGULATORY_FRAMINGS)[number];

export const ADAPTATION_BREACH_ACTIONS = [
  'signal_substantial_modification',
  'alert_only',
  'auto_revert',
] as const;
export type AdaptationBreachAction = (typeof ADAPTATION_BREACH_ACTIONS)[number];

export interface AdaptationBounds {
  policy_hash: string;
  tool_catalog_fingerprint: string;
  memory_root_hash?: string | null;
  mcp_manifest_fingerprint?: string | null;
  tool_allowlist_digest?: string | null;
}

export interface AdaptationDriftThreshold {
  metric_id: string;
  max_delta?: number | null;
  max_absolute?: number | null;
  breach_action: AdaptationBreachAction;
}

export interface AdaptationReversionRules {
  auto_revert_on_breach: boolean;
  revert_to_baseline_entry_hash?: string | null;
  human_review_gate_id?: string | null;
}

export interface AdaptationHumanReviewGate {
  gate_id: string;
  label: string;
  required_for_metrics?: string[];
}

export interface AdaptationComposedMemberDigests {
  behavioral_sbom_digest?: string | null;
  memory_commitment_profile_digest?: string | null;
  mcp_manifest_bind_digest?: string | null;
}

export interface DeclaredAdaptationEnvelopeInput {
  organization_id: string;
  system_id: string;
  operator_role: AdaptationOperatorRole;
  regulatory_framings: AdaptationRegulatoryFraming[];
  declared_at?: string;
  bounds: AdaptationBounds;
  monitored_metrics: string[];
  drift_thresholds: AdaptationDriftThreshold[];
  reversion_rules: AdaptationReversionRules;
  human_review_gates?: AdaptationHumanReviewGate[];
  composed_member_digests?: AdaptationComposedMemberDigests | null;
  conformity_baseline_id?: string | null;
  envelope_entry_hash?: string | null;
  disclaimer?: string;
}

export interface RuntimeAdaptationSnapshot {
  observed_at: string;
  bounds: Partial<AdaptationBounds>;
  metric_values?: Record<string, number>;
}

export interface AdaptationDriftBreach {
  kind: 'bound_mismatch' | 'metric_threshold';
  field?: string;
  metric_id?: string;
  expected?: string | number;
  observed?: string | number;
  breach_action?: AdaptationBreachAction;
}

export interface AdaptationDriftEvaluation {
  status: 'inside_envelope' | 'breach' | 'insufficient_snapshot';
  breaches: AdaptationDriftBreach[];
  code: 'INSIDE_ENVELOPE' | 'ENVELOPE_BREACH' | 'INSUFFICIENT_SNAPSHOT';
}

const BOUND_DIGEST_FIELDS: (keyof AdaptationBounds)[] = [
  'policy_hash',
  'tool_catalog_fingerprint',
  'memory_root_hash',
  'mcp_manifest_fingerprint',
  'tool_allowlist_digest',
];

function normalizeHex64(value: unknown): string | null {
  const s = String(value || '').trim().toLowerCase();
  return /^[a-f0-9]{64}$/.test(s) ? s : null;
}

function normalizeBounds(bounds: AdaptationBounds): Record<string, unknown> {
  const out: Record<string, unknown> = {
    policy_hash: normalizeHex64(bounds.policy_hash) || String(bounds.policy_hash || '').trim().toLowerCase(),
    tool_catalog_fingerprint:
      normalizeHex64(bounds.tool_catalog_fingerprint)
      || String(bounds.tool_catalog_fingerprint || '').trim().toLowerCase(),
  };
  const memory = bounds.memory_root_hash != null ? normalizeHex64(bounds.memory_root_hash) : null;
  if (memory) out.memory_root_hash = memory;
  const mcp = bounds.mcp_manifest_fingerprint != null ? normalizeHex64(bounds.mcp_manifest_fingerprint) : null;
  if (mcp) out.mcp_manifest_fingerprint = mcp;
  const allow = bounds.tool_allowlist_digest != null ? normalizeHex64(bounds.tool_allowlist_digest) : null;
  if (allow) out.tool_allowlist_digest = allow;
  return out;
}

function sortFramings(framings: string[]): string[] {
  return [...framings]
    .map((f) => String(f || '').trim())
    .filter((f) => ADAPTATION_REGULATORY_FRAMINGS.includes(f as AdaptationRegulatoryFraming))
    .sort();
}

function sortMetrics(metrics: string[]): string[] {
  return [...metrics].map((m) => String(m || '').trim()).filter(Boolean).sort();
}

function normalizeThresholds(thresholds: AdaptationDriftThreshold[]): Record<string, unknown>[] {
  return [...thresholds]
    .map((t) => ({
      metric_id: String(t.metric_id || '').trim(),
      ...(t.max_delta != null ? { max_delta: Number(t.max_delta) } : {}),
      ...(t.max_absolute != null ? { max_absolute: Number(t.max_absolute) } : {}),
      breach_action: ADAPTATION_BREACH_ACTIONS.includes(t.breach_action as AdaptationBreachAction)
        ? t.breach_action
        : 'alert_only',
    }))
    .filter((t) => t.metric_id.length > 0)
    .sort((a, b) => String(a.metric_id).localeCompare(String(b.metric_id)));
}

function normalizeReviewGates(gates?: AdaptationHumanReviewGate[]): Record<string, unknown>[] {
  return [...(gates || [])]
    .map((g) => ({
      gate_id: String(g.gate_id || '').trim(),
      label: String(g.label || '').trim(),
      ...(Array.isArray(g.required_for_metrics) && g.required_for_metrics.length > 0
        ? { required_for_metrics: sortMetrics(g.required_for_metrics) }
        : {}),
    }))
    .filter((g) => g.gate_id.length > 0)
    .sort((a, b) => String(a.gate_id).localeCompare(String(b.gate_id)));
}

/**
 * Deterministic envelope preimage — excludes envelope_entry_hash and envelope_digest.
 */
export function buildDeclaredAdaptationEnvelopePreimage(
  input: DeclaredAdaptationEnvelopeInput,
): Record<string, unknown> {
  const composed = input.composed_member_digests;
  const composedBlock =
    composed && typeof composed === 'object'
      ? {
          ...(composed.behavioral_sbom_digest
            ? { behavioral_sbom_digest: normalizeHex64(composed.behavioral_sbom_digest) }
            : {}),
          ...(composed.memory_commitment_profile_digest
            ? {
                memory_commitment_profile_digest: normalizeHex64(
                  composed.memory_commitment_profile_digest,
                ),
              }
            : {}),
          ...(composed.mcp_manifest_bind_digest
            ? { mcp_manifest_bind_digest: normalizeHex64(composed.mcp_manifest_bind_digest) }
            : {}),
        }
      : null;

  return {
    schema: DECLARED_ADAPTATION_ENVELOPE_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    system_id: String(input.system_id || '').trim(),
    operator_role: input.operator_role,
    regulatory_framings: sortFramings(input.regulatory_framings),
    declared_at: input.declared_at || new Date(0).toISOString(),
    bounds: normalizeBounds(input.bounds),
    monitored_metrics: sortMetrics(input.monitored_metrics),
    drift_thresholds: normalizeThresholds(input.drift_thresholds || []),
    reversion_rules: {
      auto_revert_on_breach: input.reversion_rules?.auto_revert_on_breach === true,
      ...(input.reversion_rules?.revert_to_baseline_entry_hash
        ? {
            revert_to_baseline_entry_hash: normalizeHex64(
              input.reversion_rules.revert_to_baseline_entry_hash,
            ),
          }
        : {}),
      ...(input.reversion_rules?.human_review_gate_id
        ? { human_review_gate_id: String(input.reversion_rules.human_review_gate_id).trim() }
        : {}),
    },
    human_review_gates: normalizeReviewGates(input.human_review_gates),
    composed_member_digests: composedBlock,
    conformity_baseline_id: input.conformity_baseline_id
      ? String(input.conformity_baseline_id).trim()
      : null,
    disclaimer:
      input.disclaimer
      || 'Declared adaptation envelope evidence only — not legal advice, conformity certification, or CE marking.',
  };
}

export function buildDeclaredAdaptationEnvelopeDocument(input: DeclaredAdaptationEnvelopeInput) {
  const declared_at = input.declared_at || new Date().toISOString();
  const preimage = buildDeclaredAdaptationEnvelopePreimage({ ...input, declared_at });
  const envelope_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    envelope_entry_hash: input.envelope_entry_hash ?? null,
    envelope_digest,
  };
}

/**
 * Amendment A1 — deployer artifacts must not claim Art. 43(4) envelope conformity without Art. 26 monitoring framing.
 */
export function validateAdaptationOperatorFraming(input: {
  operator_role?: string;
  regulatory_framings?: string[];
}): { valid: boolean; code: string | null } {
  const role = String(input.operator_role || '').trim();
  const framings = sortFramings(input.regulatory_framings || []);
  if (role === 'deployer') {
    const claimsArt434 = framings.includes('eu_art_43_4_envelope');
    const hasArt26 = framings.includes('eu_art_26_monitoring');
    if (claimsArt434 && !hasArt26) {
      return { valid: false, code: 'DEPLOYER_ART43_FRAMING_INVALID' };
    }
  }
  if (role === 'provider' && framings.length === 0) {
    return { valid: false, code: 'PROVIDER_FRAMING_REQUIRED' };
  }
  return { valid: true, code: null };
}

/**
 * Compare runtime snapshot against declared envelope bounds and metric thresholds (pure — no I/O).
 */
export function evaluateAdaptationEnvelopeDrift(
  envelope: { bounds?: AdaptationBounds; drift_thresholds?: AdaptationDriftThreshold[] },
  snapshot: RuntimeAdaptationSnapshot,
): AdaptationDriftEvaluation {
  const bounds = envelope.bounds;
  if (!bounds || !snapshot?.observed_at) {
    return { status: 'insufficient_snapshot', breaches: [], code: 'INSUFFICIENT_SNAPSHOT' };
  }

  const breaches: AdaptationDriftBreach[] = [];
  let comparedBound = false;

  for (const field of BOUND_DIGEST_FIELDS) {
    const expectedRaw = bounds[field];
    if (expectedRaw == null || String(expectedRaw).trim() === '') continue;
    const expected = String(expectedRaw).trim().toLowerCase();
    const observedRaw = snapshot.bounds?.[field];
    if (observedRaw == null || String(observedRaw).trim() === '') continue;
    comparedBound = true;
    const observed = String(observedRaw).trim().toLowerCase();
    if (observed !== expected) {
      breaches.push({
        kind: 'bound_mismatch',
        field,
        expected,
        observed,
      });
    }
  }

  for (const threshold of envelope.drift_thresholds || []) {
    const metricId = String(threshold.metric_id || '').trim();
    if (!metricId) continue;
    const observedVal = snapshot.metric_values?.[metricId];
    if (observedVal == null || Number.isNaN(Number(observedVal))) continue;
    comparedBound = true;
    const val = Number(observedVal);
    if (threshold.max_absolute != null && val > Number(threshold.max_absolute)) {
      breaches.push({
        kind: 'metric_threshold',
        metric_id: metricId,
        expected: threshold.max_absolute,
        observed: val,
        breach_action: threshold.breach_action,
      });
    }
  }

  if (!comparedBound) {
    return { status: 'insufficient_snapshot', breaches: [], code: 'INSUFFICIENT_SNAPSHOT' };
  }

  if (breaches.length > 0) {
    return { status: 'breach', breaches, code: 'ENVELOPE_BREACH' };
  }
  return { status: 'inside_envelope', breaches: [], code: 'INSIDE_ENVELOPE' };
}
