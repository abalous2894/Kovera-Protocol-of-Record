import { sha256HexUtf8 } from '../core/sha256.js';
import { stableStringify } from '../core/stableStringify.js';
import {
  ADAPTATION_OPERATOR_ROLES,
  ADAPTATION_REGULATORY_FRAMINGS,
  DECLARED_ADAPTATION_ENVELOPE_SCHEMA,
  DECLARED_ADAPTATION_ENVELOPE_SKU,
  buildDeclaredAdaptationEnvelopePreimage,
  validateAdaptationOperatorFraming,
  type AdaptationBounds,
  type AdaptationDriftThreshold,
  type AdaptationHumanReviewGate,
  type AdaptationOperatorRole,
  type AdaptationRegulatoryFraming,
  type AdaptationReversionRules,
} from '../core/declaredAdaptationEnvelope.js';

export interface DeclaredAdaptationEnvelopeDocument {
  schema?: string;
  organization_id?: string;
  system_id?: string;
  operator_role?: AdaptationOperatorRole;
  regulatory_framings?: AdaptationRegulatoryFraming[];
  declared_at?: string;
  bounds?: AdaptationBounds;
  monitored_metrics?: string[];
  drift_thresholds?: AdaptationDriftThreshold[];
  reversion_rules?: AdaptationReversionRules;
  human_review_gates?: AdaptationHumanReviewGate[];
  composed_member_digests?: Record<string, unknown> | null;
  conformity_baseline_id?: string | null;
  envelope_entry_hash?: string | null;
  envelope_digest?: string;
  disclaimer?: string;
}

export interface DeclaredAdaptationEnvelopeVerifyOptions {
  requireEnvelopeEntryHash?: boolean;
}

export interface DeclaredAdaptationEnvelopeVerifyResult {
  schema: typeof DECLARED_ADAPTATION_ENVELOPE_SCHEMA;
  sku: typeof DECLARED_ADAPTATION_ENVELOPE_SKU;
  ok: boolean;
  checks: {
    schemaValid: boolean;
    organizationIdPresent: boolean;
    systemIdPresent: boolean;
    operatorRoleValid: boolean;
    regulatoryFramingsValid: boolean;
    operatorFramingValid: boolean;
    boundsPresent: boolean;
    envelopeDigestMatches: boolean;
    envelopeEntryHashPresent: boolean;
    profileComplete: boolean;
  };
  gtmLine: string;
  note: string | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function isHex64(value: unknown): boolean {
  return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
}

export function verifyDeclaredAdaptationEnvelopeBundle(
  input: unknown,
  options: DeclaredAdaptationEnvelopeVerifyOptions = {},
): DeclaredAdaptationEnvelopeVerifyResult {
  const doc = asRecord(input) as DeclaredAdaptationEnvelopeDocument | null;
  const schemaValid = doc?.schema === DECLARED_ADAPTATION_ENVELOPE_SCHEMA;
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;
  const systemIdPresent = String(doc?.system_id || '').trim().length > 0;
  const operatorRoleValid = ADAPTATION_OPERATOR_ROLES.includes(
    doc?.operator_role as AdaptationOperatorRole,
  );

  const framings = Array.isArray(doc?.regulatory_framings) ? doc!.regulatory_framings : [];
  const regulatoryFramingsValid =
    framings.length > 0
    && framings.every((f) =>
      ADAPTATION_REGULATORY_FRAMINGS.includes(f as AdaptationRegulatoryFraming),
    );

  const framingEval = validateAdaptationOperatorFraming({
    operator_role: doc?.operator_role,
    regulatory_framings: framings.map(String),
  });
  const operatorFramingValid = framingEval.valid;

  const bounds = doc?.bounds;
  const boundsPresent =
    bounds != null
    && typeof bounds === 'object'
    && isHex64(bounds.policy_hash)
    && isHex64(bounds.tool_catalog_fingerprint);

  let envelopeDigestMatches = false;
  if (organizationIdPresent && systemIdPresent && operatorRoleValid && boundsPresent && doc?.declared_at) {
    const expected = sha256HexUtf8(
      stableStringify(
        buildDeclaredAdaptationEnvelopePreimage({
          organization_id: String(doc!.organization_id),
          system_id: String(doc!.system_id),
          operator_role: doc!.operator_role as AdaptationOperatorRole,
          regulatory_framings: framings as AdaptationRegulatoryFraming[],
          declared_at: String(doc!.declared_at),
          bounds: bounds as AdaptationBounds,
          monitored_metrics: Array.isArray(doc!.monitored_metrics)
            ? doc!.monitored_metrics.map(String)
            : [],
          drift_thresholds: Array.isArray(doc!.drift_thresholds)
            ? (doc!.drift_thresholds as AdaptationDriftThreshold[])
            : [],
          reversion_rules: (doc!.reversion_rules as AdaptationReversionRules) || {
            auto_revert_on_breach: false,
          },
          human_review_gates: Array.isArray(doc!.human_review_gates)
            ? (doc!.human_review_gates as AdaptationHumanReviewGate[])
            : [],
          composed_member_digests:
            doc!.composed_member_digests && typeof doc!.composed_member_digests === 'object'
              ? (doc!.composed_member_digests as Record<string, string | null>)
              : null,
          conformity_baseline_id: doc!.conformity_baseline_id ?? null,
          envelope_entry_hash: doc!.envelope_entry_hash ?? null,
          disclaimer: doc!.disclaimer,
        }),
      ),
    );
    envelopeDigestMatches = Boolean(doc!.envelope_digest) && doc!.envelope_digest === expected;
  }

  const envelopeEntryHashPresent =
    options.requireEnvelopeEntryHash !== true
    || (typeof doc?.envelope_entry_hash === 'string' && isHex64(doc.envelope_entry_hash));

  const profileComplete =
    schemaValid
    && organizationIdPresent
    && systemIdPresent
    && operatorRoleValid
    && regulatoryFramingsValid
    && operatorFramingValid
    && boundsPresent
    && envelopeDigestMatches
    && envelopeEntryHashPresent;

  const ok = profileComplete;

  let note: string | null = null;
  if (!schemaValid) note = 'Invalid or missing schema.';
  else if (!operatorFramingValid) note = framingEval.code;
  else if (!envelopeDigestMatches) note = 'Envelope digest mismatch — tamper or serialization drift.';
  else if (!boundsPresent) note = 'policy_hash and tool_catalog_fingerprint must be sha256 hex digests.';
  else if (!regulatoryFramingsValid) note = 'regulatory_framings must be non-empty known values.';

  const gtmLine = ok
    ? 'Declared adaptation envelope verified offline — pre-determined change bounds digest-bound at baseline.'
    : 'Declared adaptation envelope verification failed — envelope not independently verifiable.';

  return {
    schema: DECLARED_ADAPTATION_ENVELOPE_SCHEMA,
    sku: DECLARED_ADAPTATION_ENVELOPE_SKU,
    ok,
    checks: {
      schemaValid,
      organizationIdPresent,
      systemIdPresent,
      operatorRoleValid,
      regulatoryFramingsValid,
      operatorFramingValid,
      boundsPresent,
      envelopeDigestMatches,
      envelopeEntryHashPresent,
      profileComplete,
    },
    gtmLine,
    note,
  };
}
