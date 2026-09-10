import { sha256HexUtf8 } from './sha256.js';
import { stableStringify } from './stableStringify.js';
import {
  buildInterceptDecisionEnvelopeDigest,
  canonicalizeInterceptDecisionEnvelope,
  type InterceptDecisionEnvelope,
  type InterceptDecisionValue,
  type InterceptToolCallFacts,
  type InterceptVendorAdapterId,
} from './interceptDecisionAdapter.js';

/** Wave 14 Track A — intercept decision attestation (INT-01). */

export const INTERCEPT_DECISION_ATTESTATION_SCHEMA =
  'aevesa.intercept-decision-attestation/v1' as const;

export type InterceptReadiness = 'intercept_notary_ready' | 'partial' | 'unverified';

export interface WitnessAnchorRef {
  inclusion_proof_uri?: string | null;
  witness_log_id?: string | null;
  anchor_digest?: string | null;
}

export interface AttestationAssertionsInput {
  third_party_verifiable: boolean;
  policy_bound?: boolean;
}

export interface InterceptSessionBinding {
  session_id: string;
  decision_digest: string;
  gateway_event_hash: string | null;
  normalization_bound: boolean;
}

export interface InterceptDecisionAttestationInput {
  organization_id: string;
  session_id: string;
  generated_at?: string;
  vendor_adapter_id: InterceptVendorAdapterId;
  vendor_decision_id: string;
  decision: InterceptDecisionValue;
  evaluated_at: string;
  decision_digest: string;
  policy_digest: string | null;
  tool_call_facts: InterceptToolCallFacts;
  intercept_context_digest: string;
  gateway_event_hash?: string | null;
  witness_anchor?: WitnessAnchorRef | null;
  attestation_assertions: AttestationAssertionsInput;
  session_binding: InterceptSessionBinding;
  disclaimer?: string;
}

export function deriveInterceptReadiness(
  decisionDigestMatches: boolean,
  policyBound: boolean,
  thirdPartyVerifiable: boolean,
  normalizationBound: boolean,
  gatewayLinked: boolean,
): InterceptReadiness {
  if (
    decisionDigestMatches
    && thirdPartyVerifiable
    && normalizationBound
    && policyBound
    && gatewayLinked
  ) {
    return 'intercept_notary_ready';
  }
  if (decisionDigestMatches && thirdPartyVerifiable && normalizationBound) {
    return 'partial';
  }
  return 'unverified';
}

export function buildAttestationAssertionsBlock(
  input: AttestationAssertionsInput,
  decisionDigestMatches: boolean,
  policyDigestPresent: boolean,
  normalizationBound: boolean,
  gatewayEventHashPresent: boolean,
) {
  const policy_bound = input.policy_bound !== false && policyDigestPresent;
  const intercept_readiness = deriveInterceptReadiness(
    decisionDigestMatches,
    policy_bound,
    input.third_party_verifiable === true,
    normalizationBound,
    gatewayEventHashPresent,
  );

  return {
    third_party_verifiable: input.third_party_verifiable === true,
    decision_digest_matches: decisionDigestMatches,
    policy_bound,
    intercept_readiness,
  };
}

export function buildInterceptDecisionAttestationPreimage(
  input: Omit<InterceptDecisionAttestationInput, 'disclaimer' | 'attestation_assertions'> & {
    generated_at: string;
    attestation_assertions: ReturnType<typeof buildAttestationAssertionsBlock>;
  },
): Record<string, unknown> {
  const binding = input.session_binding;
  const witness = input.witness_anchor ?? null;

  return {
    schema: INTERCEPT_DECISION_ATTESTATION_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    session_id: String(input.session_id || '').trim(),
    generated_at: input.generated_at,
    vendor_adapter_id: input.vendor_adapter_id,
    vendor_decision_id: String(input.vendor_decision_id || '').trim(),
    decision: input.decision,
    evaluated_at: String(input.evaluated_at || '').trim(),
    decision_digest: String(input.decision_digest || '').trim().toLowerCase(),
    policy_digest: input.policy_digest
      ? String(input.policy_digest).trim().toLowerCase()
      : null,
    tool_call_facts: {
      tool_name_digest: String(input.tool_call_facts.tool_name_digest || '').toLowerCase(),
      arguments_digest: input.tool_call_facts.arguments_digest
        ? String(input.tool_call_facts.arguments_digest).toLowerCase()
        : null,
      agent_identity_digest: String(input.tool_call_facts.agent_identity_digest || '').toLowerCase(),
    },
    intercept_context_digest: String(input.intercept_context_digest || '').toLowerCase(),
    gateway_event_hash: input.gateway_event_hash
      ? String(input.gateway_event_hash).toLowerCase()
      : null,
    witness_anchor: witness
      ? {
          inclusion_proof_uri: witness.inclusion_proof_uri ?? null,
          witness_log_id: witness.witness_log_id ?? null,
          anchor_digest: witness.anchor_digest
            ? String(witness.anchor_digest).toLowerCase()
            : null,
        }
      : null,
    attestation_assertions: input.attestation_assertions,
    session_binding: {
      session_id: String(binding.session_id || '').trim(),
      decision_digest: String(binding.decision_digest || '').trim().toLowerCase(),
      gateway_event_hash: binding.gateway_event_hash
        ? String(binding.gateway_event_hash).toLowerCase()
        : null,
      normalization_bound: binding.normalization_bound === true,
    },
  };
}

export interface InterceptDecisionAttestationDocument {
  schema: typeof INTERCEPT_DECISION_ATTESTATION_SCHEMA;
  organization_id: string;
  session_id: string;
  generated_at: string;
  vendor_adapter_id: InterceptVendorAdapterId;
  vendor_decision_id: string;
  decision: InterceptDecisionValue;
  evaluated_at: string;
  decision_digest: string;
  policy_digest: string | null;
  tool_call_facts: InterceptToolCallFacts;
  intercept_context_digest: string;
  gateway_event_hash: string | null;
  witness_anchor: WitnessAnchorRef | null;
  attestation_assertions: ReturnType<typeof buildAttestationAssertionsBlock>;
  session_binding: InterceptSessionBinding;
  attestation_digest: string;
  disclaimer: string;
}

export function buildInterceptDecisionAttestationFromEnvelope(
  envelope: InterceptDecisionEnvelope,
  input: {
    organization_id: string;
    session_id: string;
    generated_at?: string;
    attestation_assertions?: AttestationAssertionsInput;
    witness_anchor?: WitnessAnchorRef | null;
    disclaimer?: string;
  },
): InterceptDecisionAttestationDocument {
  const decision_digest = buildInterceptDecisionEnvelopeDigest(envelope);
  const generated_at = input.generated_at || new Date().toISOString();
  const gateway_event_hash = envelope.gateway_event_hash ?? null;

  const session_binding: InterceptSessionBinding = {
    session_id: String(input.session_id || '').trim(),
    decision_digest,
    gateway_event_hash,
    normalization_bound: true,
  };

  const attestation_assertions = buildAttestationAssertionsBlock(
    input.attestation_assertions ?? { third_party_verifiable: true, policy_bound: true },
    true,
    envelope.policy_digest != null,
    true,
    gateway_event_hash != null,
  );

  const preimage = buildInterceptDecisionAttestationPreimage({
    organization_id: input.organization_id,
    session_id: input.session_id,
    generated_at,
    vendor_adapter_id: envelope.vendor_adapter_id,
    vendor_decision_id: envelope.vendor_decision_id,
    decision: envelope.decision,
    evaluated_at: envelope.evaluated_at,
    decision_digest,
    policy_digest: envelope.policy_digest,
    tool_call_facts: envelope.tool_call_facts,
    intercept_context_digest: envelope.intercept_context_digest,
    gateway_event_hash,
    witness_anchor: input.witness_anchor ?? null,
    attestation_assertions,
    session_binding,
  });

  const attestation_digest = sha256HexUtf8(stableStringify(preimage));

  return {
    ...(preimage as Omit<InterceptDecisionAttestationDocument, 'attestation_digest' | 'disclaimer'>),
    attestation_digest,
    disclaimer:
      input.disclaimer ??
      'Intercept decision attestation — third-party offline verify; not legal advice.',
  };
}

export function buildInterceptDecisionAttestationDocument(
  input: InterceptDecisionAttestationInput,
): InterceptDecisionAttestationDocument {
  const generated_at = input.generated_at || new Date().toISOString();
  const recomputedDecisionDigest = recomputeDecisionDigestFromAttestation({
    vendor_adapter_id: input.vendor_adapter_id,
    vendor_decision_id: input.vendor_decision_id,
    decision: input.decision,
    evaluated_at: input.evaluated_at,
    tool_call_facts: input.tool_call_facts,
    intercept_context_digest: input.intercept_context_digest,
    policy_digest: input.policy_digest,
    gateway_event_hash: input.gateway_event_hash ?? null,
  });
  const decisionDigestMatches =
    recomputedDecisionDigest === String(input.decision_digest || '').trim().toLowerCase();
  const attestation_assertions = buildAttestationAssertionsBlock(
    input.attestation_assertions,
    decisionDigestMatches,
    input.policy_digest != null,
    input.session_binding.normalization_bound === true,
    input.gateway_event_hash != null,
  );

  const preimage = buildInterceptDecisionAttestationPreimage({
    ...input,
    generated_at,
    attestation_assertions,
  });
  const attestation_digest = sha256HexUtf8(stableStringify(preimage));

  return {
    ...(preimage as Omit<InterceptDecisionAttestationDocument, 'attestation_digest' | 'disclaimer'>),
    attestation_digest,
    disclaimer:
      input.disclaimer ??
      'Intercept decision attestation — third-party offline verify; not legal advice.',
  };
}

export function envelopeFromAttestationFields(
  doc: Pick<
    InterceptDecisionAttestationDocument,
    | 'vendor_adapter_id'
    | 'vendor_decision_id'
    | 'decision'
    | 'evaluated_at'
    | 'tool_call_facts'
    | 'intercept_context_digest'
    | 'policy_digest'
    | 'gateway_event_hash'
  >,
): InterceptDecisionEnvelope {
  return {
    vendor_adapter_id: doc.vendor_adapter_id,
    vendor_decision_id: doc.vendor_decision_id,
    decision: doc.decision,
    evaluated_at: doc.evaluated_at,
    tool_call_facts: doc.tool_call_facts,
    intercept_context_digest: doc.intercept_context_digest,
    policy_digest: doc.policy_digest,
    gateway_event_hash: doc.gateway_event_hash,
  };
}

export function recomputeDecisionDigestFromAttestation(
  doc: Pick<
    InterceptDecisionAttestationDocument,
    | 'vendor_adapter_id'
    | 'vendor_decision_id'
    | 'decision'
    | 'evaluated_at'
    | 'tool_call_facts'
    | 'intercept_context_digest'
    | 'policy_digest'
    | 'gateway_event_hash'
  >,
): string {
  return buildInterceptDecisionEnvelopeDigest(envelopeFromAttestationFields(doc));
}

export default {
  INTERCEPT_DECISION_ATTESTATION_SCHEMA,
  buildInterceptDecisionAttestationDocument,
  buildInterceptDecisionAttestationFromEnvelope,
  buildInterceptDecisionAttestationPreimage,
  buildAttestationAssertionsBlock,
  deriveInterceptReadiness,
  recomputeDecisionDigestFromAttestation,
  envelopeFromAttestationFields,
  canonicalizeInterceptDecisionEnvelope,
};
