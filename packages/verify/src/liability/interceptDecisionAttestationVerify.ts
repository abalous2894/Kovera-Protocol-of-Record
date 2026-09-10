import { sha256HexUtf8 } from '../core/sha256.js';
import { stableStringify } from '../core/stableStringify.js';
import {
  buildInterceptDecisionAttestationPreimage,
  INTERCEPT_DECISION_ATTESTATION_SCHEMA,
  recomputeDecisionDigestFromAttestation,
  type InterceptReadiness,
} from '../core/interceptDecisionAttestation.js';
import { INTERCEPT_DECISION_VALUES, INTERCEPT_VENDOR_ADAPTER_IDS } from '../core/interceptDecisionAdapter.js';

export const INTERCEPT_DECISION_ATTESTATION_SKU = 'aevesa-intercept-decision-attestation-v1' as const;

const HEX64 = /^[a-f0-9]{64}$/;
const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|ssn|phone|address|pan|cvv)$/i;

export interface InterceptDecisionAttestationVerifyOptions {
  requireGatewayLink?: boolean;
}

export interface InterceptDecisionAttestationVerifyResult {
  schema: typeof INTERCEPT_DECISION_ATTESTATION_SCHEMA;
  sku: typeof INTERCEPT_DECISION_ATTESTATION_SKU;
  ok: boolean;
  checks: Record<string, boolean>;
  intercept_readiness: InterceptReadiness | null;
  profileComplete: boolean;
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
  if (Array.isArray(value)) return value.some((v) => hasForbiddenKeys(v, depth + 1));
  if (typeof value !== 'object') return false;
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (FORBIDDEN_KEYS.test(key)) return true;
    if (hasForbiddenKeys(child, depth + 1)) return true;
  }
  return false;
}

export function verifyInterceptDecisionAttestation(
  docInput: unknown,
  options: InterceptDecisionAttestationVerifyOptions = {},
): InterceptDecisionAttestationVerifyResult {
  const doc = asRecord(docInput);
  const schemaValid = doc?.schema === INTERCEPT_DECISION_ATTESTATION_SCHEMA;
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;
  const sessionIdPresent = String(doc?.session_id || '').trim().length > 0;
  const vendorAdapterValid = INTERCEPT_VENDOR_ADAPTER_IDS.includes(
    String(doc?.vendor_adapter_id || '') as (typeof INTERCEPT_VENDOR_ADAPTER_IDS)[number],
  );
  const decisionValid = INTERCEPT_DECISION_VALUES.includes(
    String(doc?.decision || '') as (typeof INTERCEPT_DECISION_VALUES)[number],
  );
  const vendorDecisionIdPresent = String(doc?.vendor_decision_id || '').trim().length > 0;
  const evaluatedAtPresent = String(doc?.evaluated_at || '').trim().length > 0;
  const generatedAtPresent = String(doc?.generated_at || '').trim().length > 0;

  const decisionDigestValid = HEX64.test(String(doc?.decision_digest || '').toLowerCase());
  const attestationDigestValid = HEX64.test(String(doc?.attestation_digest || '').toLowerCase());
  const interceptContextDigestValid = HEX64.test(
    String(doc?.intercept_context_digest || '').toLowerCase(),
  );

  const policyDigestRaw = doc?.policy_digest;
  const policyDigestValid =
    policyDigestRaw == null || HEX64.test(String(policyDigestRaw).toLowerCase());

  const gatewayHashRaw = doc?.gateway_event_hash;
  const gatewayEventHashValid =
    gatewayHashRaw == null || HEX64.test(String(gatewayHashRaw).toLowerCase());

  const facts = asRecord(doc?.tool_call_facts) || {};
  const toolNameDigestValid = HEX64.test(String(facts.tool_name_digest || '').toLowerCase());
  const agentDigestValid = HEX64.test(String(facts.agent_identity_digest || '').toLowerCase());
  const argumentsDigestRaw = facts.arguments_digest;
  const argumentsDigestValid =
    argumentsDigestRaw == null || HEX64.test(String(argumentsDigestRaw).toLowerCase());
  const toolCallFactsValid =
    toolNameDigestValid && agentDigestValid && argumentsDigestValid;

  const hashOnlySurface = doc != null && !hasForbiddenKeys(doc);

  const recomputedDecisionDigest = doc
    ? recomputeDecisionDigestFromAttestation({
        vendor_adapter_id: String(doc.vendor_adapter_id) as never,
        vendor_decision_id: String(doc.vendor_decision_id),
        decision: String(doc.decision) as never,
        evaluated_at: String(doc.evaluated_at),
        tool_call_facts: {
          tool_name_digest: String(facts.tool_name_digest || ''),
          arguments_digest:
            argumentsDigestRaw != null ? String(argumentsDigestRaw) : null,
          agent_identity_digest: String(facts.agent_identity_digest || ''),
        },
        intercept_context_digest: String(doc.intercept_context_digest || ''),
        policy_digest:
          policyDigestRaw != null ? String(policyDigestRaw) : null,
        gateway_event_hash: gatewayHashRaw != null ? String(gatewayHashRaw) : null,
      })
    : '';

  const decisionDigestMatches =
    decisionDigestValid &&
    recomputedDecisionDigest === String(doc?.decision_digest || '').toLowerCase();

  const binding = asRecord(doc?.session_binding) || {};
  const normalizationBound = binding.normalization_bound === true;
  const bindingDecisionDigestValid = HEX64.test(String(binding.decision_digest || '').toLowerCase());
  const bindingGatewayHashValid =
    binding.gateway_event_hash == null
    || HEX64.test(String(binding.gateway_event_hash).toLowerCase());

  const bindingMatchesFields =
    String(binding.session_id || '') === String(doc?.session_id || '') &&
    String(binding.decision_digest || '').toLowerCase() ===
      String(doc?.decision_digest || '').toLowerCase() &&
    String(binding.gateway_event_hash || '').toLowerCase() ===
      String(doc?.gateway_event_hash || '').toLowerCase();

  const assertions = asRecord(doc?.attestation_assertions) || {};
  const derivedReadiness = String(assertions.intercept_readiness || '') as InterceptReadiness;

  let attestationAssertionsConsistent =
    assertions.third_party_verifiable === true && sessionIdPresent;

  if (derivedReadiness === 'intercept_notary_ready') {
    attestationAssertionsConsistent =
      attestationAssertionsConsistent &&
      assertions.decision_digest_matches === true &&
      assertions.policy_bound === true &&
      decisionDigestMatches &&
      bindingMatchesFields &&
      normalizationBound &&
      (policyDigestRaw != null || assertions.policy_bound !== true);
  } else if (derivedReadiness === 'partial') {
    attestationAssertionsConsistent =
      attestationAssertionsConsistent &&
      assertions.decision_digest_matches === true &&
      decisionDigestMatches &&
      bindingMatchesFields &&
      normalizationBound;
  }

  const readinessConsistent = assertions.intercept_readiness === derivedReadiness;

  let attestationDigestMatches = false;
  if (schemaValid && doc && bindingDecisionDigestValid && bindingGatewayHashValid) {
    const preimage = buildInterceptDecisionAttestationPreimage({
      organization_id: String(doc.organization_id),
      session_id: String(doc.session_id),
      generated_at: String(doc.generated_at || ''),
      vendor_adapter_id: String(doc.vendor_adapter_id) as never,
      vendor_decision_id: String(doc.vendor_decision_id),
      decision: String(doc.decision) as never,
      evaluated_at: String(doc.evaluated_at),
      decision_digest: String(doc.decision_digest),
      policy_digest: policyDigestRaw != null ? String(policyDigestRaw) : null,
      tool_call_facts: {
        tool_name_digest: String(facts.tool_name_digest || ''),
        arguments_digest: argumentsDigestRaw != null ? String(argumentsDigestRaw) : null,
        agent_identity_digest: String(facts.agent_identity_digest || ''),
      },
      intercept_context_digest: String(doc.intercept_context_digest || ''),
      gateway_event_hash: gatewayHashRaw != null ? String(gatewayHashRaw) : null,
      witness_anchor: asRecord(doc.witness_anchor),
      attestation_assertions: {
        third_party_verifiable: assertions.third_party_verifiable === true,
        decision_digest_matches: assertions.decision_digest_matches === true,
        policy_bound: assertions.policy_bound === true,
        intercept_readiness: derivedReadiness,
      },
      session_binding: {
        session_id: String(binding.session_id || ''),
        decision_digest: String(binding.decision_digest || ''),
        gateway_event_hash:
          binding.gateway_event_hash != null ? String(binding.gateway_event_hash) : null,
        normalization_bound: normalizationBound,
      },
    });
    attestationDigestMatches =
      sha256HexUtf8(stableStringify(preimage)) ===
      String(doc.attestation_digest || '').toLowerCase();
  }

  const gatewayLinkRequired = options.requireGatewayLink === true;
  const gatewayLinkPresent = gatewayHashRaw != null && gatewayEventHashValid;
  const gatewayLinkOk = !gatewayLinkRequired || gatewayLinkPresent;

  const profileComplete =
    schemaValid &&
    organizationIdPresent &&
    sessionIdPresent &&
    vendorAdapterValid &&
    decisionValid &&
    vendorDecisionIdPresent &&
    evaluatedAtPresent &&
    generatedAtPresent &&
    decisionDigestMatches &&
    attestationDigestMatches &&
    interceptContextDigestValid &&
    policyDigestValid &&
    toolCallFactsValid &&
    hashOnlySurface &&
    bindingMatchesFields &&
    normalizationBound &&
    attestationAssertionsConsistent &&
    readinessConsistent &&
    gatewayLinkOk;

  const ok = profileComplete;

  let note: string | null = null;
  if (!schemaValid) {
    note = `schema must be ${INTERCEPT_DECISION_ATTESTATION_SCHEMA}`;
  } else if (!decisionDigestMatches) {
    note = 'decision_digest does not match canonical envelope';
  } else if (!attestationDigestMatches) {
    note = 'attestation_digest does not match preimage';
  } else if (!hashOnlySurface) {
    note = 'document contains forbidden raw identity keys';
  } else if (!gatewayLinkOk) {
    note = 'gateway_event_hash required for ingest-bound attestation';
  } else if (!attestationAssertionsConsistent) {
    note = 'attestation_assertions inconsistent with derived checks';
  }

  return {
    schema: INTERCEPT_DECISION_ATTESTATION_SCHEMA,
    sku: INTERCEPT_DECISION_ATTESTATION_SKU,
    ok,
    checks: {
      schemaValid: schemaValid === true,
      organizationIdPresent: organizationIdPresent === true,
      sessionIdPresent: sessionIdPresent === true,
      vendorAdapterValid: vendorAdapterValid === true,
      decisionValid: decisionValid === true,
      vendorDecisionIdPresent: vendorDecisionIdPresent === true,
      decisionDigestMatches: decisionDigestMatches === true,
      attestationDigestMatches: attestationDigestMatches === true,
      interceptContextDigestValid: interceptContextDigestValid === true,
      policyDigestValid: policyDigestValid === true,
      toolCallFactsValid: toolCallFactsValid === true,
      hashOnlySurface: hashOnlySurface === true,
      bindingMatchesFields: bindingMatchesFields === true,
      normalizationBound: normalizationBound === true,
      attestationAssertionsConsistent: attestationAssertionsConsistent === true,
      readinessConsistent: readinessConsistent === true,
      gatewayLinkOk: gatewayLinkOk === true,
      profileComplete: profileComplete === true,
    },
    intercept_readiness: derivedReadiness || null,
    profileComplete,
    gtmLine:
      'AIR decided. Aevesa proves the decision happened — and a third party can verify it without the vendor admin login.',
    note,
  };
}

export default { verifyInterceptDecisionAttestation, INTERCEPT_DECISION_ATTESTATION_SKU };
