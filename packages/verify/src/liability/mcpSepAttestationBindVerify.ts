import { sha256HexUtf8 } from '../core/sha256.js';
import { buildMcpSepAttestationBindPreimage, MCP_SEP_ATTESTATION_BIND_SCHEMA, type AttestationReadiness } from '../core/mcpSepAttestationBind.js';
import {
  computeSepInstanceDigest,
  recomputeSepDecisionRecordDigest,
  recomputeSepOutcomeRecordDigest,
  verifySepAttestationSignature,
  verifySepBackLink,
  verifySepInstanceBinding,
  type SepDecisionRecord,
  type SepOutcomeRecord,
  type SepToolCallAttestationWire,
} from '../core/sepAttestationAdapter.js';
import { stableStringify } from '../core/stableStringify.js';

export const MCP_SEP_ATTESTATION_BIND_SKU = 'aevesa-mcp-sep-attestation-bind-v1' as const;

const HEX64 = /^[a-f0-9]{64}$/;
const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|ssn|phone|address|pan|cvv)$/i;

export interface McpSepAttestationBindVerifyOptions {
  signingSecret?: string | null;
}

export interface McpSepAttestationBindVerifyResult {
  schema: typeof MCP_SEP_ATTESTATION_BIND_SCHEMA;
  sku: typeof MCP_SEP_ATTESTATION_BIND_SKU;
  ok: boolean;
  checks: Record<string, boolean>;
  attestation_readiness: AttestationReadiness | null;
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

export function verifyMcpSepAttestationBind(
  docInput: unknown,
  options: McpSepAttestationBindVerifyOptions = {},
): McpSepAttestationBindVerifyResult {
  const doc = asRecord(docInput);
  const schemaValid = doc?.schema === MCP_SEP_ATTESTATION_BIND_SCHEMA;
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;
  const sessionIdPresent = String(doc?.session_id || '').trim().length > 0;
  const toolNamePresent = String(doc?.tool_name || '').trim().length > 0;

  const attestationDigestValid = HEX64.test(String(doc?.attestation_digest || '').toLowerCase());
  const decisionDigestValid = HEX64.test(String(doc?.decision_record_digest || '').toLowerCase());
  const outcomeDigestValid = HEX64.test(String(doc?.outcome_record_digest || '').toLowerCase());
  const argumentsDigestValid = HEX64.test(String(doc?.arguments_digest || '').toLowerCase());
  const agentDigestValid = HEX64.test(String(doc?.agent_identity_digest || '').toLowerCase());

  const artifacts = asRecord(doc?.sep_artifacts) || {};
  const wire = artifacts.tool_call_attestation_wire as SepToolCallAttestationWire | undefined;
  const wireBytes = String(artifacts.tool_call_attestation_wire_bytes || '');
  const decision = artifacts.decision_record as SepDecisionRecord | undefined;
  const outcome = artifacts.outcome_record as SepOutcomeRecord | undefined;

  const artifactsPresent =
    wire != null &&
    wireBytes.length > 0 &&
    decision != null &&
    outcome != null;

  const attestationDigestMatches =
    artifactsPresent &&
    computeSepInstanceDigest(wireBytes) ===
      String(doc?.attestation_digest || '').toLowerCase();

  const wireAttestationDigest = artifactsPresent ? computeSepInstanceDigest(wireBytes) : '';

  const decisionRecordDigestMatches =
    decision != null &&
    recomputeSepDecisionRecordDigest(decision) ===
      String(decision.record_digest || '').toLowerCase() &&
    String(decision.record_digest || '').toLowerCase() ===
      String(doc?.decision_record_digest || '').toLowerCase();

  const outcomeRecordDigestMatches =
    outcome != null &&
    recomputeSepOutcomeRecordDigest(outcome) ===
      String(outcome.record_digest || '').toLowerCase() &&
    String(outcome.record_digest || '').toLowerCase() ===
      String(doc?.outcome_record_digest || '').toLowerCase();

  const instanceBindingValid =
    artifactsPresent &&
    verifySepInstanceBinding(wireAttestationDigest, decision!, outcome!);

  const backLinkValid =
    artifactsPresent && decision != null && outcome != null && verifySepBackLink(decision, outcome);

  let signatureValid = false;
  const secret = options.signingSecret?.trim();
  if (artifactsPresent && secret) {
    signatureValid = verifySepAttestationSignature(wire!, secret);
  } else if (artifactsPresent) {
    signatureValid = asRecord(doc?.bind_assertions)?.signature_valid === true;
  }

  const binding = asRecord(doc?.session_binding) || {};
  const normalizationBound = binding.normalization_bound === true;
  const bindingDigestsValid =
    HEX64.test(String(binding.attestation_digest || '').toLowerCase()) &&
    HEX64.test(String(binding.decision_record_digest || '').toLowerCase()) &&
    HEX64.test(String(binding.outcome_record_digest || '').toLowerCase());

  const bindingMatchesArtifacts =
    String(binding.session_id || '') === String(doc?.session_id || '') &&
    String(binding.attestation_digest || '').toLowerCase() ===
      String(doc?.attestation_digest || '').toLowerCase() &&
    String(binding.decision_record_digest || '').toLowerCase() ===
      String(doc?.decision_record_digest || '').toLowerCase() &&
    String(binding.outcome_record_digest || '').toLowerCase() ===
      String(doc?.outcome_record_digest || '').toLowerCase();

  const assertions = asRecord(doc?.bind_assertions) || {};
  const derivedReadiness = String(assertions.attestation_readiness || '') as AttestationReadiness;

  let bindAssertionsConsistent =
    assertions.third_party_verifiable === true && sessionIdPresent;

  if (derivedReadiness === 'governed_proxy_ready') {
    bindAssertionsConsistent =
      bindAssertionsConsistent &&
      assertions.instance_binding_valid === true &&
      assertions.back_link_valid === true &&
      assertions.signature_valid === true &&
      instanceBindingValid &&
      backLinkValid &&
      signatureValid &&
      bindingMatchesArtifacts &&
      normalizationBound;
  } else if (derivedReadiness === 'partial') {
    bindAssertionsConsistent =
      bindAssertionsConsistent &&
      assertions.instance_binding_valid === true &&
      assertions.back_link_valid === true &&
      instanceBindingValid &&
      backLinkValid &&
      bindingMatchesArtifacts;
  }

  const readinessConsistent = assertions.attestation_readiness === derivedReadiness;

  let bindDigestMatches = false;
  if (schemaValid && doc && bindingDigestsValid && bindingMatchesArtifacts) {
    const preimage = buildMcpSepAttestationBindPreimage({
      organization_id: String(doc.organization_id),
      session_id: String(doc.session_id),
      generated_at: String(doc.generated_at || ''),
      tool_name: String(doc.tool_name || ''),
      arguments_digest: String(doc.arguments_digest || ''),
      agent_identity_digest: String(doc.agent_identity_digest || ''),
      attestation_digest: String(doc.attestation_digest || ''),
      decision_record_digest: String(doc.decision_record_digest || ''),
      outcome_record_digest: String(doc.outcome_record_digest || ''),
      sep_artifacts: {
        tool_call_attestation_wire: wire!,
        tool_call_attestation_wire_bytes: wireBytes,
        decision_record: decision!,
        outcome_record: outcome!,
      },
      bind_assertions: {
        instance_binding_valid: assertions.instance_binding_valid === true,
        back_link_valid: assertions.back_link_valid === true,
        signature_valid: assertions.signature_valid === true,
        third_party_verifiable: assertions.third_party_verifiable === true,
        attestation_readiness: derivedReadiness,
      },
      session_binding: {
        session_id: String(binding.session_id || ''),
        attestation_digest: String(binding.attestation_digest || ''),
        decision_record_digest: String(binding.decision_record_digest || ''),
        outcome_record_digest: String(binding.outcome_record_digest || ''),
        normalization_bound: normalizationBound,
      },
      disclaimer: String(doc.disclaimer || ''),
    });
    const expected = sha256HexUtf8(stableStringify(preimage));
    bindDigestMatches = String(doc.bind_digest || '').toLowerCase() === expected;
  }

  const hashOnlySurface = !hasForbiddenKeys(doc);

  const profileComplete =
    schemaValid &&
    organizationIdPresent &&
    sessionIdPresent &&
    toolNamePresent &&
    artifactsPresent &&
    attestationDigestValid &&
    decisionDigestValid &&
    outcomeDigestValid &&
    argumentsDigestValid &&
    agentDigestValid &&
    attestationDigestMatches &&
    decisionRecordDigestMatches &&
    outcomeRecordDigestMatches &&
    instanceBindingValid &&
    backLinkValid &&
    signatureValid &&
    bindingMatchesArtifacts &&
    bindingDigestsValid &&
    bindAssertionsConsistent &&
    bindDigestMatches &&
    hashOnlySurface &&
    readinessConsistent;

  let note: string | null = null;
  if (!schemaValid) note = `schema must be ${MCP_SEP_ATTESTATION_BIND_SCHEMA}`;
  else if (!attestationDigestMatches) note = 'attestation_digest does not match JCS wire bytes (instance binding broken)';
  else if (!instanceBindingValid) note = 'SEP-2828 Check A failed — decision/outcome attestation_digest mismatch';
  else if (!backLinkValid) note = 'SEP-2828 Check B failed — outcome backLink does not resolve to decision digest';
  else if (!signatureValid) note = 'SEP-2787 attestation HMAC signature invalid or secret not provided';
  else if (!bindDigestMatches) note = 'bind_digest does not match canonical preimage';
  else if (!bindAssertionsConsistent) note = 'bind_assertions inconsistent with artifacts or session binding';

  return {
    schema: MCP_SEP_ATTESTATION_BIND_SCHEMA,
    sku: MCP_SEP_ATTESTATION_BIND_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      organizationIdPresent,
      sessionIdPresent,
      toolNamePresent,
      artifactsPresent,
      attestationDigestValid,
      decisionDigestValid,
      outcomeDigestValid,
      attestationDigestMatches,
      decisionRecordDigestMatches,
      outcomeRecordDigestMatches,
      instanceBindingValid,
      backLinkValid,
      signatureValid,
      bindingMatchesArtifacts,
      bindingDigestsValid,
      bindAssertionsConsistent,
      bindDigestMatches,
      hashOnlySurface,
      readinessConsistent,
      profileComplete,
    },
    attestation_readiness: derivedReadiness || null,
    gtmLine:
      'MCP is standardizing signed tool-call attestation. Aevesa already verifies it — offline, conformance-tested, before the SEP even lands.',
    note,
  };
}

export default { verifyMcpSepAttestationBind, MCP_SEP_ATTESTATION_BIND_SKU };
