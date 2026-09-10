import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';
import {
  buildSepDecisionRecord,
  buildSepOutcomeRecord,
  buildSepToolCallAttestation,
  recomputeSepDecisionRecordDigest,
  recomputeSepOutcomeRecordDigest,
  verifySepAttestationSignature,
  verifySepBackLink,
  verifySepInstanceBinding,
  type SepDecisionRecord,
  type SepOutcomeRecord,
  type SepToolCallAttestationWire,
} from './sepAttestationAdapter.js';

/** Wave 13 Track B — MCP SEP attestation bind (2787 instance + 2828 decision/outcome). */

export const MCP_SEP_ATTESTATION_BIND_SCHEMA = 'aevesa.mcp-sep-attestation-bind/v1' as const;

export type AttestationReadiness = 'governed_proxy_ready' | 'partial' | 'unverified';

export interface SepArtifactsBlock {
  tool_call_attestation_wire: SepToolCallAttestationWire;
  tool_call_attestation_wire_bytes: string;
  decision_record: SepDecisionRecord;
  outcome_record: SepOutcomeRecord;
}

export interface BindAssertionsInput {
  third_party_verifiable: boolean;
}

export interface SessionBinding {
  session_id: string;
  attestation_digest: string;
  decision_record_digest: string;
  outcome_record_digest: string;
  normalization_bound: boolean;
}

export interface McpSepAttestationBindInput {
  organization_id: string;
  session_id: string;
  generated_at?: string;
  tool_name: string;
  arguments_digest: string;
  agent_identity_digest: string;
  sep_artifacts: SepArtifactsBlock;
  bind_assertions: BindAssertionsInput;
  session_binding: SessionBinding;
  signing_secret?: string;
  disclaimer?: string;
}



export function deriveAttestationReadiness(
  instanceBindingValid: boolean,
  backLinkValid: boolean,
  signatureValid: boolean,
  digestsConsistent: boolean,
): AttestationReadiness {
  if (instanceBindingValid && backLinkValid && signatureValid && digestsConsistent) {
    return 'governed_proxy_ready';
  }
  if (instanceBindingValid && backLinkValid && digestsConsistent) {
    return 'partial';
  }
  return 'unverified';
}

export function buildBindAssertionsBlock(
  input: BindAssertionsInput,
  instanceBindingValid: boolean,
  backLinkValid: boolean,
  signatureValid: boolean,
  digestsConsistent: boolean,
) {
  const attestation_readiness = deriveAttestationReadiness(
    instanceBindingValid,
    backLinkValid,
    signatureValid,
    digestsConsistent,
  );
  return {
    instance_binding_valid: instanceBindingValid,
    back_link_valid: backLinkValid,
    signature_valid: signatureValid,
    third_party_verifiable: input.third_party_verifiable === true,
    attestation_readiness,
  };
}

export function buildMcpSepAttestationBindPreimage(
  input: McpSepAttestationBindInput & {
    generated_at: string;
    attestation_digest: string;
    decision_record_digest: string;
    outcome_record_digest: string;
    bind_assertions: ReturnType<typeof buildBindAssertionsBlock>;
  },
): Record<string, unknown> {
  return {
    schema: MCP_SEP_ATTESTATION_BIND_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    session_id: String(input.session_id || '').trim(),
    generated_at: input.generated_at,
    tool_name: String(input.tool_name || '').trim(),
    arguments_digest: String(input.arguments_digest || '').trim().toLowerCase(),
    agent_identity_digest: String(input.agent_identity_digest || '').trim().toLowerCase(),
    attestation_digest: String(input.attestation_digest || '').trim().toLowerCase(),
    decision_record_digest: String(input.decision_record_digest || '').trim().toLowerCase(),
    outcome_record_digest: String(input.outcome_record_digest || '').trim().toLowerCase(),
    sep_artifacts: {
      tool_call_attestation_wire: input.sep_artifacts.tool_call_attestation_wire,
      tool_call_attestation_wire_bytes: input.sep_artifacts.tool_call_attestation_wire_bytes,
      decision_record: input.sep_artifacts.decision_record,
      outcome_record: input.sep_artifacts.outcome_record,
    },
    bind_assertions: input.bind_assertions,
    session_binding: {
      session_id: String(input.session_binding.session_id || '').trim(),
      attestation_digest: String(input.session_binding.attestation_digest || '').trim().toLowerCase(),
      decision_record_digest: String(input.session_binding.decision_record_digest || '')
        .trim()
        .toLowerCase(),
      outcome_record_digest: String(input.session_binding.outcome_record_digest || '')
        .trim()
        .toLowerCase(),
      normalization_bound: input.session_binding.normalization_bound === true,
    },
    disclaimer:
      input.disclaimer ??
      'MCP SEP attestation bind — not legal advice or authorization to act.',
  };
}

export interface McpSepAttestationBindDocument {
  schema: typeof MCP_SEP_ATTESTATION_BIND_SCHEMA;
  organization_id: string;
  session_id: string;
  generated_at: string;
  tool_name: string;
  arguments_digest: string;
  agent_identity_digest: string;
  attestation_digest: string;
  decision_record_digest: string;
  outcome_record_digest: string;
  sep_artifacts: SepArtifactsBlock;
  bind_assertions: ReturnType<typeof buildBindAssertionsBlock>;
  session_binding: SessionBinding;
  disclaimer: string;
  bind_digest: string;
}

export function buildMcpSepAttestationBindDocument(
  input: McpSepAttestationBindInput,
): McpSepAttestationBindDocument {
  const generated_at = input.generated_at || new Date().toISOString();
  const attestation_digest = String(
    input.sep_artifacts.tool_call_attestation_wire_bytes
      ? sha256HexUtf8(input.sep_artifacts.tool_call_attestation_wire_bytes)
      : input.session_binding.attestation_digest,
  ).toLowerCase();
  const decision_record_digest = String(
    input.sep_artifacts.decision_record?.record_digest || '',
  ).toLowerCase();
  const outcome_record_digest = String(
    input.sep_artifacts.outcome_record?.record_digest || '',
  ).toLowerCase();

  const instanceBindingValid = verifySepInstanceBinding(
    attestation_digest,
    input.sep_artifacts.decision_record,
    input.sep_artifacts.outcome_record,
  );
  const backLinkValid = verifySepBackLink(
    input.sep_artifacts.decision_record,
    input.sep_artifacts.outcome_record,
  );
  const decisionDigestMatches =
    recomputeSepDecisionRecordDigest(input.sep_artifacts.decision_record) ===
    decision_record_digest;
  const outcomeDigestMatches =
    recomputeSepOutcomeRecordDigest(input.sep_artifacts.outcome_record) === outcome_record_digest;
  const digestsConsistent = decisionDigestMatches && outcomeDigestMatches;

  let signatureValid = false;
  if (input.signing_secret?.trim()) {
    signatureValid = verifySepAttestationSignature(
      input.sep_artifacts.tool_call_attestation_wire,
      input.signing_secret,
    );
  }

  const bind_assertions = buildBindAssertionsBlock(
    input.bind_assertions,
    instanceBindingValid,
    backLinkValid,
    signatureValid,
    digestsConsistent,
  );

  const preimage = buildMcpSepAttestationBindPreimage({
    ...input,
    generated_at,
    attestation_digest,
    decision_record_digest,
    outcome_record_digest,
    bind_assertions,
  });
  const bind_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...(preimage as Omit<McpSepAttestationBindDocument, 'bind_digest'>),
    bind_digest,
  };
}

export interface BuildMcpSepAttestationDemoArtifactsInput {
  attestation_id: string;
  issued_at: string;
  mcp_server_id: string;
  tool_name: string;
  arguments_digest: string;
  agent_identity_digest: string;
  policy_digest: string;
  result_digest: string;
  decision_issued_at: string;
  outcome_issued_at: string;
  signing_secret: string;
}

/** Convenience builder for demo/conformance — constructs all three SEP artifacts. */
export function buildMcpSepAttestationDemoArtifacts(input: BuildMcpSepAttestationDemoArtifactsInput) {
  const attestation = buildSepToolCallAttestation({
    attestation_id: input.attestation_id,
    issued_at: input.issued_at,
    mcp_server_id: input.mcp_server_id,
    tool_name: input.tool_name,
    arguments_digest: input.arguments_digest,
    agent_identity_digest: input.agent_identity_digest,
    signing_secret: input.signing_secret,
  });
  const decision_record = buildSepDecisionRecord({
    attestation_digest: attestation.attestation_digest,
    decision: 'ALLOW',
    policy_digest: input.policy_digest,
    issued_at: input.decision_issued_at,
    mcp_server_id: input.mcp_server_id,
  });
  const outcome_record = buildSepOutcomeRecord({
    attestation_digest: attestation.attestation_digest,
    decision_record_digest: decision_record.record_digest,
    result_digest: input.result_digest,
    issued_at: input.outcome_issued_at,
    mcp_server_id: input.mcp_server_id,
  });
  return {
    attestation,
    decision_record,
    outcome_record,
    sep_artifacts: {
      tool_call_attestation_wire: attestation.wire,
      tool_call_attestation_wire_bytes: attestation.wireBytes,
      decision_record,
      outcome_record,
    },
  };
}

export default {
  MCP_SEP_ATTESTATION_BIND_SCHEMA,
  buildMcpSepAttestationBindDocument,
  buildMcpSepAttestationBindPreimage,
  buildBindAssertionsBlock,
  buildMcpSepAttestationDemoArtifacts,
  deriveAttestationReadiness,
};
