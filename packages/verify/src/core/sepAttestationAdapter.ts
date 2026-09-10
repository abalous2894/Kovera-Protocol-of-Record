import { sha256HexUtf8 } from './sha256.js';
import { createHash, createHmac } from 'node:crypto';
import { serializeJcs } from './jcs.js';
import { stableStringify } from './stableStringify.js';

/**
 * Wave 13 Track B — MCP SEP-2787/2828 wire-shape adapter (single containment module).
 * All SEP draft assumptions live here; Aevesa bind schema stays canonical.
 *
 * @see MCP SEP PR #2787 (tool-call attestation)
 * @see MCP SEP PR #2828 (server decision/outcome records)
 */

export const SEP_TOOL_CALL_ATTESTATION_SCHEMA = 'mcp.tool-call-attestation/v1' as const;
export const SEP_DECISION_RECORD_SCHEMA = 'mcp.tool-decision-record/v1' as const;
export const SEP_OUTCOME_RECORD_SCHEMA = 'mcp.tool-outcome-record/v1' as const;

export type SepDecision = 'ALLOW' | 'DENY';

export interface SepToolCallAttestationInput {
  attestation_id: string;
  issued_at: string;
  mcp_server_id: string;
  tool_name: string;
  arguments_digest: string;
  agent_identity_digest: string;
  signing_secret: string;
}

export interface SepDecisionRecordInput {
  attestation_digest: string;
  decision: SepDecision;
  policy_digest: string;
  issued_at: string;
  mcp_server_id: string;
}

export interface SepOutcomeRecordInput {
  attestation_digest: string;
  decision_record_digest: string;
  result_digest: string;
  issued_at: string;
  mcp_server_id: string;
}

export interface SepToolCallAttestationWire {
  _meta: {
    schema: typeof SEP_TOOL_CALL_ATTESTATION_SCHEMA;
    attestation_id: string;
    issued_at: string;
    mcp_server_id: string;
    tool_call: {
      tool_name: string;
      arguments_digest: string;
      agent_identity_digest: string;
    };
    signature_alg: 'HMAC-SHA256';
    signature: string;
  };
}

export interface SepDecisionRecord {
  schema: typeof SEP_DECISION_RECORD_SCHEMA;
  attestation_digest: string;
  decision: SepDecision;
  policy_digest: string;
  issued_at: string;
  mcp_server_id: string;
  record_digest: string;
}

export interface SepOutcomeRecord {
  schema: typeof SEP_OUTCOME_RECORD_SCHEMA;
  attestation_digest: string;
  backLink: string;
  result_digest: string;
  issued_at: string;
  mcp_server_id: string;
  record_digest: string;
}



export function computeSepInstanceDigest(wireBytesString: string): string {
  return sha256HexUtf8(String(wireBytesString || ''));
}

function signSepAttestationPayload(canonicalPayload: string, signingSecret: string): string {
  return createHmac('sha256', String(signingSecret).trim())
    .update(canonicalPayload, 'utf8')
    .digest('hex');
}

function buildUnsignedSepAttestationMeta(
  input: Omit<SepToolCallAttestationInput, 'signing_secret'>,
): Omit<SepToolCallAttestationWire['_meta'], 'signature_alg' | 'signature'> {
  return {
    schema: SEP_TOOL_CALL_ATTESTATION_SCHEMA,
    attestation_id: String(input.attestation_id || '').trim(),
    issued_at: String(input.issued_at || '').trim(),
    mcp_server_id: String(input.mcp_server_id || '').trim(),
    tool_call: {
      tool_name: String(input.tool_name || '').trim(),
      arguments_digest: String(input.arguments_digest || '').trim().toLowerCase(),
      agent_identity_digest: String(input.agent_identity_digest || '').trim().toLowerCase(),
    },
  };
}

/**
 * Emit SEP-2787-shaped `_meta` envelope: JCS-canonical payload + detached HMAC-SHA256 signature.
 */
export function buildSepToolCallAttestation(input: SepToolCallAttestationInput): {
  wire: SepToolCallAttestationWire;
  wireBytes: string;
  attestation_digest: string;
} {
  const unsignedMeta = buildUnsignedSepAttestationMeta(input);
  const canonicalPayload = serializeJcs(unsignedMeta);
  const signature = signSepAttestationPayload(canonicalPayload, input.signing_secret);
  const wire: SepToolCallAttestationWire = {
    _meta: {
      ...unsignedMeta,
      signature_alg: 'HMAC-SHA256',
      signature,
    },
  };
  const wireBytes = serializeJcs(wire);
  return {
    wire,
    wireBytes,
    attestation_digest: computeSepInstanceDigest(wireBytes),
  };
}

export function buildSepDecisionRecord(input: SepDecisionRecordInput): SepDecisionRecord {
  const preimage = {
    schema: SEP_DECISION_RECORD_SCHEMA,
    attestation_digest: String(input.attestation_digest || '').trim().toLowerCase(),
    decision: input.decision,
    policy_digest: String(input.policy_digest || '').trim().toLowerCase(),
    issued_at: String(input.issued_at || '').trim(),
    mcp_server_id: String(input.mcp_server_id || '').trim(),
  };
  const record_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    record_digest,
  };
}

export function buildSepOutcomeRecord(input: SepOutcomeRecordInput): SepOutcomeRecord {
  const decision_record_digest = String(input.decision_record_digest || '').trim().toLowerCase();
  const preimage = {
    schema: SEP_OUTCOME_RECORD_SCHEMA,
    attestation_digest: String(input.attestation_digest || '').trim().toLowerCase(),
    backLink: decision_record_digest,
    result_digest: String(input.result_digest || '').trim().toLowerCase(),
    issued_at: String(input.issued_at || '').trim(),
    mcp_server_id: String(input.mcp_server_id || '').trim(),
  };
  const record_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    record_digest,
  };
}

export function verifySepAttestationSignature(
  wire: SepToolCallAttestationWire,
  signingSecret: string,
): boolean {
  const meta = wire?._meta;
  if (!meta || meta.signature_alg !== 'HMAC-SHA256') return false;
  const { signature_alg: _alg, signature, ...unsignedMeta } = meta;
  const canonicalPayload = serializeJcs(unsignedMeta);
  const expected = signSepAttestationPayload(canonicalPayload, signingSecret);
  return String(signature || '').toLowerCase() === expected.toLowerCase();
}

/** SEP-2828 Check A — decision and outcome bind to the same attestation instance digest. */
export function verifySepInstanceBinding(
  attestationDigest: string,
  decision: SepDecisionRecord,
  outcome: SepOutcomeRecord,
): boolean {
  const expected = String(attestationDigest || '').trim().toLowerCase();
  return (
    String(decision?.attestation_digest || '').toLowerCase() === expected &&
    String(outcome?.attestation_digest || '').toLowerCase() === expected
  );
}

/** SEP-2828 Check B — outcome backLink resolves to the decision record digest. */
export function verifySepBackLink(decision: SepDecisionRecord, outcome: SepOutcomeRecord): boolean {
  return (
    String(outcome?.backLink || '').toLowerCase() ===
    String(decision?.record_digest || '').toLowerCase()
  );
}

export function recomputeSepDecisionRecordDigest(decision: SepDecisionRecord): string {
  const preimage = {
    schema: SEP_DECISION_RECORD_SCHEMA,
    attestation_digest: String(decision.attestation_digest || '').toLowerCase(),
    decision: decision.decision,
    policy_digest: String(decision.policy_digest || '').toLowerCase(),
    issued_at: String(decision.issued_at || ''),
    mcp_server_id: String(decision.mcp_server_id || ''),
  };
  return sha256HexUtf8(stableStringify(preimage));
}

export function recomputeSepOutcomeRecordDigest(outcome: SepOutcomeRecord): string {
  const preimage = {
    schema: SEP_OUTCOME_RECORD_SCHEMA,
    attestation_digest: String(outcome.attestation_digest || '').toLowerCase(),
    backLink: String(outcome.backLink || '').toLowerCase(),
    result_digest: String(outcome.result_digest || '').toLowerCase(),
    issued_at: String(outcome.issued_at || ''),
    mcp_server_id: String(outcome.mcp_server_id || ''),
  };
  return sha256HexUtf8(stableStringify(preimage));
}

export default {
  SEP_TOOL_CALL_ATTESTATION_SCHEMA,
  SEP_DECISION_RECORD_SCHEMA,
  SEP_OUTCOME_RECORD_SCHEMA,
  buildSepToolCallAttestation,
  buildSepDecisionRecord,
  buildSepOutcomeRecord,
  computeSepInstanceDigest,
  verifySepAttestationSignature,
  verifySepInstanceBinding,
  verifySepBackLink,
  recomputeSepDecisionRecordDigest,
  recomputeSepOutcomeRecordDigest,
};
