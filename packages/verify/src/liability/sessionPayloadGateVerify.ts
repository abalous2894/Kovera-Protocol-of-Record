import { createHmac, timingSafeEqual } from 'node:crypto';
import {
  verifyChannelProvenanceBundle,
  CHANNEL_PROVENANCE_SCHEMA,
  type ChannelProvenanceDocument,
} from './channelProvenanceVerify.js';

export const SESSION_PAYLOAD_GATE_SCHEMA = 'aevesa.session-payload-gate/v1' as const;
export const SESSION_PAYLOAD_GATE_SKU = 'aevesa-session-payload-gate-v1' as const;
export const SESSION_PAYLOAD_GATE_EVENT = 'SESSION_PAYLOAD_MUTATION' as const;

export const SESSION_PAYLOAD_ACTION_TYPES = [
  'memory.write',
  'oauth.grant',
  'instruction.persist',
  'credential.bind',
] as const;

export type SessionPayloadActionType = (typeof SESSION_PAYLOAD_ACTION_TYPES)[number];

export const SESSION_PAYLOAD_VERDICTS = ['PERMIT', 'DENY'] as const;
export type SessionPayloadVerdict = (typeof SESSION_PAYLOAD_VERDICTS)[number];

export interface SessionPayloadMutation {
  action_type: SessionPayloadActionType;
  target: string;
  preimage_digest: string;
  payload_summary?: string;
}

export interface SessionPayloadLedgerAttestation {
  entryHash: string;
  prevHash?: string;
  attestationSignature: string;
}

export interface SessionPayloadGateDocument {
  schema?: string;
  session_id?: string;
  mutation?: SessionPayloadMutation;
  verdict?: SessionPayloadVerdict;
  pre_execution?: boolean;
  execution_occurred?: boolean;
  aeg_edge?: number;
  aeg_check?: string;
  aeg_source?: string;
  channel_provenance?: ChannelProvenanceDocument;
  ledger_attestation?: SessionPayloadLedgerAttestation;
}

export interface SessionPayloadGateVerifyOptions {
  attestationSecret?: string;
  skipSignatureVerification?: boolean;
  requirePreExecution?: boolean;
  requireChannelProvenance?: boolean;
}

export interface SessionPayloadGateVerifyChecks {
  schemaValid: boolean;
  sessionIdPresent: boolean;
  mutationValid: boolean;
  actionTypeRecognized: boolean;
  verdictValid: boolean;
  preExecutionMarked: boolean;
  denyInvariantHolds: boolean;
  permitExecutionConsistent: boolean;
  aegEdgePresent: boolean;
  aegCheckPresent: boolean;
  channelProvenanceVerified: boolean;
  entryHashFormat: boolean;
  attestationSignaturePresent: boolean;
  attestationSignatureMatch: boolean | null;
  profileComplete: boolean;
}

export interface SessionPayloadGateVerifyResult {
  schema: typeof SESSION_PAYLOAD_GATE_SCHEMA;
  sku: typeof SESSION_PAYLOAD_GATE_SKU;
  ok: boolean;
  checks: SessionPayloadGateVerifyChecks;
  channelProvenance: ReturnType<typeof verifyChannelProvenanceBundle> | null;
  gtmLine: string;
  note: string | null;
}

const ENTRY_HASH_RE = /^[a-f0-9]{64}$/;

export function computeSessionPayloadGateSignature(
  entryHash: string,
  prevHash: string | null | undefined,
  secret: string,
): string {
  const material = `SESSION_PAYLOAD|v1|${String(entryHash)}|${String(prevHash || 'GENESIS')}`;
  return createHmac('sha256', String(secret).trim()).update(material, 'utf8').digest('hex');
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

/**
 * Verify session payload gate attestation — durable state mutations witnessed before side effects.
 */
export function verifySessionPayloadGateBundle(
  input: unknown,
  options: SessionPayloadGateVerifyOptions = {},
): SessionPayloadGateVerifyResult {
  const doc = asRecord(input) as SessionPayloadGateDocument | null;
  const schemaValid = doc?.schema === SESSION_PAYLOAD_GATE_SCHEMA;

  const session_id = String(doc?.session_id || '').trim();
  const sessionIdPresent = session_id.length > 0;

  const mutationRaw = asRecord(doc?.mutation);
  const action_type = String(mutationRaw?.action_type || '').trim() as SessionPayloadActionType;
  const target = String(mutationRaw?.target || '').trim();
  const preimage_digest = String(mutationRaw?.preimage_digest || '').trim().toLowerCase();
  const actionTypeRecognized = SESSION_PAYLOAD_ACTION_TYPES.includes(action_type);
  const mutationValid =
    actionTypeRecognized && target.length > 0 && ENTRY_HASH_RE.test(preimage_digest);

  const verdict = String(doc?.verdict || '').trim().toUpperCase() as SessionPayloadVerdict;
  const verdictValid = SESSION_PAYLOAD_VERDICTS.includes(verdict);

  const requirePreExecution = options.requirePreExecution !== false;
  const preExecutionMarked = !requirePreExecution || doc?.pre_execution === true;

  const execution_occurred = doc?.execution_occurred === true;
  const denyInvariantHolds = verdict !== 'DENY' || execution_occurred === false;
  const permitExecutionConsistent = verdict !== 'PERMIT' || doc?.execution_occurred !== false;

  const aegEdgePresent = doc?.aeg_edge === 3;
  const aegCheckPresent =
    doc?.aeg_check === 'provenance_preservation' || doc?.aeg_check === 'authority_attribution';

  let channelProvenance: ReturnType<typeof verifyChannelProvenanceBundle> | null = null;
  const requireChannel = options.requireChannelProvenance === true;
  if (doc?.channel_provenance) {
    channelProvenance = verifyChannelProvenanceBundle(doc.channel_provenance, {
      requireEnvironmentalSource: doc.aeg_source === 'B',
    });
  }
  const channelProvenanceVerified =
    !requireChannel || (channelProvenance?.ok === true && doc?.channel_provenance != null);

  const ledgerRaw = asRecord(doc?.ledger_attestation);
  const entryHash = String(ledgerRaw?.entryHash || '').trim().toLowerCase();
  const entryHashFormat = ENTRY_HASH_RE.test(entryHash);
  const attestationSignature = String(ledgerRaw?.attestationSignature || '').trim();
  const attestationSignaturePresent = ENTRY_HASH_RE.test(attestationSignature);

  let attestationSignatureMatch: boolean | null = null;
  if (options.attestationSecret && entryHashFormat && attestationSignaturePresent) {
    const expected = computeSessionPayloadGateSignature(
      entryHash,
      String(ledgerRaw?.prevHash || 'GENESIS'),
      options.attestationSecret,
    );
    attestationSignatureMatch =
      expected.length === attestationSignature.length &&
      timingSafeEqual(Buffer.from(expected, 'utf8'), Buffer.from(attestationSignature, 'utf8'));
  }

  const skipSignatureVerification = options.skipSignatureVerification === true;
  const signatureOk = skipSignatureVerification
    ? attestationSignaturePresent
    : options.attestationSecret
      ? attestationSignatureMatch === true
      : false;

  const profileComplete =
    schemaValid &&
    sessionIdPresent &&
    mutationValid &&
    verdictValid &&
    preExecutionMarked &&
    denyInvariantHolds &&
    permitExecutionConsistent &&
    aegEdgePresent &&
    aegCheckPresent &&
    channelProvenanceVerified &&
    entryHashFormat &&
    signatureOk;

  const ok = profileComplete;

  let note: string | null = null;
  if (ok) {
    note = `Session payload gate verified — ${action_type} ${verdict} with pre-execution attestation`;
  } else if (!schemaValid) {
    note = `Expected schema ${SESSION_PAYLOAD_GATE_SCHEMA}`;
  } else if (!denyInvariantHolds) {
    note = 'DENY attestation requires execution_occurred false (PEP invariant)';
  } else if (!options.attestationSecret && !skipSignatureVerification) {
    note = 'Session payload gate requires attestationSecret for HMAC verification (fail closed)';
  } else if (attestationSignatureMatch === false) {
    note = 'Ledger attestation HMAC does not match entryHash|prevHash material';
  } else if (requireChannel && !channelProvenanceVerified) {
    note = 'Session payload gate requires verified channel_provenance binding';
  } else {
    note = 'Session payload gate profile verification failed';
  }

  return {
    schema: SESSION_PAYLOAD_GATE_SCHEMA,
    sku: SESSION_PAYLOAD_GATE_SKU,
    ok,
    checks: {
      schemaValid,
      sessionIdPresent,
      mutationValid,
      actionTypeRecognized,
      verdictValid,
      preExecutionMarked,
      denyInvariantHolds,
      permitExecutionConsistent,
      aegEdgePresent,
      aegCheckPresent,
      channelProvenanceVerified,
      entryHashFormat,
      attestationSignaturePresent,
      attestationSignatureMatch,
      profileComplete,
    },
    channelProvenance,
    gtmLine:
      'The authenticated session was the payload. Aevesa witnesses memory, OAuth, and instruction mutations — not just tool calls.',
    note,
  };
}

export { CHANNEL_PROVENANCE_SCHEMA };
