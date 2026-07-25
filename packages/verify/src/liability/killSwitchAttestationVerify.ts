import { createHmac } from 'node:crypto';

export const KILL_SWITCH_ATTESTATION_SCHEMA = 'aevesa.kill-switch-attestation/v1' as const;
export const KILL_SWITCH_ATTESTATION_SKU = 'aevesa-kill-switch-attestation-v1' as const;
export const AEGIS_GOVERNANCE_STATUS_EVENT = 'AEGIS_GOVERNANCE_STATUS' as const;
export const DEFAULT_KILL_SWITCH_POLICY_ID = '3b7e7d2a-0c0f-4a1b-8e2d-5f6a7b8c9d0e';

const ENTRY_HASH_RE = /^[a-f0-9]{64}$/;

export interface KillSwitchLedgerAttestation {
  entryHash: string;
  prevHash?: string;
  attestationSignature: string;
  policyId?: string;
}

export interface KillSwitchAttestationPayload {
  targetAgentId: string;
  newStatus: string;
  interventionReason?: string;
  at?: string;
  test_type?: string;
}

export interface KillSwitchAttestationDocument {
  schema?: string;
  test_type?: string;
  agent_id?: string;
  eventType?: string;
  ledger_attestation?: KillSwitchLedgerAttestation;
  payload?: KillSwitchAttestationPayload;
}

export interface KillSwitchAttestationVerifyOptions {
  /** HMAC secret for offline attestation signature verification */
  attestationSecret?: string;
  /** Explicit dev/conformance bypass — do not use in production verify paths */
  skipSignatureVerification?: boolean;
  /** Expected policy id (defaults to Aevesa kill-switch policy) */
  policyId?: string;
  /** Require live-test marker on attestation */
  requireLiveTest?: boolean;
}

export interface KillSwitchAttestationVerifyChecks {
  schemaValid: boolean;
  entryHashFormat: boolean;
  eventTypeValid: boolean;
  statusBlocked: boolean;
  policyIdMatch: boolean;
  targetAgentPresent: boolean;
  attestationSignaturePresent: boolean;
  attestationSignatureMatch: boolean | null;
  liveTestMarked: boolean;
  profileComplete: boolean;
}

export interface KillSwitchAttestationVerifyResult {
  schema: typeof KILL_SWITCH_ATTESTATION_SCHEMA;
  sku: typeof KILL_SWITCH_ATTESTATION_SKU;
  ok: boolean;
  checks: KillSwitchAttestationVerifyChecks;
  gtmLine: string;
  note: string | null;
}

export function computeKillSwitchAttestationSignature(
  entryHash: string,
  prevHash: string | null | undefined,
  secret: string,
): string {
  const material = `LEDGER_ATTEST|v1|${String(entryHash)}|${String(prevHash || 'GENESIS')}`;
  return createHmac('sha256', String(secret).trim()).update(material, 'utf8').digest('hex');
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

/**
 * Verify kill-switch live-test attestation — carrier control #1 (human kill switch with recent test).
 */
export function verifyKillSwitchAttestationBundle(
  input: unknown,
  options: KillSwitchAttestationVerifyOptions = {},
): KillSwitchAttestationVerifyResult {
  const doc = asRecord(input);
  const schemaValid = doc?.schema === KILL_SWITCH_ATTESTATION_SCHEMA;

  const ledgerRaw = asRecord(doc?.ledger_attestation);
  const payloadRaw = asRecord(doc?.payload);
  const entryHash = String(ledgerRaw?.entryHash || '').trim().toLowerCase();
  const entryHashFormat = ENTRY_HASH_RE.test(entryHash);

  const eventType = String(doc?.eventType || AEGIS_GOVERNANCE_STATUS_EVENT);
  const eventTypeValid = eventType === AEGIS_GOVERNANCE_STATUS_EVENT;

  const newStatus = String(payloadRaw?.newStatus || '').trim().toUpperCase();
  const statusBlocked = newStatus === 'BLOCKED';

  const expectedPolicyId = options.policyId || DEFAULT_KILL_SWITCH_POLICY_ID;
  const policyId = String(ledgerRaw?.policyId || expectedPolicyId);
  const policyIdMatch = policyId === expectedPolicyId;

  const targetAgentId = String(payloadRaw?.targetAgentId || doc?.agent_id || '').trim();
  const targetAgentPresent = targetAgentId.length > 0;

  const attestationSignature = String(ledgerRaw?.attestationSignature || '').trim();
  const attestationSignaturePresent = /^[a-f0-9]{64}$/.test(attestationSignature);

  let attestationSignatureMatch: boolean | null = null;
  if (options.attestationSecret && entryHashFormat && attestationSignaturePresent) {
    const expected = computeKillSwitchAttestationSignature(
      entryHash,
      String(ledgerRaw?.prevHash || 'GENESIS'),
      options.attestationSecret,
    );
    attestationSignatureMatch = expected === attestationSignature;
  }

  const requireLiveTest = options.requireLiveTest !== false;
  const testType = String(doc?.test_type || payloadRaw?.test_type || '').trim();
  const liveTestMarked = !requireLiveTest || testType === 'live_kill_switch_test';

  const skipSignatureVerification = options.skipSignatureVerification === true;
  const signatureOk = skipSignatureVerification
    ? attestationSignaturePresent
    : options.attestationSecret
      ? attestationSignatureMatch === true
      : false;

  const profileComplete =
    schemaValid &&
    entryHashFormat &&
    eventTypeValid &&
    statusBlocked &&
    policyIdMatch &&
    targetAgentPresent &&
    signatureOk &&
    liveTestMarked;

  const ok = profileComplete;

  let note: string | null = null;
  if (ok) {
    note = 'Kill-switch live-test attestation verified — BLOCKED status with ledger HMAC attestation';
  } else if (!schemaValid) {
    note = `Expected schema ${KILL_SWITCH_ATTESTATION_SCHEMA}`;
  } else if (!statusBlocked) {
    note = 'Kill-switch attestation requires payload.newStatus BLOCKED';
  } else if (!liveTestMarked) {
    note = 'Kill-switch attestation requires test_type live_kill_switch_test';
  } else if (!options.attestationSecret && !skipSignatureVerification) {
    note = 'Kill-switch attestation requires attestationSecret for HMAC verification (fail closed)';
  } else if (attestationSignatureMatch === false) {
    note = 'Ledger attestation HMAC does not match entryHash|prevHash material';
  } else {
    note = 'Kill-switch attestation profile verification failed';
  }

  return {
    schema: KILL_SWITCH_ATTESTATION_SCHEMA,
    sku: KILL_SWITCH_ATTESTATION_SKU,
    ok,
    checks: {
      schemaValid,
      entryHashFormat,
      eventTypeValid,
      statusBlocked,
      policyIdMatch,
      targetAgentPresent,
      attestationSignaturePresent,
      attestationSignatureMatch,
      liveTestMarked,
      profileComplete,
    },
    gtmLine:
      'Underwriters ask for a tested kill switch — not a feature flag. Aevesa attests BLOCKED with offline-verifiable ledger HMAC.',
    note,
  };
}
