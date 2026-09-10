import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';

/** Wave 13 Track A — per-hop delegation step receipt (anti-splicing context bind). */

export const DELEGATION_STEP_RECEIPT_SCHEMA = 'aevesa.delegation-step-receipt/v1' as const;
export const DELEGATION_CONTEXT_SCHEMA = 'aevesa.delegation-context/v1' as const;

export interface DelegationStepReceiptInput {
  organization_id: string;
  chain_id: string;
  hop_index: number;
  issuer_org_id: string;
  issuer_sts_id: string;
  subject_agent_id: string;
  actor_agent_id: string;
  on_behalf_of_principal_digest: string;
  effective_scopes: string[];
  effective_tools: string[];
  parent_scope_hash?: string | null;
  parent_receipt_digest?: string | null;
  issued_at: string;
  expires_at: string;
  generated_at?: string;
}



export function scopeHashFromEffectiveAccess(scopes: string[] = [], tools: string[] = []): string {
  const payload = {
    effective_scopes: [...scopes].map(String).sort(),
    effective_tools: [...tools].map(String).sort(),
  };
  return createHash('sha256').update(JSON.stringify(payload), 'utf8').digest('hex');
}

export function buildGrantedScopeHash(scopes: string[], tools: string[]): string {
  return scopeHashFromEffectiveAccess(scopes, tools).toLowerCase();
}

export function buildContextBindingDigest(input: {
  organization_id: string;
  chain_id: string;
  hop_index: number;
  subject_agent_id: string;
  actor_agent_id: string;
  on_behalf_of_principal_digest: string;
  parent_receipt_digest: string | null;
}): string {
  return sha256HexUtf8(
    stableStringify({
      schema: DELEGATION_CONTEXT_SCHEMA,
      organization_id: String(input.organization_id || '').trim(),
      chain_id: String(input.chain_id || '').trim(),
      hop_index: Number(input.hop_index),
      subject_agent_id: String(input.subject_agent_id || '').trim(),
      actor_agent_id: String(input.actor_agent_id || '').trim(),
      on_behalf_of_principal_digest: String(input.on_behalf_of_principal_digest || '')
        .trim()
        .toLowerCase(),
      parent_receipt_digest: input.parent_receipt_digest
        ? String(input.parent_receipt_digest).trim().toLowerCase()
        : null,
    }),
  );
}

export function buildDelegationStepReceiptPreimage(
  input: DelegationStepReceiptInput & {
    generated_at: string;
    granted_scope_hash: string;
    parent_scope_hash: string;
    context_binding_digest: string;
    attenuation_valid: boolean;
  },
): Record<string, unknown> {
  return {
    schema: DELEGATION_STEP_RECEIPT_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    chain_id: String(input.chain_id || '').trim(),
    hop_index: Number(input.hop_index),
    issuer_org_id: String(input.issuer_org_id || '').trim(),
    issuer_sts_id: String(input.issuer_sts_id || '').trim(),
    subject_agent_id: String(input.subject_agent_id || '').trim(),
    actor_agent_id: String(input.actor_agent_id || '').trim(),
    on_behalf_of_principal_digest: String(input.on_behalf_of_principal_digest || '')
      .trim()
      .toLowerCase(),
    parent_scope_hash: String(input.parent_scope_hash || '').trim().toLowerCase(),
    granted_scope_hash: String(input.granted_scope_hash || '').trim().toLowerCase(),
    attenuation_valid: input.attenuation_valid === true,
    context_binding_digest: String(input.context_binding_digest || '').trim().toLowerCase(),
    parent_receipt_digest: input.parent_receipt_digest
      ? String(input.parent_receipt_digest).trim().toLowerCase()
      : null,
    issued_at: String(input.issued_at || '').trim(),
    expires_at: String(input.expires_at || '').trim(),
    generated_at: input.generated_at,
  };
}

export interface DelegationStepReceiptDocument {
  schema: typeof DELEGATION_STEP_RECEIPT_SCHEMA;
  organization_id: string;
  chain_id: string;
  hop_index: number;
  issuer_org_id: string;
  issuer_sts_id: string;
  subject_agent_id: string;
  actor_agent_id: string;
  on_behalf_of_principal_digest: string;
  parent_scope_hash: string;
  granted_scope_hash: string;
  attenuation_valid: boolean;
  context_binding_digest: string;
  parent_receipt_digest: string | null;
  issued_at: string;
  expires_at: string;
  generated_at: string;
  receipt_digest: string;
}

export function buildDelegationStepReceiptDocument(
  input: DelegationStepReceiptInput,
): DelegationStepReceiptDocument {
  const generated_at = input.generated_at || new Date().toISOString();
  const granted_scope_hash = buildGrantedScopeHash(input.effective_scopes, input.effective_tools);
  const parent_scope_hash =
    input.parent_scope_hash != null && String(input.parent_scope_hash).trim()
      ? String(input.parent_scope_hash).trim().toLowerCase()
      : granted_scope_hash;
  const parent_receipt_digest =
    input.parent_receipt_digest != null && String(input.parent_receipt_digest).trim()
      ? String(input.parent_receipt_digest).trim().toLowerCase()
      : null;

  const context_binding_digest = buildContextBindingDigest({
    organization_id: input.organization_id,
    chain_id: input.chain_id,
    hop_index: input.hop_index,
    subject_agent_id: input.subject_agent_id,
    actor_agent_id: input.actor_agent_id,
    on_behalf_of_principal_digest: input.on_behalf_of_principal_digest,
    parent_receipt_digest,
  });

  const attenuation_valid =
    input.hop_index === 0
      ? parent_scope_hash === granted_scope_hash
      : Boolean(parent_receipt_digest);

  const preimage = buildDelegationStepReceiptPreimage({
    ...input,
    generated_at,
    granted_scope_hash,
    parent_scope_hash,
    context_binding_digest,
    attenuation_valid,
    parent_receipt_digest,
  });
  const receipt_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    receipt_digest,
  } as DelegationStepReceiptDocument;
}

export default {
  DELEGATION_STEP_RECEIPT_SCHEMA,
  DELEGATION_CONTEXT_SCHEMA,
  buildDelegationStepReceiptDocument,
  buildContextBindingDigest,
  buildGrantedScopeHash,
};
