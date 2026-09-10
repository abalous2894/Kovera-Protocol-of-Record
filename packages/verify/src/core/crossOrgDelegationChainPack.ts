import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import {
  buildContextBindingDigest,
  DELEGATION_STEP_RECEIPT_SCHEMA,
  type DelegationStepReceiptDocument,
  type DelegationStepReceiptInput,
  buildDelegationStepReceiptDocument,
} from './delegationStepReceipt.js';
import { stableStringify } from './stableStringify.js';

/** Wave 13 Track A — cross-org delegation chain pack (WIMSE-shaped offline verify). */

export const CROSS_ORG_DELEGATION_CHAIN_PACK_SCHEMA =
  'aevesa.cross-org-delegation-chain-pack/v1' as const;

export type ChainReadiness = 'relying_party_ready' | 'partial' | 'unverified';

export interface DelegationStepSummary {
  hop_index: number;
  receipt_digest: string;
  issuer_org_id: string;
  granted_scope_hash: string;
  context_binding_digest: string;
  parent_receipt_digest: string | null;
  on_behalf_of_principal_digest: string;
  parent_scope_hash: string;
  subject_agent_id: string;
  actor_agent_id: string;
}

export interface ChainAssertionsInput {
  third_party_verifiable: boolean;
}

export interface ChainSessionBinding {
  chain_id: string;
  root_receipt_digest: string;
  leaf_receipt_digest: string;
  hop_count: number;
  normalization_bound: boolean;
}

export interface ComposedChainMemberRef {
  member_schema: string;
  member_digest: string;
  verify_ok: boolean;
  label: string;
  entry_count?: number | null;
}

export interface CrossOrgDelegationChainPackInput {
  organization_id: string;
  chain_id: string;
  generated_at?: string;
  step_receipts: DelegationStepReceiptDocument[];
  chain_assertions: ChainAssertionsInput;
  composed_members: ComposedChainMemberRef[];
  chain_session_binding: ChainSessionBinding;
  disclaimer?: string;
}



export function buildDelegationStepSummaries(
  steps: DelegationStepReceiptDocument[],
): DelegationStepSummary[] {
  return [...steps]
    .sort((a, b) => Number(a.hop_index) - Number(b.hop_index))
    .map((step) => ({
      hop_index: Number(step.hop_index),
      receipt_digest: String(step.receipt_digest || '').toLowerCase(),
      issuer_org_id: String(step.issuer_org_id || '').trim(),
      granted_scope_hash: String(step.granted_scope_hash || '').toLowerCase(),
      context_binding_digest: String(step.context_binding_digest || '').toLowerCase(),
      parent_receipt_digest: step.parent_receipt_digest
        ? String(step.parent_receipt_digest).toLowerCase()
        : null,
      on_behalf_of_principal_digest: String(step.on_behalf_of_principal_digest || '').toLowerCase(),
      parent_scope_hash: String(step.parent_scope_hash || '').toLowerCase(),
      subject_agent_id: String(step.subject_agent_id || '').trim(),
      actor_agent_id: String(step.actor_agent_id || '').trim(),
    }));
}

export function evaluateChainIntegrity(
  steps: DelegationStepReceiptDocument[],
  organizationId: string,
  chainId: string,
) {
  const ordered = [...steps].sort((a, b) => Number(a.hop_index) - Number(b.hop_index));
  const summaries = buildDelegationStepSummaries(ordered);

  let hashChainContinuous = ordered.length >= 2;
  let attenuationMonotonic = ordered.length >= 1;
  let contextBindingsValid = ordered.length >= 1;
  let principalBound = ordered.length >= 1;
  const issuerOrgs = new Set<string>();

  const principalDigest = ordered[0]
    ? String(ordered[0].on_behalf_of_principal_digest || '').toLowerCase()
    : '';

  for (let i = 0; i < ordered.length; i += 1) {
    const step = ordered[i];
    issuerOrgs.add(String(step.issuer_org_id || '').trim());

    if (String(step.on_behalf_of_principal_digest || '').toLowerCase() !== principalDigest) {
      principalBound = false;
    }

    const expectedContext = buildContextBindingDigest({
      organization_id: organizationId,
      chain_id: chainId,
      hop_index: Number(step.hop_index),
      subject_agent_id: String(step.subject_agent_id || ''),
      actor_agent_id: String(step.actor_agent_id || ''),
      on_behalf_of_principal_digest: String(step.on_behalf_of_principal_digest || ''),
      parent_receipt_digest: step.parent_receipt_digest
        ? String(step.parent_receipt_digest).toLowerCase()
        : null,
    });
    if (String(step.context_binding_digest || '').toLowerCase() !== expectedContext.toLowerCase()) {
      contextBindingsValid = false;
    }

    if (i === 0) {
      if (
        String(step.parent_scope_hash || '').toLowerCase() !==
        String(step.granted_scope_hash || '').toLowerCase()
      ) {
        attenuationMonotonic = false;
      }
      if (step.parent_receipt_digest != null) {
        hashChainContinuous = false;
      }
    } else {
      const prev = ordered[i - 1];
      if (
        String(step.parent_scope_hash || '').toLowerCase() !==
        String(prev.granted_scope_hash || '').toLowerCase()
      ) {
        attenuationMonotonic = false;
      }
      if (
        String(step.parent_receipt_digest || '').toLowerCase() !==
        String(prev.receipt_digest || '').toLowerCase()
      ) {
        hashChainContinuous = false;
      }
    }
  }

  const crossOrg = issuerOrgs.size >= 2;
  const recursiveAttenuationValid = attenuationMonotonic && hashChainContinuous;

  return {
    summaries,
    recursive_attenuation_valid: recursiveAttenuationValid,
    hash_chain_continuous: hashChainContinuous,
    context_bindings_valid: contextBindingsValid,
    principal_bound: principalBound,
    cross_org: crossOrg,
  };
}

export function deriveChainReadiness(
  integrity: ReturnType<typeof evaluateChainIntegrity>,
  membersVerified: boolean,
  bindingMatches: boolean,
  thirdPartyVerifiable: boolean,
): ChainReadiness {
  if (
    integrity.recursive_attenuation_valid &&
    integrity.context_bindings_valid &&
    integrity.principal_bound &&
    integrity.cross_org &&
    integrity.hash_chain_continuous &&
    membersVerified &&
    bindingMatches &&
    thirdPartyVerifiable
  ) {
    return 'relying_party_ready';
  }
  if (integrity.context_bindings_valid && (membersVerified || bindingMatches)) {
    return 'partial';
  }
  return 'unverified';
}

export function buildChainAssertionsBlock(
  input: ChainAssertionsInput,
  steps: DelegationStepReceiptDocument[],
  organizationId: string,
  chainId: string,
  members: ComposedChainMemberRef[],
  bindingMatches: boolean,
) {
  const integrity = evaluateChainIntegrity(steps, organizationId, chainId);
  const stepMembers = members.filter((m) => m.member_schema === DELEGATION_STEP_RECEIPT_SCHEMA);
  const hitlMember = members.find((m) => m.member_schema === 'aevesa.hitl-preimage-binding/v1');
  const conductMember = members.find(
    (m) => m.member_schema === 'aevesa.traceable-conduct-manifest/v1',
  );
  const membersVerified =
    stepMembers.length === steps.length &&
    stepMembers.every((m) => m.verify_ok === true) &&
    (hitlMember?.verify_ok === true || hitlMember == null) &&
    (conductMember?.verify_ok === true || conductMember == null);

  const chain_readiness = deriveChainReadiness(
    integrity,
    membersVerified,
    bindingMatches,
    input.third_party_verifiable === true,
  );

  return {
    recursive_attenuation_valid: integrity.recursive_attenuation_valid,
    hash_chain_continuous: integrity.hash_chain_continuous,
    context_bindings_valid: integrity.context_bindings_valid,
    principal_bound: integrity.principal_bound,
    cross_org: integrity.cross_org,
    third_party_verifiable: input.third_party_verifiable === true,
    chain_readiness,
    hop_count: steps.length,
  };
}

export function buildCrossOrgDelegationChainPackPreimage(
  input: Omit<CrossOrgDelegationChainPackInput, 'disclaimer' | 'step_receipts'> & {
    generated_at: string;
    delegation_steps: DelegationStepSummary[];
    chain_assertions: ReturnType<typeof buildChainAssertionsBlock>;
    composed_members: ComposedChainMemberRef[];
  },
): Record<string, unknown> {
  const members = [...(input.composed_members || [])]
    .map((m) => ({
      member_schema: String(m.member_schema || '').trim(),
      member_digest: String(m.member_digest || '').trim().toLowerCase(),
      verify_ok: m.verify_ok === true,
      label: String(m.label || '').trim(),
      entry_count: m.entry_count != null ? Number(m.entry_count) : null,
    }))
    .sort((a, b) => a.member_schema.localeCompare(b.member_schema));

  const steps = [...(input.delegation_steps || [])].sort(
    (a, b) => a.hop_index - b.hop_index,
  );

  return {
    schema: CROSS_ORG_DELEGATION_CHAIN_PACK_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    chain_id: String(input.chain_id || '').trim(),
    generated_at: input.generated_at,
    delegation_steps: steps,
    chain_assertions: input.chain_assertions,
    composed_members: members,
    chain_session_binding: {
      chain_id: String(input.chain_session_binding.chain_id || '').trim(),
      root_receipt_digest: String(input.chain_session_binding.root_receipt_digest || '')
        .trim()
        .toLowerCase(),
      leaf_receipt_digest: String(input.chain_session_binding.leaf_receipt_digest || '')
        .trim()
        .toLowerCase(),
      hop_count: Number(input.chain_session_binding.hop_count),
      normalization_bound: input.chain_session_binding.normalization_bound === true,
    },
  };
}

export function buildDelegationStepReceiptChain(
  organizationId: string,
  chainId: string,
  hopInputs: Omit<
    DelegationStepReceiptInput,
    'organization_id' | 'chain_id' | 'hop_index' | 'parent_receipt_digest' | 'parent_scope_hash'
  >[],
) {
  const receipts: DelegationStepReceiptDocument[] = [];
  for (let i = 0; i < hopInputs.length; i += 1) {
    const prev = receipts[i - 1];
    const receipt = buildDelegationStepReceiptDocument({
      ...hopInputs[i],
      organization_id: organizationId,
      chain_id: chainId,
      hop_index: i,
      parent_receipt_digest: prev ? String(prev.receipt_digest).toLowerCase() : null,
      parent_scope_hash: prev ? String(prev.granted_scope_hash).toLowerCase() : undefined,
    });
    receipts.push(receipt);
  }
  return receipts;
}

export function buildCrossOrgDelegationChainPackDocument(input: CrossOrgDelegationChainPackInput) {
  const generated_at = input.generated_at || new Date().toISOString();
  const ordered = [...input.step_receipts].sort(
    (a, b) => Number(a.hop_index) - Number(b.hop_index),
  );
  const delegation_steps = buildDelegationStepSummaries(ordered);

  const root = ordered[0];
  const leaf = ordered[ordered.length - 1];
  const bindingMatches =
    String(input.chain_session_binding.root_receipt_digest || '').toLowerCase() ===
      String(root?.receipt_digest || '').toLowerCase() &&
    String(input.chain_session_binding.leaf_receipt_digest || '').toLowerCase() ===
      String(leaf?.receipt_digest || '').toLowerCase() &&
    Number(input.chain_session_binding.hop_count) === ordered.length &&
    String(input.chain_session_binding.chain_id || '') === String(input.chain_id || '');

  const chain_assertions = buildChainAssertionsBlock(
    input.chain_assertions,
    ordered,
    input.organization_id,
    input.chain_id,
    input.composed_members,
    bindingMatches && input.chain_session_binding.normalization_bound === true,
  );

  const preimage = buildCrossOrgDelegationChainPackPreimage({
    organization_id: input.organization_id,
    chain_id: input.chain_id,
    generated_at,
    delegation_steps,
    chain_assertions,
    composed_members: input.composed_members,
    chain_session_binding: input.chain_session_binding,
  });
  const pack_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    pack_digest,
    disclaimer:
      input.disclaimer ||
      'Cross-org delegation evidence — not legal advice or authorization to act.',
  };
}

export default {
  CROSS_ORG_DELEGATION_CHAIN_PACK_SCHEMA,
  buildCrossOrgDelegationChainPackDocument,
  buildDelegationStepReceiptChain,
  evaluateChainIntegrity,
};
