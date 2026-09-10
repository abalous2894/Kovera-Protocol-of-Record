import { sha256HexUtf8 } from '../core/sha256.js';
import { buildCrossOrgDelegationChainPackPreimage, CROSS_ORG_DELEGATION_CHAIN_PACK_SCHEMA, type ChainReadiness } from '../core/crossOrgDelegationChainPack.js';
import { buildContextBindingDigest, DELEGATION_STEP_RECEIPT_SCHEMA } from '../core/delegationStepReceipt.js';
import { stableStringify } from '../core/stableStringify.js';

export const CROSS_ORG_DELEGATION_CHAIN_PACK_SKU =
  'aevesa-cross-org-delegation-chain-pack-v1' as const;

const HEX64 = /^[a-f0-9]{64}$/;
const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|ssn|phone|address|pan|cvv)$/i;

export interface CrossOrgDelegationChainPackVerifyResult {
  schema: typeof CROSS_ORG_DELEGATION_CHAIN_PACK_SCHEMA;
  sku: typeof CROSS_ORG_DELEGATION_CHAIN_PACK_SKU;
  ok: boolean;
  checks: Record<string, boolean>;
  chain_readiness: ChainReadiness | null;
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

export function verifyCrossOrgDelegationChainPack(
  docInput: unknown,
): CrossOrgDelegationChainPackVerifyResult {
  const doc = asRecord(docInput);
  const schemaValid = doc?.schema === CROSS_ORG_DELEGATION_CHAIN_PACK_SCHEMA;
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;
  const chainIdPresent = String(doc?.chain_id || '').trim().length > 0;

  const steps = Array.isArray(doc?.delegation_steps) ? doc.delegation_steps : [];
  const stepsPresent = steps.length >= 2;
  const stepDigestsValid =
    steps.length === 0 ||
    steps.every((s) => HEX64.test(String(s?.receipt_digest || '').toLowerCase()));

  const members = Array.isArray(doc?.composed_members) ? doc.composed_members : [];
  const memberDigestsValid =
    members.length === 0 ||
    members.every((m) => HEX64.test(String(m?.member_digest || '').toLowerCase()));

  const binding = asRecord(doc?.chain_session_binding) || {};
  const bindingDigestsValid =
    HEX64.test(String(binding.root_receipt_digest || '').toLowerCase()) &&
    HEX64.test(String(binding.leaf_receipt_digest || '').toLowerCase());

  const orderedSteps = [...steps].sort(
    (a, b) => Number(a?.hop_index) - Number(b?.hop_index),
  );
  const rootStep = orderedSteps[0];
  const leafStep = orderedSteps[orderedSteps.length - 1];

  const bindingMatchesSteps =
    String(binding.chain_id || '') === String(doc?.chain_id || '') &&
    Number(binding.hop_count) === steps.length &&
    String(binding.root_receipt_digest || '').toLowerCase() ===
      String(rootStep?.receipt_digest || '').toLowerCase() &&
    String(binding.leaf_receipt_digest || '').toLowerCase() ===
      String(leafStep?.receipt_digest || '').toLowerCase();

  let hashChainContinuous = stepsPresent;
  let attenuationMonotonic = stepsPresent;
  let contextBindingsConsistent = stepsPresent;
  let principalConsistent = stepsPresent;
  const issuerOrgs = new Set<string>();

  if (stepsPresent) {
    const principal = String(rootStep?.on_behalf_of_principal_digest || '').toLowerCase();
    for (let i = 0; i < orderedSteps.length; i += 1) {
      const step = orderedSteps[i];
      issuerOrgs.add(String(step?.issuer_org_id || '').trim());
      if (String(step?.on_behalf_of_principal_digest || '').toLowerCase() !== principal) {
        principalConsistent = false;
      }
      if (step?.context_binding_digest == null) {
        contextBindingsConsistent = false;
      }
      if (i === 0) {
        if (step?.parent_receipt_digest != null) hashChainContinuous = false;
        if (
          String(step?.parent_scope_hash || '').toLowerCase() !==
          String(step?.granted_scope_hash || '').toLowerCase()
        ) {
          attenuationMonotonic = false;
        }
      } else {
        const prev = orderedSteps[i - 1];
        if (
          String(step?.parent_receipt_digest || '').toLowerCase() !==
          String(prev?.receipt_digest || '').toLowerCase()
        ) {
          hashChainContinuous = false;
        }
        if (
          String(step?.parent_scope_hash || '').toLowerCase() !==
          String(prev?.granted_scope_hash || '').toLowerCase()
        ) {
          attenuationMonotonic = false;
        }
      }
    }
  }

  const crossOrgBoundary = issuerOrgs.size >= 2;

  const stepMembers = members.filter((m) => m?.member_schema === DELEGATION_STEP_RECEIPT_SCHEMA);
  const bindingMatchesMembers =
    bindingMatchesSteps &&
    stepMembers.length >= steps.length &&
    orderedSteps.every((step) =>
      stepMembers.some(
        (m) =>
          String(m?.member_digest || '').toLowerCase() ===
          String(step?.receipt_digest || '').toLowerCase(),
      ),
    );

  const assertions = asRecord(doc?.chain_assertions) || {};
  const derivedReadiness = String(assertions.chain_readiness || '') as ChainReadiness;
  const normalizationBound = binding.normalization_bound === true;

  let chainAssertionsConsistent =
    assertions.third_party_verifiable === true && chainIdPresent;

  if (derivedReadiness === 'relying_party_ready') {
    chainAssertionsConsistent =
      chainAssertionsConsistent &&
      assertions.recursive_attenuation_valid === true &&
      assertions.hash_chain_continuous === true &&
      assertions.context_bindings_valid === true &&
      assertions.principal_bound === true &&
      assertions.cross_org === true &&
      hashChainContinuous &&
      attenuationMonotonic &&
      contextBindingsConsistent &&
      principalConsistent &&
      crossOrgBoundary &&
      bindingMatchesMembers &&
      normalizationBound;
  } else if (derivedReadiness === 'partial') {
    chainAssertionsConsistent =
      chainAssertionsConsistent &&
      assertions.context_bindings_valid === true &&
      bindingMatchesMembers;
  }

  const readinessConsistent = assertions.chain_readiness === derivedReadiness;

  let packDigestMatches = false;
  if (schemaValid && doc && bindingDigestsValid && bindingMatchesSteps) {
    const preimage = buildCrossOrgDelegationChainPackPreimage({
      organization_id: String(doc.organization_id),
      chain_id: String(doc.chain_id),
      generated_at: String(doc.generated_at || ''),
      delegation_steps: orderedSteps.map((s) => ({
        hop_index: Number(s?.hop_index),
        receipt_digest: String(s?.receipt_digest || ''),
        issuer_org_id: String(s?.issuer_org_id || ''),
        granted_scope_hash: String(s?.granted_scope_hash || ''),
        context_binding_digest: String(s?.context_binding_digest || ''),
        parent_receipt_digest: s?.parent_receipt_digest
          ? String(s.parent_receipt_digest).toLowerCase()
          : null,
        on_behalf_of_principal_digest: String(s?.on_behalf_of_principal_digest || ''),
        parent_scope_hash: String(s?.parent_scope_hash || ''),
        subject_agent_id: String(s?.subject_agent_id || ''),
        actor_agent_id: String(s?.actor_agent_id || ''),
      })),
      chain_assertions: {
        recursive_attenuation_valid: assertions.recursive_attenuation_valid === true,
        hash_chain_continuous: assertions.hash_chain_continuous === true,
        context_bindings_valid: assertions.context_bindings_valid === true,
        principal_bound: assertions.principal_bound === true,
        cross_org: assertions.cross_org === true,
        third_party_verifiable: assertions.third_party_verifiable === true,
        chain_readiness: derivedReadiness,
        hop_count: Number(assertions.hop_count ?? steps.length),
      },
      composed_members: members.map((m) => ({
        member_schema: String(m?.member_schema || ''),
        member_digest: String(m?.member_digest || ''),
        verify_ok: m?.verify_ok === true,
        label: String(m?.label || ''),
        entry_count: m?.entry_count ?? null,
      })),
      chain_session_binding: {
        chain_id: String(binding.chain_id || ''),
        root_receipt_digest: String(binding.root_receipt_digest || ''),
        leaf_receipt_digest: String(binding.leaf_receipt_digest || ''),
        hop_count: Number(binding.hop_count),
        normalization_bound: normalizationBound,
      },
    });
    const expected = sha256HexUtf8(stableStringify(preimage));
    packDigestMatches = String(doc.pack_digest || '').toLowerCase() === expected;
  }

  if (stepsPresent && organizationIdPresent && chainIdPresent && doc) {
    for (let i = 0; i < orderedSteps.length; i += 1) {
      const step = orderedSteps[i];
      const expectedContext = buildContextBindingDigest({
        organization_id: String(doc.organization_id),
        chain_id: String(doc.chain_id),
        hop_index: Number(step?.hop_index),
        subject_agent_id: String(step?.subject_agent_id || ''),
        actor_agent_id: String(step?.actor_agent_id || ''),
        on_behalf_of_principal_digest: String(step?.on_behalf_of_principal_digest || ''),
        parent_receipt_digest: step?.parent_receipt_digest
          ? String(step.parent_receipt_digest).toLowerCase()
          : null,
      });
      if (
        String(step?.context_binding_digest || '').toLowerCase() !== expectedContext.toLowerCase()
      ) {
        contextBindingsConsistent = false;
        break;
      }
    }
  }

  const hashOnlySurface = !hasForbiddenKeys(doc);

  const profileComplete =
    schemaValid &&
    organizationIdPresent &&
    chainIdPresent &&
    stepsPresent &&
    stepDigestsValid &&
    hashChainContinuous &&
    attenuationMonotonic &&
    contextBindingsConsistent &&
    principalConsistent &&
    crossOrgBoundary &&
    bindingMatchesMembers &&
    memberDigestsValid &&
    bindingDigestsValid &&
    chainAssertionsConsistent &&
    packDigestMatches &&
    hashOnlySurface &&
    readinessConsistent;

  let note: string | null = null;
  if (!schemaValid) note = `schema must be ${CROSS_ORG_DELEGATION_CHAIN_PACK_SCHEMA}`;
  else if (!contextBindingsConsistent) note = 'context binding splice detected — hop parent mismatch';
  else if (!bindingMatchesMembers) note = 'chain_session_binding digests must match delegation_steps';
  else if (!crossOrgBoundary) note = 'cross-org chain requires at least two distinct issuer_org_id values';
  else if (!packDigestMatches) note = 'pack_digest does not match canonical preimage';
  else if (!chainAssertionsConsistent) note = 'chain_assertions inconsistent with steps or binding';

  return {
    schema: CROSS_ORG_DELEGATION_CHAIN_PACK_SCHEMA,
    sku: CROSS_ORG_DELEGATION_CHAIN_PACK_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      organizationIdPresent,
      chainIdPresent,
      stepsPresent,
      stepDigestsValid,
      hashChainContinuous,
      attenuationMonotonic,
      contextBindingsConsistent,
      principalConsistent,
      crossOrgBoundary,
      bindingMatchesMembers,
      memberDigestsValid,
      bindingDigestsValid,
      chainAssertionsConsistent,
      packDigestMatches,
      hashOnlySurface,
      readinessConsistent,
      profileComplete,
    },
    chain_readiness: derivedReadiness || null,
    gtmLine:
      'RFC 8693 delegation history is forgeable. Aevesa proves every hop across org boundaries — offline, splice-resistant.',
    note,
  };
}
