/**
 * Wave 2.1 — portable offline verify for kovera-delegation-chain/1.
 */

import { createHmac, createHash } from 'node:crypto';

export const DELEGATION_CHAIN_SCHEMA = 'kovera-delegation-chain/1';
export const HDP_HOP_SCHEMA = 'aevesa.hdp-hop-receipt/v1';
export const DELEGATION_CHAIN_DEMO_SIGNING_SECRET = 'kovera-delegation-chain-demo-v1-public';

export function hopPayloadMaterial(hop) {
  return JSON.stringify({
    schema: hop.schema,
    hop_index: hop.hop_index,
    session_id: hop.session_id,
    parent_session_id: hop.parent_session_id ?? null,
    parent_hop_hash: hop.parent_hop_hash ?? null,
    scope_hash: hop.scope_hash ?? null,
    agent_id: hop.agent_id ?? null,
    passport_jti: hop.passport_jti ?? null,
    issued_at: hop.issued_at,
  });
}

export function scopeHashFromEffectiveAccess(scopes = [], tools = []) {
  const payload = {
    effective_scopes: [...scopes].map(String).sort(),
    effective_tools: [...tools].map(String).sort(),
  };
  return createHash('sha256').update(JSON.stringify(payload), 'utf8').digest('hex');
}

function isSubset(parentScopes = [], childScopes = []) {
  const parent = new Set(parentScopes.map(String));
  return childScopes.every((s) => parent.has(String(s)));
}

function isToolSubset(parentTools = [], childTools = []) {
  const parent = new Set(parentTools.map(String));
  return childTools.every((t) => parent.has(String(t)));
}

export function verifyHdpHopReceipt(hop, signingSecret) {
  if (!hop || hop.schema !== HDP_HOP_SCHEMA) {
    return { ok: false, code: 'INVALID_HOP_SCHEMA' };
  }
  const { hop_hash, signature, signature_alg, ...rest } = hop;
  const material = { ...rest, schema: HDP_HOP_SCHEMA };
  const expectedHash = createHash('sha256').update(hopPayloadMaterial(material), 'utf8').digest('hex');
  if (expectedHash !== hop_hash) {
    return { ok: false, code: 'HOP_HASH_MISMATCH' };
  }
  const expectedSig = createHmac('sha256', signingSecret).update(hop_hash, 'utf8').digest('hex');
  if (expectedSig !== signature) {
    return { ok: false, code: 'HOP_SIGNATURE_INVALID' };
  }
  return { ok: true, code: 'HOP_VERIFIED', hop_hash };
}

export function verifyHdpHopChain(hops, signingSecret) {
  if (!Array.isArray(hops) || hops.length === 0) {
    return { ok: false, code: 'EMPTY_CHAIN' };
  }
  let prevHash = null;
  for (let i = 0; i < hops.length; i += 1) {
    const v = verifyHdpHopReceipt(hops[i], signingSecret);
    if (!v.ok) return { ok: false, code: v.code, hop_index: i };
    if (i > 0 && hops[i].parent_hop_hash !== prevHash) {
      return { ok: false, code: 'CHAIN_LINK_BROKEN', hop_index: i };
    }
    prevHash = hops[i].hop_hash;
  }
  return { ok: true, code: 'CHAIN_VERIFIED', hop_count: hops.length, chain_tip_hash: prevHash };
}

/**
 * @param {object} chain
 * @param {{ signingSecret?: string }} [options]
 */
export function verifyDelegationChain(chain, options = {}) {
  const signingSecretRaw = options.signingSecret;
  const signingSecret =
    signingSecretRaw != null && String(signingSecretRaw).trim()
      ? String(signingSecretRaw).trim()
      : '';
  if (!signingSecret) {
    return { ok: false, code: 'MISSING_SIGNING_SECRET' };
  }

  if (!chain || chain.schema !== DELEGATION_CHAIN_SCHEMA) {
    return { ok: false, code: 'INVALID_CHAIN_SCHEMA' };
  }
  if (!chain.origin?.origin_sub) {
    return { ok: false, code: 'ORIGIN_SUB_REQUIRED' };
  }
  const links = chain.links || [];
  if (!Array.isArray(links) || links.length === 0) {
    return { ok: false, code: 'EMPTY_LINKS' };
  }
  if (chain.depth !== links.length) {
    return { ok: false, code: 'DEPTH_MISMATCH' };
  }

  for (let i = 0; i < links.length; i += 1) {
    const link = links[i];
    if (link.hop_index !== i) {
      return { ok: false, code: 'HOP_INDEX_MISMATCH', hop_index: i };
    }
    if (i > 0) {
      const parent = links[i - 1];
      if (link.parent_agent_run_id !== parent.agent_run_id) {
        return { ok: false, code: 'PARENT_RUN_ID_MISMATCH', hop_index: i };
      }
      if (!isSubset(parent.effective_scopes || [], link.effective_scopes || [])) {
        return { ok: false, code: 'SCOPE_NOT_NARROWED', hop_index: i };
      }
      if (!isToolSubset(parent.effective_tools || [], link.effective_tools || [])) {
        return { ok: false, code: 'TOOLS_NOT_NARROWED', hop_index: i };
      }
      if ((link.remaining_budget_cents ?? 0) > (parent.remaining_budget_cents ?? 0)) {
        return { ok: false, code: 'BUDGET_NOT_PROPAGATED', hop_index: i };
      }
    }
  }

  const hops = chain.proof?.hops;
  if (!Array.isArray(hops) || hops.length !== links.length) {
    return { ok: false, code: 'PROOF_HOP_COUNT_MISMATCH' };
  }
  const hopVerify = verifyHdpHopChain(hops, signingSecret);
  if (!hopVerify.ok) {
    return { ok: false, code: hopVerify.code, hop_index: hopVerify.hop_index ?? null };
  }

  return {
    ok: true,
    code: 'DELEGATION_CHAIN_VERIFIED',
    depth: links.length,
    chain_tip_hash: chain.proof?.chain_tip_hash ?? hopVerify.chain_tip_hash,
    origin_sub: chain.origin.origin_sub,
  };
}

export function buildDelegationChainProofTrace(chain, options = {}) {
  const verify = verifyDelegationChain(chain, options);
  const steps = [
    {
      key: 'schema',
      label: 'kovera-delegation-chain/1 schema recognized',
      ok: chain?.schema === DELEGATION_CHAIN_SCHEMA,
    },
    {
      key: 'origin',
      label: 'Human origin invariant (origin_sub present)',
      ok: Boolean(chain?.origin?.origin_sub),
      detail: chain?.origin?.origin_sub ? `origin_sub: ${chain.origin.origin_sub}` : null,
    },
    {
      key: 'depth',
      label: 'ADCS depth matches links[] length',
      ok: chain?.depth === (chain?.links?.length ?? 0),
      detail: `depth=${chain?.depth ?? 0}`,
    },
    {
      key: 'scope_narrowing',
      label: 'Monotonic scope + tool narrowing (Agent A → Agent B)',
      ok: verify.code !== 'SCOPE_NOT_NARROWED' && verify.code !== 'TOOLS_NOT_NARROWED',
    },
    {
      key: 'hdp_proof',
      label: 'HDP hop chain signatures + parent_hop_hash links',
      ok: verify.code === 'DELEGATION_CHAIN_VERIFIED' || verify.code === 'HOP_VERIFIED',
      detail: verify.code,
    },
    {
      key: 'verified',
      label: 'Full delegation chain verified offline',
      ok: verify.ok === true,
      detail: verify.chain_tip_hash ? `tip: ${verify.chain_tip_hash.slice(0, 16)}…` : verify.code,
    },
  ];
  return { ok: verify.ok === true, verify, steps };
}

export default {
  DELEGATION_CHAIN_SCHEMA,
  DELEGATION_CHAIN_DEMO_SIGNING_SECRET,
  verifyDelegationChain,
  buildDelegationChainProofTrace,
};
