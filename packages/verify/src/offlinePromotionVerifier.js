/**
 * APoR — offline policy promotion proof verification (stateless, zero I/O).
 * Validates aevesa-rgp/v1 promotion JWS envelopes without database access.
 */

import * as jose from 'jose';
import { z } from 'zod';

const KoveraRgpPromotionPayloadSchema = z.object({
  policyDialect: z.literal('aevesa-rgp/v1').optional(),
  policy_dialect: z.literal('aevesa-rgp/v1').optional(),
  tenantId: z.string().min(1).optional(),
  tenant_id: z.string().min(1).optional(),
  contextStructureHash: z.string().min(1).optional(),
  context_structure_hash: z.string().min(1).optional(),
  allowedTransitions: z.array(z.string()).optional(),
  allowed_transitions: z.array(z.string()).optional(),
  sovereigntyLawSeal: z.union([z.record(z.unknown()), z.string().min(1)]).optional(),
  sovereignty_law_seal: z.union([z.record(z.unknown()), z.string().min(1)]).optional(),
  sovereignty_law_seal_digest: z.string().min(1).optional(),
  timestamp: z.string().optional(),
  promoted_at: z.string().optional(),
  type: z.string().optional(),
  version: z.string().optional(),
  precedent_id: z.string().optional(),
  policy_diff_hash: z.string().optional(),
  jti: z.string().min(1).optional(),
  exp: z.number().optional(),
  iat: z.number().optional(),
});

/**
 * @param {string} keyMaterial PEM SPKI, compact JWK JSON, or CryptoKey-like import source
 */
async function importTrustedPublicKey(keyMaterial) {
  const raw = String(keyMaterial ?? '').trim();
  if (!raw) throw new Error('Empty trusted public key material.');

  if (raw.startsWith('{')) {
    const jwk = JSON.parse(raw);
    if (jwk.alg && jwk.alg !== 'RS256') {
      throw new Error('Unsupported JWK algorithm — expected RS256.');
    }
    return jose.importJWK(jwk, 'RS256');
  }

  if (raw.includes('BEGIN PUBLIC KEY')) {
    return jose.importSPKI(raw, 'RS256');
  }

  throw new Error('Unsupported trusted public key format (expected PEM SPKI or JWK JSON).');
}

function normalizePromotionPayload(payload) {
  const policyDialect = payload.policyDialect || payload.policy_dialect || null;
  const tenantId = payload.tenantId || payload.tenant_id || null;
  const contextStructureHash = payload.contextStructureHash || payload.context_structure_hash || null;
  const allowedTransitions = payload.allowedTransitions || payload.allowed_transitions || [];
  const sovereigntyLawSeal = (
    payload.sovereigntyLawSeal
    ?? payload.sovereignty_law_seal
    ?? (payload.sovereignty_law_seal_digest
      ? { digest: payload.sovereignty_law_seal_digest }
      : null)
  );
  const sealedAt = payload.timestamp || payload.promoted_at || new Date().toISOString();

  return {
    policyDialect,
    tenantId,
    contextStructureHash,
    allowedTransitions: Array.isArray(allowedTransitions) ? allowedTransitions : [],
    sovereigntyLawSeal,
    sealedAt,
    promotionJti: payload.jti || null,
    expiresAt: payload.exp || null,
    issuedAt: payload.iat || null,
  };
}

function buildVerifiedResult(parsed, verifiedPayload, options = {}) {
  const normalized = normalizePromotionPayload(parsed.data);
  return {
    verified: true,
    promotionJti: normalized.promotionJti || verifiedPayload.jti || null,
    legacyEnvelope: Boolean(options.legacyEnvelope),
    requiresBackgroundRenewal: Boolean(options.requiresBackgroundRenewal),
    promotedPolicy: {
      tenantId: normalized.tenantId,
      contextStructureHash: normalized.contextStructureHash,
      allowedTransitions: normalized.allowedTransitions,
      sovereigntyLawSeal: normalized.sovereigntyLawSeal,
      sealedAt: normalized.sealedAt,
      policyDialect: 'aevesa-rgp/v1',
      precedentId: parsed.data.precedent_id || null,
      policyDiffHash: parsed.data.policy_diff_hash || null,
      promotionJti: normalized.promotionJti || verifiedPayload.jti || null,
      expiresAt: normalized.expiresAt,
      issuedAt: normalized.issuedAt,
      legacyEnvelope: Boolean(options.legacyEnvelope),
    },
  };
}

function validateKoveraRgpStructures(normalized) {
  return (
    normalized.policyDialect === 'aevesa-rgp/v1'
    && normalized.contextStructureHash
    && normalized.sovereigntyLawSeal
  );
}

function emitMigrationWarn(precedentId) {
  console.warn('[MIGRATION_WARN] Processing legacy non-enveloped JWS token.', {
    precedent_id: precedentId || null,
    timestamp: new Date().toISOString(),
  });
}

/**
 * Validates an APoR policy promotion proof completely offline.
 *
 * @param {string} jwsString Signed JWS promotion envelope.
 * @param {Array<string>} trustedRootPublicKeys PEM/JWK public keys allowed to sign promotions.
 * @returns {Promise<{ verified: boolean, promotedPolicy?: object, promotionJti?: string, legacyEnvelope?: boolean, requiresBackgroundRenewal?: boolean, error?: string }>}
 */
export async function verifyPolicyPromotionProof(jwsString, trustedRootPublicKeys = []) {
  try {
    const compact = String(jwsString || '').trim();
    if (!compact) {
      return { verified: false, error: 'Missing policy promotion JWS string.' };
    }

    if (compact.split('.').length !== 3) {
      return { verified: false, error: 'APoR JWS malformed: expected compact JWT.' };
    }

    const keys = Array.isArray(trustedRootPublicKeys) ? trustedRootPublicKeys : [];
    if (keys.length === 0) {
      return { verified: false, error: 'No trusted root public keys supplied for verification.' };
    }

    /** @type {jose.JWTPayload | null} */
    let verifiedPayload = null;

    for (const keyMaterial of keys) {
      try {
        const publicKey = await importTrustedPublicKey(keyMaterial);
        const verified = await jose.jwtVerify(compact, publicKey, {
          algorithms: ['RS256'],
          maxTokenAge: '30d',
          clockTolerance: 30,
        });
        verifiedPayload = verified.payload;

        if (!verifiedPayload.jti || typeof verifiedPayload.jti !== 'string') {
          return { verified: false, error: 'Missing promotion jti — replay protection required.' };
        }

        const parsed = KoveraRgpPromotionPayloadSchema.safeParse(verifiedPayload);
        if (!parsed.success) {
          return { verified: false, error: 'Malformed promotion payload: schema validation failed.' };
        }

        const normalized = normalizePromotionPayload(parsed.data);
        if (!validateKoveraRgpStructures(normalized)) {
          return {
            verified: false,
            error: 'Malformed policy dialect: Missing aevesa-rgp/v1 schema structures.',
          };
        }

        return buildVerifiedResult(parsed, verifiedPayload, {
          legacyEnvelope: false,
          requiresBackgroundRenewal: false,
        });
      } catch {
        // try next trusted root key on strict path
      }
    }

    return { verified: false, error: 'APoR Signature Verification Failed: Untrusted promotion key or expired token.' };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { verified: false, error: `Stateless validation error: ${message}` };
  }
}
