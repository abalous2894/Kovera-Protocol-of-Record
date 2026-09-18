/**
 * Optional embedded issuer public key on liability-receipt/v1 integrity block (PC-05 optional).
 * Safe additive field — offline verify when PEM/JWK travels with the receipt.
 */

export type IntegrityWithEmbeddedKey = {
  issuer_public_key_pem?: string | null;
  issuer_public_key_jwk?: string | Record<string, unknown> | null;
};

/**
 * Resolve issuer verification material from integrity block when not passed via options.
 */
export function resolveEmbeddedIssuerPublicKey(
  integrity: IntegrityWithEmbeddedKey | null | undefined,
): string | undefined {
  if (!integrity || typeof integrity !== 'object') return undefined;

  const pem = String(integrity.issuer_public_key_pem || '').trim();
  if (pem.length > 0) return pem;

  const jwkRaw = integrity.issuer_public_key_jwk;
  if (jwkRaw == null) return undefined;
  if (typeof jwkRaw === 'string') {
    const trimmed = jwkRaw.trim();
    return trimmed.length > 0 ? trimmed : undefined;
  }
  if (typeof jwkRaw === 'object') {
    try {
      return JSON.stringify(jwkRaw);
    } catch {
      return undefined;
    }
  }
  return undefined;
}
