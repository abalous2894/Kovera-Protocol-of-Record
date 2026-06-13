export interface VerifiedPromotionPolicy {
  tenantId: string | null;
  contextStructureHash: string | null;
  allowedTransitions: string[];
  sovereigntyLawSeal: unknown;
  sealedAt: string;
  policyDialect: 'kovera-rgp/v1';
  precedentId: string | null;
  policyDiffHash: string | null;
  promotionJti: string | null;
  expiresAt: number | null;
  issuedAt: number | null;
  legacyEnvelope?: boolean;
}

export interface VerifyPolicyPromotionProofResult {
  verified: boolean;
  promotedPolicy?: VerifiedPromotionPolicy;
  promotionJti?: string | null;
  legacyEnvelope?: boolean;
  requiresBackgroundRenewal?: boolean;
  error?: string;
}

export declare function verifyPolicyPromotionProof(
  jwsString: string,
  trustedRootPublicKeys?: string[],
): Promise<VerifyPolicyPromotionProofResult>;
