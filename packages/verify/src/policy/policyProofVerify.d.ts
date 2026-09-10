export declare const POLICY_PROOF_BUNDLE_SCHEMA: 'aevesa.policy-proof-bundle/v1';
export declare const POLICY_PROOF_VERIFY_SCHEMA: 'aevesa.policy-proof-verify/v1';

export declare function computePolicyProofDigest(bundle: object): string;

export declare function verifyPolicyProofBundle(
  bundle: unknown,
  opts?: { skipReceipt?: boolean },
): Record<string, unknown>;
