export declare const DELEGATION_CHAIN_SCHEMA: 'kovera-delegation-chain/1';

export interface DelegationChainVerifyResult {
  ok: boolean;
  code: string;
  depth?: number;
  chain_tip_hash?: string;
  origin_sub?: string;
  hop_index?: number | null;
}

export interface DelegationChainVerifyOptions {
  signingSecret?: string;
}

export declare function verifyDelegationChain(
  chain: unknown,
  options?: DelegationChainVerifyOptions,
): DelegationChainVerifyResult;
