export interface CausalLineageRecord {
  parent_entry_hash: string;
  parent_session_id?: string;
  root_session_id?: string;
}

export interface CausalProofBinding {
  parentEntryHash: string;
  parentSessionId?: string;
  rootSessionId?: string;
}

export declare function extractCausalLineageFromPayload(
  payload?: object | null,
): CausalLineageRecord | null;

export declare function canonicalizeCausalLineageForDigest(
  lineage?: object | null,
): CausalLineageRecord | null;

export declare function causalLineageToProofBinding(
  lineage?: object | null,
): CausalProofBinding | null;
