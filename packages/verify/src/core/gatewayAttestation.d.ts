export interface GatewayAttestationRecord {
  gateway_decision_id: string;
  gateway_source: string;
  decision: 'permit' | 'deny';
  gateway_event_hash?: string;
  data_classification_tag?: string;
  policy_reference?: string;
  evaluated_at?: string;
}

export declare function canonicalizeGatewayAttestationForDigest(
  raw?: object | null,
): GatewayAttestationRecord | null;
