export declare const CONFORMANCE_ATTESTATION_SCHEMA: 'aevesa.conformance-attestation/v1';

export declare function computeConformanceAttestationDigest(attestation: object): string;

export declare function buildConformanceAttestation(input: {
  apiBase?: string | null;
  programs: object[];
  interop?: object | null;
  remote?: object | null;
  generatedAt?: string;
}): Record<string, unknown>;

export declare function verifyConformanceAttestation(attestation: unknown): {
  ok: boolean;
  errors: string[];
  attestation_digest: string | null;
};
