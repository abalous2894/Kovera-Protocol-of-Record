export declare function detectEvidenceType(input: unknown): {
  kind: string;
  payload?: object;
  entryHash?: string;
  error?: string;
  wrapped?: boolean;
};

export declare function isProofOfActionBundle(obj: unknown): boolean;
export declare function normalizeProofBundleInput(obj: object): object;

export declare const EVIDENCE_KINDS: string[];
