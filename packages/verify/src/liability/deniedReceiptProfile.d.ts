export declare const RECEIPT_PROFILE_DENIED: 'DENIED';
export declare const RECEIPT_PROFILE_PERMITTED: 'PERMITTED';
export declare const SCITT_REFUSAL_PROFILE: 'SCITT-refusal-event-draft-01';

export declare function isDeniedReceiptProfile(receipt: unknown): boolean;

export declare function validateDeniedReceiptProfile(receipt: unknown): {
  ok: boolean;
  code: string;
  skipped?: boolean;
  errors?: string[];
};

export declare function validateScittRefusalAlignment(receipt: unknown): {
  ok: boolean;
  code: string;
  skipped?: boolean;
  errors?: string[];
};

export declare function buildDeniedReceiptProofSteps(receipt: unknown): Array<{
  key: string;
  label: string;
  ok: boolean;
  detail: string | null;
}>;
