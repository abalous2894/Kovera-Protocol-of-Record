export const INTENT_ALIGNMENT_LEVEL: {
  readonly ALIGNED: 'ALIGNED';
  readonly ELEVATED: 'ELEVATED';
  readonly CRITICAL: 'CRITICAL';
};

export const MAX_INTENT_ALIGNMENT_SIGNALS: 16;

export interface IntentAlignmentOutput {
  score: number;
  level: 'ALIGNED' | 'ELEVATED' | 'CRITICAL';
  signals: string[];
}

export function normalizeStructuralPayload(raw: unknown): {
  tool: string;
  path: string;
  host: string;
  method: string;
  amount: number;
  scopes: string[];
};

export function intentAlignmentLevelFromScore(score: number): 'ALIGNED' | 'ELEVATED' | 'CRITICAL';

export function evaluateIntentAlignment(
  intentContext: unknown,
  normalizedPayload: unknown,
): IntentAlignmentOutput;

export function canonicalizeIntentAlignmentForDigest(alignment: unknown): {
  level: 'ALIGNED' | 'ELEVATED' | 'CRITICAL';
  score: number;
  signals: string[];
};
