export declare const CAPABILITY_BUDGET_SCHEMA: 'aevesa.capability-budget/v1';
export declare const CAPABILITY_SINKS: readonly string[];

export declare function initialCapabilityBudget(): Record<string, boolean>;
export declare function intersectCapabilityBudgets(
  a: Record<string, boolean>,
  b: Record<string, boolean>,
): Record<string, boolean>;
export declare function classifyToolCapability(
  toolName: string,
  ctx?: { pathHint?: string | null; args?: Record<string, unknown> | null },
): {
  toolName: string;
  role: string;
  sinks: string[];
  taintClass: string | null;
};
export declare function attenuateBudgetForTaint(
  budget: Record<string, boolean>,
  taintClass: string | null,
): Record<string, boolean>;
export declare function deriveCapabilityBudgetFromSteps(
  steps?: Array<{
    toolName?: string;
    tool_name?: string;
    verdict?: string;
    pathHint?: string | null;
    path_hint?: string | null;
  }>,
): { budget: Record<string, boolean>; taintClass: string | null; tainted: boolean };
export declare function evaluateCapabilityBudget(
  priorSteps: Array<{ toolName?: string; tool_name?: string; verdict?: string; pathHint?: string | null; path_hint?: string | null }>,
  proposedTool: string,
  ctx?: { pathHint?: string | null; args?: Record<string, unknown> | null },
): {
  allow: boolean;
  code: string;
  message: string;
  budget: Record<string, boolean>;
  taintClass: string | null;
  blockedSinks: string[];
  proposedSinks?: string[];
};
export declare function buildCapabilityBudgetCommitment(
  budget: Record<string, boolean>,
  taintClass?: string | null,
): Record<string, unknown>;
export declare function verifyCapabilityBudgetCommitment(block: unknown): { ok: boolean; code: string; [k: string]: unknown };
export declare function verifyBudgetMonotonicityFromPartialSteps(
  partialSteps: Array<{ tool_name?: string; verdict?: string; path_hint?: string | null }>,
): { ok: boolean; code: string; message?: string; [k: string]: unknown };
export declare function verifyMonotonicBudgetAttenuation(
  stepBudgets: Array<{ capability_budget?: { sinks?: Record<string, boolean> } }>,
): { ok: boolean; code: string; message?: string; [k: string]: unknown };
