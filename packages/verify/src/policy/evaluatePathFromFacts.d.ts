export declare function evaluatePathFromFacts(
  parsed: {
    steps?: { toolName: string; verdict?: string }[];
    readCount?: number;
    stepCount?: number;
    destructiveBurst?: number | null;
    sessionId?: string;
    proposedTool?: string;
  },
  proposedTool: string,
  params?: { maxReadsBeforeDestructive?: number },
): Record<string, unknown>;

export declare function matchKapteinPolicies(
  engineCode: string,
  policyPack: object,
): Array<Record<string, unknown>>;
