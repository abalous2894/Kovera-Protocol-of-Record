export declare function parseDatalogFacts(facts: string[]): {
  ok: boolean;
  errors: string[];
  parsed: {
    sessionId: string;
    steps: { toolName: string; verdict: string }[];
    readCount: number;
    stepCount: number;
    proposedTool: string;
    destructiveBurst: number | null;
  } | null;
};
