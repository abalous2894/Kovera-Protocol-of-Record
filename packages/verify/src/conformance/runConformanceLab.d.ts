export declare function runLocalConformanceInterop(fixturePath?: string): Record<string, unknown>;

export declare function probeDeploymentConformance(
  apiBase: string,
  opts?: { timeoutMs?: number },
): Promise<Record<string, unknown>>;

export declare function runConformanceLab(opts?: {
  apiBase?: string | null;
  fixturePath?: string;
  timeoutMs?: number;
  localOnly?: boolean;
}): Promise<Record<string, unknown>>;
