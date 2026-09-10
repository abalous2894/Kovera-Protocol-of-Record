export const TRANSPARENCY_LOG_MONITOR_STATUS_SCHEMA: string;
export const TRANSPARENCY_LOG_MONITOR_SKU: string;

export function verifyTransparencyLogMonitorStatus(
  snapshot: unknown,
  options?: { entryDigests?: string[] },
): {
  schema: string;
  sku: string;
  ok: boolean;
  checks: Record<string, boolean>;
  gtmLine: string;
  note: string | null;
};
