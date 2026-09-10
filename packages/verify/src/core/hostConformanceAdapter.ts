import { sha256HexUtf8 } from './sha256.js';
import { stableStringify } from './stableStringify.js';

/** Wave 14 Track E — Agent Hooks / AGT host conformance report normalization (GAP-12). */

export const AGENT_HOOKS_CONFORMANCE_SCHEMA = 'agent.hooks.conformance-report/v1' as const;
export const MICROSOFT_AGT_CONFORMANCE_SCHEMA = 'microsoft.agt.conformance-report/v1' as const;

export const HOST_CONFORMANCE_ADAPTER_IDS = [
  'agent_hooks',
  'microsoft_agt',
  'generic',
] as const;

export type HostConformanceAdapterId = (typeof HOST_CONFORMANCE_ADAPTER_IDS)[number];

export interface HostConformanceScenarioResult {
  scenario_id: string;
  result: 'pass' | 'fail' | 'skip';
}

export interface HostConformanceReportEnvelope {
  host_adapter_id: HostConformanceAdapterId;
  report_id: string;
  evaluated_at: string;
  host_version_digest: string;
  scenario_count: number;
  scenarios_passed: number;
  scenarios_failed: number;
  enforcement_profile_digest: string;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function digestString(value: string): string {
  return sha256HexUtf8(
    stableStringify({
      schema: 'aevesa.host-string-digest/v1',
      value: String(value || '').trim(),
    }),
  );
}

function summarizeScenarios(raw: unknown): HostConformanceScenarioResult[] {
  const scenarios = Array.isArray(raw) ? raw : [];
  return scenarios
    .map((item) => {
      const row = asRecord(item);
      if (!row) return null;
      const scenario_id = String(row.scenario_id || row.id || row.name || '').trim();
      if (!scenario_id) return null;
      const resultRaw = String(row.result || row.status || row.outcome || 'pass').toLowerCase();
      const result =
        resultRaw === 'fail' || resultRaw === 'failed' || resultRaw === 'error'
          ? 'fail'
          : resultRaw === 'skip' || resultRaw === 'skipped'
            ? 'skip'
            : 'pass';
      return { scenario_id, result };
    })
    .filter(Boolean) as HostConformanceScenarioResult[];
}

export function canonicalizeHostConformanceReportEnvelope(
  envelope: HostConformanceReportEnvelope,
): Record<string, unknown> {
  return {
    host_adapter_id: envelope.host_adapter_id,
    report_id: String(envelope.report_id || '').trim(),
    evaluated_at: String(envelope.evaluated_at || '').trim(),
    host_version_digest: String(envelope.host_version_digest || '').trim().toLowerCase(),
    scenario_count: Number(envelope.scenario_count) || 0,
    scenarios_passed: Number(envelope.scenarios_passed) || 0,
    scenarios_failed: Number(envelope.scenarios_failed) || 0,
    enforcement_profile_digest: String(envelope.enforcement_profile_digest || '')
      .trim()
      .toLowerCase(),
  };
}

export function buildHostConformanceReportDigest(
  envelope: HostConformanceReportEnvelope,
): string {
  return sha256HexUtf8(
    stableStringify({
      schema: 'aevesa.host-conformance-report-envelope/v1',
      ...canonicalizeHostConformanceReportEnvelope(envelope),
    }),
  );
}

export function normalizeAgentHooksConformanceReport(rawInput: unknown): HostConformanceReportEnvelope {
  const raw = asRecord(rawInput);
  if (!raw) throw new Error('Agent Hooks conformance report must be an object');

  const scenarios = summarizeScenarios(raw.scenarios);
  const scenarios_passed = scenarios.filter((s) => s.result === 'pass').length;
  const scenarios_failed = scenarios.filter((s) => s.result === 'fail').length;
  const scenario_count = scenarios.length || Number(raw.scenario_count) || 0;

  const hostVersion = String(raw.host_version || raw.hooks_version || raw.runtime_version || '1.0.0');

  const envelope: HostConformanceReportEnvelope = {
    host_adapter_id: 'agent_hooks',
    report_id: String(raw.report_id || raw.conformance_report_id || '').trim(),
    evaluated_at: String(raw.evaluated_at || raw.generated_at || '').trim(),
    host_version_digest: digestString(hostVersion),
    scenario_count,
    scenarios_passed,
    scenarios_failed,
    enforcement_profile_digest:
      typeof raw.enforcement_profile_digest === 'string'
        ? raw.enforcement_profile_digest
        : digestString(String(raw.enforcement_profile_ref || raw.profile_id || 'agent-hooks/default')),
  };

  if (!envelope.report_id || !envelope.evaluated_at) {
    throw new Error('Agent Hooks conformance report missing report_id or evaluated_at');
  }

  return envelope;
}

export function normalizeMicrosoftAgtConformanceReport(rawInput: unknown): HostConformanceReportEnvelope {
  const raw = asRecord(rawInput);
  if (!raw) throw new Error('Microsoft AGT conformance report must be an object');

  const scenarios = summarizeScenarios(raw.scenarios ?? raw.conformance_scenarios);
  const scenarios_passed = scenarios.filter((s) => s.result === 'pass').length;
  const scenarios_failed = scenarios.filter((s) => s.result === 'fail').length;

  const envelope: HostConformanceReportEnvelope = {
    host_adapter_id: 'microsoft_agt',
    report_id: String(raw.report_id || raw.agt_report_id || '').trim(),
    evaluated_at: String(raw.evaluated_at || raw.report_generated_at || '').trim(),
    host_version_digest: digestString(String(raw.agt_version || raw.host_version || 'agt-2026')),
    scenario_count: scenarios.length || Number(raw.scenario_count) || 0,
    scenarios_passed,
    scenarios_failed,
    enforcement_profile_digest:
      typeof raw.enforcement_profile_digest === 'string'
        ? raw.enforcement_profile_digest
        : digestString(String(raw.enforcement_profile || 'microsoft.agt/default')),
  };

  if (!envelope.report_id || !envelope.evaluated_at) {
    throw new Error('Microsoft AGT conformance report missing report_id or evaluated_at');
  }

  return envelope;
}

export function coerceHostConformanceReport(
  rawInput: unknown,
  adapterHint?: string | null,
): HostConformanceReportEnvelope {
  const raw = asRecord(rawInput);
  const schema = String(raw?.schema || adapterHint || '').trim().toLowerCase();

  if (schema.includes('microsoft.agt') || adapterHint === 'microsoft_agt') {
    return normalizeMicrosoftAgtConformanceReport(rawInput);
  }
  if (raw?.host_adapter_id === 'microsoft_agt') {
    return normalizeMicrosoftAgtConformanceReport(rawInput);
  }
  return normalizeAgentHooksConformanceReport(rawInput);
}

export default {
  AGENT_HOOKS_CONFORMANCE_SCHEMA,
  MICROSOFT_AGT_CONFORMANCE_SCHEMA,
  HOST_CONFORMANCE_ADAPTER_IDS,
  buildHostConformanceReportDigest,
  canonicalizeHostConformanceReportEnvelope,
  normalizeAgentHooksConformanceReport,
  normalizeMicrosoftAgtConformanceReport,
  coerceHostConformanceReport,
};
