import {
  QUARTERLY_REVIEW_EXPORT_SCHEMA,
  QUARTERLY_REVIEW_EXPORT_SKU,
} from '../core/quarterlyReviewExport.js';
import { verifyConformityClosureBundle } from './conformityClosureVerify.js';

export { QUARTERLY_REVIEW_EXPORT_SKU };

export interface QuarterlyReviewExportDocument {
  schema?: string;
  organization_id?: string;
  quarter?: string;
  lookback_days?: number;
  generated_at?: string;
  posture?: {
    summary?: {
      aggregateGapScore?: number;
      aggregateGapScoreAfterClosures?: number;
      obligationsClosedInLookback?: number;
    };
    obligations?: unknown[];
  };
  closures?: Array<{ conformity_closure?: unknown }>;
  open_incidents?: Array<{
    id?: string;
    status?: string;
    anchorEntryHash?: string;
    title?: string;
  }>;
}

export interface QuarterlyReviewExportVerifyChecks {
  schemaValid: boolean;
  organizationIdPresent: boolean;
  quarterPresent: boolean;
  lookbackDaysValid: boolean;
  postureSummaryPresent: boolean;
  closuresPresent: boolean;
  closuresVerify: boolean;
  openIncidentsPresent: boolean;
  profileComplete: boolean;
}

export interface QuarterlyReviewExportVerifyResult {
  schema: typeof QUARTERLY_REVIEW_EXPORT_SCHEMA;
  sku: typeof QUARTERLY_REVIEW_EXPORT_SKU;
  ok: boolean;
  checks: QuarterlyReviewExportVerifyChecks;
  closureCount: number;
  openIncidentCount: number;
  gtmLine: string;
  note: string | null;
}

const QUARTER_RE = /^\d{4}-Q[1-4]$/;

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

/**
 * Verify quarterly review export stub — posture + closures + open incidents composite.
 */
export function verifyQuarterlyReviewExport(
  input: unknown,
): QuarterlyReviewExportVerifyResult {
  const doc = asRecord(input) as QuarterlyReviewExportDocument | null;
  const schemaValid = doc?.schema === QUARTERLY_REVIEW_EXPORT_SCHEMA;
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;
  const quarter = String(doc?.quarter || '').trim();
  const quarterPresent = QUARTER_RE.test(quarter);
  const lookback_days = Number(doc?.lookback_days);
  const lookbackDaysValid = Number.isFinite(lookback_days) && lookback_days >= 7 && lookback_days <= 365;

  const summary = asRecord(doc?.posture?.summary);
  const postureSummaryPresent =
    summary != null &&
    Number.isFinite(Number(summary.aggregateGapScore)) &&
    Number.isFinite(Number(summary.aggregateGapScoreAfterClosures));

  const closures = Array.isArray(doc?.closures) ? doc.closures : [];
  const closuresPresent = closures.length > 0;
  const closuresVerify =
    closuresPresent &&
    closures.every((row) => {
      const closure = asRecord(row)?.conformity_closure ?? row;
      return verifyConformityClosureBundle(closure).ok === true;
    });

  const openIncidents = Array.isArray(doc?.open_incidents) ? doc.open_incidents : [];
  const openIncidentsPresent = openIncidents.length >= 0;
  const openIncidentCount = openIncidents.filter((i) => String(i?.status || '') === 'open').length;

  const checks: QuarterlyReviewExportVerifyChecks = {
    schemaValid,
    organizationIdPresent,
    quarterPresent,
    lookbackDaysValid,
    postureSummaryPresent,
    closuresPresent,
    closuresVerify,
    openIncidentsPresent,
    profileComplete:
      schemaValid &&
      organizationIdPresent &&
      quarterPresent &&
      lookbackDaysValid &&
      postureSummaryPresent &&
      closuresPresent &&
      closuresVerify &&
      openIncidentsPresent,
  };

  const ok = checks.profileComplete;
  let note: string | null = null;
  if (!schemaValid) note = 'schema must be aevesa.quarterly-review-export/v1';
  else if (!closuresVerify) note = 'one or more nested conformity_closure bundles failed verify';
  else if (!postureSummaryPresent) note = 'posture.summary aggregate gap fields required';

  return {
    schema: QUARTERLY_REVIEW_EXPORT_SCHEMA,
    sku: QUARTERLY_REVIEW_EXPORT_SKU,
    ok,
    checks,
    closureCount: closures.length,
    openIncidentCount,
    gtmLine:
      'Quarterly EU AI Act review — posture snapshot, closed obligations, and open incident trail in one export.',
    note,
  };
}
