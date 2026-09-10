import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';

/** Wave 13 Track D — adversarial test evidence custody pack (underwriter-facing). */

export const ADVERSARIAL_TEST_EVIDENCE_PACK_SCHEMA =
  'aevesa.adversarial-test-evidence-pack/v1' as const;

export const DEFAULT_ADVERSARIAL_CADENCE_DAYS = 90;

export type MethodologyRef = 'owasp-llm-top10' | 'mitre-atlas' | 'aiuc1-b005' | 'custom';
export type RemediationStatus = 'remediated' | 'accepted_risk' | 'open';
export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low';
export type TestingReadiness = 'underwriting_ready' | 'partial' | 'unverified';

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface TestCampaignInput {
  campaign_id: string;
  vendor_id_digest: string;
  executed_at: string;
  methodology_ref: MethodologyRef;
  finding_count: number;
  severity_counts: SeverityCounts;
}

export interface RemediationLinkInput {
  finding_digest: string;
  severity: FindingSeverity;
  remediation_receipt_digest: string | null;
  remediated_at: string | null;
  status: RemediationStatus;
}

export interface CadenceInput {
  previous_campaign_executed_at: string | null;
  previous_campaign_digest: string | null;
  cadence_days_target?: number;
}

export interface UnderwritingAssertionsInput {
  third_party_verifiable: boolean;
}

export interface CampaignSessionBinding {
  campaign_id: string;
  findings_manifest_digest: string;
  campaign_digest: string;
  normalization_bound: boolean;
}

export interface AdversarialTestEvidencePackInput {
  organization_id: string;
  generated_at?: string;
  test_campaign: TestCampaignInput;
  remediation_links: RemediationLinkInput[];
  cadence: CadenceInput;
  underwriting_assertions: UnderwritingAssertionsInput;
  campaign_session_binding: CampaignSessionBinding;
  disclaimer?: string;
}



export function computeDaysSincePrevious(
  previousExecutedAt: string | null | undefined,
  currentExecutedAt: string,
): number | null {
  if (!previousExecutedAt?.trim() || !currentExecutedAt?.trim()) return null;
  const prev = Date.parse(previousExecutedAt);
  const current = Date.parse(currentExecutedAt);
  if (!Number.isFinite(prev) || !Number.isFinite(current)) return null;
  const diffMs = current - prev;
  if (diffMs < 0) return null;
  return Math.floor(diffMs / (24 * 60 * 60 * 1000));
}

export function buildFindingsManifestDigest(links: RemediationLinkInput[]): string {
  const digests = [...links]
    .map((l) => String(l.finding_digest || '').trim().toLowerCase())
    .filter(Boolean)
    .sort();
  return sha256HexUtf8(
    stableStringify({
      schema: 'aevesa.adversarial-findings-manifest/v1',
      finding_digests: digests,
    }),
  );
}

export function buildTestCampaignDigest(campaign: TestCampaignInput): string {
  return sha256HexUtf8(
    stableStringify({
      schema: 'aevesa.adversarial-test-campaign/v1',
      campaign_id: String(campaign.campaign_id || '').trim(),
      vendor_id_digest: String(campaign.vendor_id_digest || '').trim().toLowerCase(),
      executed_at: String(campaign.executed_at || '').trim(),
      methodology_ref: campaign.methodology_ref,
      finding_count: Number(campaign.finding_count) || 0,
      severity_counts: {
        critical: Number(campaign.severity_counts?.critical) || 0,
        high: Number(campaign.severity_counts?.high) || 0,
        medium: Number(campaign.severity_counts?.medium) || 0,
        low: Number(campaign.severity_counts?.low) || 0,
      },
    }),
  );
}

export function evaluateSeverityCounts(links: RemediationLinkInput[]): SeverityCounts {
  const counts: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const link of links) {
    const sev = link.severity;
    if (sev === 'critical') counts.critical += 1;
    else if (sev === 'high') counts.high += 1;
    else if (sev === 'medium') counts.medium += 1;
    else if (sev === 'low') counts.low += 1;
  }
  return counts;
}

export function evaluateRemediationsLinked(links: RemediationLinkInput[]): boolean {
  return !links.some(
    (l) =>
      (l.severity === 'critical' || l.severity === 'high') && l.status === 'open',
  );
}

export function deriveTestingReadiness(
  testsBound: boolean,
  remediationsLinked: boolean,
  cadenceMet: boolean,
  thirdPartyVerifiable: boolean,
): TestingReadiness {
  if (testsBound && remediationsLinked && cadenceMet && thirdPartyVerifiable) {
    return 'underwriting_ready';
  }
  if (testsBound && (remediationsLinked || cadenceMet)) return 'partial';
  return 'unverified';
}

export function buildUnderwritingAssertionsBlock(
  input: UnderwritingAssertionsInput,
  links: RemediationLinkInput[],
  campaign: TestCampaignInput,
  findingsManifestDigest: string,
  campaignDigest: string,
  cadenceMet: boolean,
) {
  const tests_bound =
    findingsManifestDigest === buildFindingsManifestDigest(links) &&
    campaignDigest === buildTestCampaignDigest(campaign) &&
    Number(campaign.finding_count) === links.length;

  const remediations_linked = evaluateRemediationsLinked(links);
  const testing_readiness = deriveTestingReadiness(
    tests_bound,
    remediations_linked,
    cadenceMet,
    input.third_party_verifiable === true,
  );

  return {
    tests_bound,
    remediations_linked,
    cadence_met: cadenceMet,
    third_party_verifiable: input.third_party_verifiable === true,
    testing_readiness,
    open_critical_high_count: links.filter(
      (l) =>
        (l.severity === 'critical' || l.severity === 'high') && l.status === 'open',
    ).length,
  };
}

export function buildAdversarialTestEvidencePackPreimage(
  input: Omit<AdversarialTestEvidencePackInput, 'disclaimer'> & {
    generated_at: string;
    test_campaign: TestCampaignInput & { findings_manifest_digest: string; campaign_digest: string };
    underwriting_assertions: ReturnType<typeof buildUnderwritingAssertionsBlock>;
    cadence: CadenceInput & {
      days_since_previous: number | null;
      cadence_days_target: number;
    };
  },
): Record<string, unknown> {
  const links = [...input.remediation_links]
    .map((l) => ({
      finding_digest: String(l.finding_digest || '').trim().toLowerCase(),
      severity: l.severity,
      remediation_receipt_digest: l.remediation_receipt_digest
        ? String(l.remediation_receipt_digest).trim().toLowerCase()
        : null,
      remediated_at: l.remediated_at ? String(l.remediated_at).trim() : null,
      status: l.status,
    }))
    .sort((a, b) => a.finding_digest.localeCompare(b.finding_digest));

  const binding = input.campaign_session_binding;

  return {
    schema: ADVERSARIAL_TEST_EVIDENCE_PACK_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    generated_at: input.generated_at,
    test_campaign: {
      campaign_id: String(input.test_campaign.campaign_id || '').trim(),
      vendor_id_digest: String(input.test_campaign.vendor_id_digest || '').trim().toLowerCase(),
      executed_at: String(input.test_campaign.executed_at || '').trim(),
      methodology_ref: input.test_campaign.methodology_ref,
      findings_manifest_digest: String(input.test_campaign.findings_manifest_digest || '')
        .trim()
        .toLowerCase(),
      finding_count: Number(input.test_campaign.finding_count) || 0,
      severity_counts: {
        critical: Number(input.test_campaign.severity_counts?.critical) || 0,
        high: Number(input.test_campaign.severity_counts?.high) || 0,
        medium: Number(input.test_campaign.severity_counts?.medium) || 0,
        low: Number(input.test_campaign.severity_counts?.low) || 0,
      },
      campaign_digest: String(input.test_campaign.campaign_digest || '').trim().toLowerCase(),
    },
    remediation_links: links,
    cadence: {
      previous_campaign_digest: input.cadence.previous_campaign_digest
        ? String(input.cadence.previous_campaign_digest).trim().toLowerCase()
        : null,
      days_since_previous: input.cadence.days_since_previous,
      cadence_days_target: Number(input.cadence.cadence_days_target) || DEFAULT_ADVERSARIAL_CADENCE_DAYS,
    },
    underwriting_assertions: input.underwriting_assertions,
    campaign_session_binding: {
      campaign_id: String(binding.campaign_id || '').trim(),
      findings_manifest_digest: String(binding.findings_manifest_digest || '')
        .trim()
        .toLowerCase(),
      campaign_digest: String(binding.campaign_digest || '').trim().toLowerCase(),
      normalization_bound: binding.normalization_bound === true,
    },
  };
}

export interface AdversarialTestEvidencePackDocument {
  schema: typeof ADVERSARIAL_TEST_EVIDENCE_PACK_SCHEMA;
  organization_id: string;
  generated_at: string;
  test_campaign: TestCampaignInput & {
    findings_manifest_digest: string;
    campaign_digest: string;
  };
  remediation_links: RemediationLinkInput[];
  cadence: CadenceInput & {
    days_since_previous: number | null;
    cadence_days_target: number;
  };
  underwriting_assertions: ReturnType<typeof buildUnderwritingAssertionsBlock>;
  campaign_session_binding: CampaignSessionBinding;
  disclaimer: string;
  pack_digest: string;
}

export function buildAdversarialTestEvidencePackDocument(
  input: AdversarialTestEvidencePackInput,
): AdversarialTestEvidencePackDocument {
  const generated_at = input.generated_at || new Date().toISOString();
  const findings_manifest_digest = buildFindingsManifestDigest(input.remediation_links);
  const campaign_digest = buildTestCampaignDigest(input.test_campaign);
  const cadence_days_target =
    input.cadence.cadence_days_target ?? DEFAULT_ADVERSARIAL_CADENCE_DAYS;
  const days_since_previous = computeDaysSincePrevious(
    input.cadence.previous_campaign_executed_at,
    input.test_campaign.executed_at,
  );
  const cadence_met =
    days_since_previous != null && days_since_previous <= cadence_days_target;

  const severity_counts = evaluateSeverityCounts(input.remediation_links);
  const test_campaign = {
    ...input.test_campaign,
    finding_count: input.remediation_links.length,
    severity_counts,
    findings_manifest_digest,
    campaign_digest,
  };

  const underwriting_assertions = buildUnderwritingAssertionsBlock(
    input.underwriting_assertions,
    input.remediation_links,
    test_campaign,
    findings_manifest_digest,
    campaign_digest,
    cadence_met,
  );

  const preimage = buildAdversarialTestEvidencePackPreimage({
    ...input,
    generated_at,
    test_campaign,
    underwriting_assertions,
    cadence: {
      ...input.cadence,
      days_since_previous,
      cadence_days_target,
    },
  });

  const pack_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...(preimage as Omit<AdversarialTestEvidencePackDocument, 'pack_digest' | 'disclaimer'>),
    pack_digest,
    disclaimer:
      input.disclaimer ??
      'Adversarial test evidence custody — not red-team services, underwriting, or legal advice.',
  };
}

export default {
  ADVERSARIAL_TEST_EVIDENCE_PACK_SCHEMA,
  DEFAULT_ADVERSARIAL_CADENCE_DAYS,
  buildAdversarialTestEvidencePackDocument,
  buildFindingsManifestDigest,
  buildTestCampaignDigest,
  evaluateRemediationsLinked,
  deriveTestingReadiness,
};
