import { sha256HexUtf8 } from '../core/sha256.js';
import { ADVERSARIAL_TEST_EVIDENCE_PACK_SCHEMA, buildAdversarialTestEvidencePackPreimage, buildFindingsManifestDigest, buildTestCampaignDigest, DEFAULT_ADVERSARIAL_CADENCE_DAYS, evaluateRemediationsLinked, evaluateSeverityCounts, type TestingReadiness } from '../core/adversarialTestEvidencePack.js';
import { stableStringify } from '../core/stableStringify.js';

export const ADVERSARIAL_TEST_EVIDENCE_PACK_SKU =
  'aevesa-adversarial-test-evidence-pack-v1' as const;

const HEX64 = /^[a-f0-9]{64}$/;
const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|ssn|phone|address|pan|cvv)$/i;
const METHODOLOGIES = new Set(['owasp-llm-top10', 'mitre-atlas', 'aiuc1-b005', 'custom']);

export interface AdversarialTestEvidencePackVerifyResult {
  schema: typeof ADVERSARIAL_TEST_EVIDENCE_PACK_SCHEMA;
  sku: typeof ADVERSARIAL_TEST_EVIDENCE_PACK_SKU;
  ok: boolean;
  checks: Record<string, boolean>;
  testing_readiness: TestingReadiness | null;
  gtmLine: string;
  note: string | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function hasForbiddenKeys(value: unknown, depth = 0): boolean {
  if (depth > 8 || value == null) return false;
  if (Array.isArray(value)) return value.some((v) => hasForbiddenKeys(v, depth + 1));
  if (typeof value !== 'object') return false;
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (FORBIDDEN_KEYS.test(key)) return true;
    if (hasForbiddenKeys(child, depth + 1)) return true;
  }
  return false;
}

export function verifyAdversarialTestEvidencePack(
  docInput: unknown,
): AdversarialTestEvidencePackVerifyResult {
  const doc = asRecord(docInput);
  const schemaValid = doc?.schema === ADVERSARIAL_TEST_EVIDENCE_PACK_SCHEMA;
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;

  const campaign = asRecord(doc?.test_campaign) || {};
  const campaignIdPresent = String(campaign.campaign_id || '').trim().length > 0;
  const methodologyValid = METHODOLOGIES.has(String(campaign.methodology_ref || ''));

  const links = Array.isArray(doc?.remediation_links) ? doc.remediation_links : [];
  const linksPresent = links.length >= 1;
  const linkDigestsValid =
    links.length === 0 ||
    links.every((l) => HEX64.test(String(l?.finding_digest || '').toLowerCase()));

  const findingsManifestDigest = buildFindingsManifestDigest(
    links.map((l) => ({
      finding_digest: String(l?.finding_digest || ''),
      severity: String(l?.severity || 'low') as 'low',
      remediation_receipt_digest: l?.remediation_receipt_digest
        ? String(l.remediation_receipt_digest)
        : null,
      remediated_at: l?.remediated_at ? String(l.remediated_at) : null,
      status: String(l?.status || 'open') as 'open',
    })),
  );

  const campaignForDigest = {
    campaign_id: String(campaign.campaign_id || ''),
    vendor_id_digest: String(campaign.vendor_id_digest || ''),
    executed_at: String(campaign.executed_at || ''),
    methodology_ref: String(campaign.methodology_ref || 'custom') as 'custom',
    finding_count: Number(campaign.finding_count) || links.length,
    severity_counts: {
      critical: Number(asRecord(campaign.severity_counts)?.critical) || 0,
      high: Number(asRecord(campaign.severity_counts)?.high) || 0,
      medium: Number(asRecord(campaign.severity_counts)?.medium) || 0,
      low: Number(asRecord(campaign.severity_counts)?.low) || 0,
    },
  };

  const expectedCampaignDigest = buildTestCampaignDigest(campaignForDigest);
  const campaignDigestMatches =
    HEX64.test(String(campaign.campaign_digest || '').toLowerCase()) &&
    String(campaign.campaign_digest || '').toLowerCase() === expectedCampaignDigest;

  const manifestDigestMatches =
    HEX64.test(String(campaign.findings_manifest_digest || '').toLowerCase()) &&
    String(campaign.findings_manifest_digest || '').toLowerCase() === findingsManifestDigest;

  const findingCountMatches = Number(campaign.finding_count) === links.length;

  const computedSeverity = evaluateSeverityCounts(
    links.map((l) => ({
      finding_digest: String(l?.finding_digest || ''),
      severity: String(l?.severity || 'low') as 'low',
      remediation_receipt_digest: null,
      remediated_at: null,
      status: String(l?.status || 'open') as 'open',
    })),
  );
  const severityCountsMatch =
    Number(asRecord(campaign.severity_counts)?.critical) === computedSeverity.critical &&
    Number(asRecord(campaign.severity_counts)?.high) === computedSeverity.high &&
    Number(asRecord(campaign.severity_counts)?.medium) === computedSeverity.medium &&
    Number(asRecord(campaign.severity_counts)?.low) === computedSeverity.low;

  const remediationsLinked = evaluateRemediationsLinked(
    links.map((l) => ({
      finding_digest: String(l?.finding_digest || ''),
      severity: String(l?.severity || 'low') as 'low',
      remediation_receipt_digest: l?.remediation_receipt_digest
        ? String(l.remediation_receipt_digest)
        : null,
      remediated_at: l?.remediated_at ? String(l.remediated_at) : null,
      status: String(l?.status || 'open') as 'open',
    })),
  );

  const cadence = asRecord(doc?.cadence) || {};
  const cadenceTarget = Number(cadence.cadence_days_target) || DEFAULT_ADVERSARIAL_CADENCE_DAYS;
  const daysSincePrevious = Number(cadence.days_since_previous);
  const cadenceMet =
    Number.isFinite(daysSincePrevious) && daysSincePrevious <= cadenceTarget;

  const binding = asRecord(doc?.campaign_session_binding) || {};
  const normalizationBound = binding.normalization_bound === true;
  const bindingDigestsValid =
    HEX64.test(String(binding.findings_manifest_digest || '').toLowerCase()) &&
    HEX64.test(String(binding.campaign_digest || '').toLowerCase());

  const bindingMatchesCampaign =
    String(binding.campaign_id || '') === String(campaign.campaign_id || '') &&
    String(binding.findings_manifest_digest || '').toLowerCase() === findingsManifestDigest &&
    String(binding.campaign_digest || '').toLowerCase() === expectedCampaignDigest;

  const testsBound =
    manifestDigestMatches &&
    campaignDigestMatches &&
    findingCountMatches &&
    bindingMatchesCampaign;

  const assertions = asRecord(doc?.underwriting_assertions) || {};
  const derivedReadiness = String(assertions.testing_readiness || '') as TestingReadiness;

  let underwritingAssertionsConsistent =
    assertions.third_party_verifiable === true && campaignIdPresent;

  if (derivedReadiness === 'underwriting_ready') {
    underwritingAssertionsConsistent =
      underwritingAssertionsConsistent &&
      assertions.tests_bound === true &&
      assertions.remediations_linked === true &&
      assertions.cadence_met === true &&
      testsBound &&
      remediationsLinked &&
      cadenceMet &&
      normalizationBound;
  } else if (derivedReadiness === 'partial') {
    underwritingAssertionsConsistent =
      underwritingAssertionsConsistent &&
      testsBound &&
      bindingMatchesCampaign;
  } else if (derivedReadiness === 'unverified') {
    underwritingAssertionsConsistent =
      underwritingAssertionsConsistent &&
      (!remediationsLinked || !cadenceMet || assertions.remediations_linked === false);
  }

  const readinessConsistent = assertions.testing_readiness === derivedReadiness;

  let packDigestMatches = false;
  if (schemaValid && doc && bindingDigestsValid && bindingMatchesCampaign && linksPresent) {
    const preimage = buildAdversarialTestEvidencePackPreimage({
      organization_id: String(doc.organization_id),
      generated_at: String(doc.generated_at || ''),
      test_campaign: {
        ...campaignForDigest,
        findings_manifest_digest: findingsManifestDigest,
        campaign_digest: expectedCampaignDigest,
      },
      remediation_links: links.map((l) => ({
        finding_digest: String(l?.finding_digest || ''),
        severity: String(l?.severity || 'low') as 'low',
        remediation_receipt_digest: l?.remediation_receipt_digest
          ? String(l.remediation_receipt_digest)
          : null,
        remediated_at: l?.remediated_at ? String(l.remediated_at) : null,
        status: String(l?.status || 'open') as 'open',
      })),
      cadence: {
        previous_campaign_executed_at: null,
        previous_campaign_digest: cadence.previous_campaign_digest
          ? String(cadence.previous_campaign_digest)
          : null,
        days_since_previous: Number.isFinite(daysSincePrevious) ? daysSincePrevious : null,
        cadence_days_target: cadenceTarget,
      },
      underwriting_assertions: {
        tests_bound: assertions.tests_bound === true,
        remediations_linked: assertions.remediations_linked === true,
        cadence_met: assertions.cadence_met === true,
        third_party_verifiable: assertions.third_party_verifiable === true,
        testing_readiness: derivedReadiness,
        open_critical_high_count: Number(assertions.open_critical_high_count) || 0,
      },
      campaign_session_binding: {
        campaign_id: String(binding.campaign_id || ''),
        findings_manifest_digest: String(binding.findings_manifest_digest || ''),
        campaign_digest: String(binding.campaign_digest || ''),
        normalization_bound: normalizationBound,
      },
    });
    const expected = sha256HexUtf8(stableStringify(preimage));
    packDigestMatches = String(doc.pack_digest || '').toLowerCase() === expected;
  }

  const hashOnlySurface = !hasForbiddenKeys(doc);

  const profileComplete =
    schemaValid &&
    organizationIdPresent &&
    campaignIdPresent &&
    methodologyValid &&
    linksPresent &&
    linkDigestsValid &&
    testsBound &&
    severityCountsMatch &&
    remediationsLinked === (assertions.remediations_linked === true) &&
    cadenceMet === (assertions.cadence_met === true) &&
    bindingMatchesCampaign &&
    bindingDigestsValid &&
    underwritingAssertionsConsistent &&
    packDigestMatches &&
    hashOnlySurface &&
    readinessConsistent &&
    derivedReadiness === 'underwriting_ready';

  let note: string | null = null;
  if (!schemaValid) note = `schema must be ${ADVERSARIAL_TEST_EVIDENCE_PACK_SCHEMA}`;
  else if (!remediationsLinked) note = 'open critical/high finding — remediations_linked must be false';
  else if (!testsBound) note = 'test campaign or findings manifest digest mismatch';
  else if (!cadenceMet) note = `cadence exceeds ${cadenceTarget}-day target`;
  else if (!packDigestMatches) note = 'pack_digest does not match canonical preimage';
  else if (!underwritingAssertionsConsistent) note = 'underwriting_assertions inconsistent with campaign or links';

  return {
    schema: ADVERSARIAL_TEST_EVIDENCE_PACK_SCHEMA,
    sku: ADVERSARIAL_TEST_EVIDENCE_PACK_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      organizationIdPresent,
      campaignIdPresent,
      methodologyValid,
      linksPresent,
      linkDigestsValid,
      manifestDigestMatches,
      campaignDigestMatches,
      findingCountMatches,
      severityCountsMatch,
      testsBound,
      remediationsLinked,
      cadenceMet,
      bindingMatchesCampaign,
      bindingDigestsValid,
      underwritingAssertionsConsistent,
      packDigestMatches,
      hashOnlySurface,
      readinessConsistent,
      profileComplete,
    },
    testing_readiness: derivedReadiness || null,
    gtmLine:
      "Underwriters don't price controls lists — they price test evidence. Aevesa binds your red-team results to remediation receipts, offline.",
    note,
  };
}

export default { verifyAdversarialTestEvidencePack, ADVERSARIAL_TEST_EVIDENCE_PACK_SKU };
