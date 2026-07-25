export const AUTONOMY_TIER_ATTESTATION_SCHEMA = 'aevesa.autonomy-tier-attestation/v1' as const;
export const AUTONOMY_TIER_ATTESTATION_SKU = 'aevesa-autonomy-tier-attestation-v1' as const;
export const EVIDENCE_PORTFOLIO_SCHEMA = 'aevesa.evidence-portfolio/v1' as const;
export const AUTONOMY_TIER_SCHEMA = 'aevesa.autonomy-tier/v1' as const;

/** CSA 4-tier autonomy classification aligned with VERA evidence ladder. */
export const CSA_AUTONOMY_TIERS = [
  { id: 'T0', veraId: 'observer', label: 'Supervised', minScore: 0, maxScore: 39 },
  { id: 'T1', veraId: 'copilot', label: 'Co-Pilot', minScore: 40, maxScore: 64 },
  { id: 'T2', veraId: 'delegated', label: 'Delegated', minScore: 65, maxScore: 84 },
  { id: 'T3', veraId: 'autonomous', label: 'Full Autonomy', minScore: 85, maxScore: 100 },
] as const;

export interface EvidencePortfolioAutonomy {
  schema?: string;
  tierId?: string;
  tierLabel?: string;
  score?: number;
  veraLadder?: string;
}

export interface EvidencePortfolioDocument {
  schema?: string;
  agentId?: string;
  evaluatedAt?: string;
  autonomy?: EvidencePortfolioAutonomy;
  signals?: Record<string, unknown>;
}

export interface AutonomyTierAttestationDocument {
  schema?: string;
  evidence_portfolio?: EvidencePortfolioDocument;
  declared_csa_tier?: string;
  declared_vera_tier_id?: string;
  attested_at?: string;
}

export interface AutonomyTierAttestationVerifyOptions {
  /** When set, declared tier must match this CSA tier id */
  expectedCsaTier?: string;
}

export interface AutonomyTierAttestationVerifyChecks {
  schemaValid: boolean;
  portfolioSchemaValid: boolean;
  autonomySchemaValid: boolean;
  scorePresent: boolean;
  scoreInTierRange: boolean;
  csaTierResolved: boolean;
  veraTierMatchesScore: boolean;
  declaredTierMatchesEvidence: boolean;
  profileComplete: boolean;
}

export interface AutonomyTierAttestationVerifyResult {
  schema: typeof AUTONOMY_TIER_ATTESTATION_SCHEMA;
  sku: typeof AUTONOMY_TIER_ATTESTATION_SKU;
  ok: boolean;
  checks: AutonomyTierAttestationVerifyChecks;
  resolvedCsaTier: (typeof CSA_AUTONOMY_TIERS)[number] | null;
  gtmLine: string;
  note: string | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

export function resolveCsaAutonomyTier(score: number) {
  const s = Math.max(0, Math.min(100, Math.round(Number(score) || 0)));
  return (
    CSA_AUTONOMY_TIERS.find((t) => s >= t.minScore && s <= t.maxScore) || CSA_AUTONOMY_TIERS[0]
  );
}

/**
 * Autonomy tier attestation — binds VERA evidence portfolio score to CSA 4-tier classification.
 */
export function verifyAutonomyTierAttestationBundle(
  input: unknown,
  options: AutonomyTierAttestationVerifyOptions = {},
): AutonomyTierAttestationVerifyResult {
  const doc = asRecord(input) as AutonomyTierAttestationDocument | null;
  const schemaValid = doc?.schema === AUTONOMY_TIER_ATTESTATION_SCHEMA;

  const portfolio = asRecord(doc?.evidence_portfolio) as EvidencePortfolioDocument | null;
  const portfolioSchemaValid = portfolio?.schema === EVIDENCE_PORTFOLIO_SCHEMA;

  const autonomy = asRecord(portfolio?.autonomy) as EvidencePortfolioAutonomy | null;
  const autonomySchemaValid = autonomy?.schema === AUTONOMY_TIER_SCHEMA;

  const score = Number(autonomy?.score);
  const scorePresent = Number.isFinite(score);
  const resolved = scorePresent ? resolveCsaAutonomyTier(score) : null;

  const scoreInTierRange =
    resolved != null && score >= resolved.minScore && score <= resolved.maxScore;

  const veraTierId = String(autonomy?.tierId || '').trim();
  const veraTierMatchesScore = !resolved || veraTierId === '' || veraTierId === resolved.veraId;

  const declaredCsa = String(doc?.declared_csa_tier || '').trim();
  const declaredVera = String(doc?.declared_vera_tier_id || autonomy?.tierId || '').trim();
  const csaTierResolved = Boolean(resolved);

  let declaredTierMatchesEvidence = true;
  if (declaredCsa && resolved) {
    declaredTierMatchesEvidence = declaredCsa === resolved.id;
  } else if (declaredVera && resolved) {
    declaredTierMatchesEvidence = declaredVera === resolved.veraId;
  }
  if (options.expectedCsaTier && resolved) {
    declaredTierMatchesEvidence =
      declaredTierMatchesEvidence && resolved.id === options.expectedCsaTier;
  }

  const profileComplete =
    schemaValid &&
    portfolioSchemaValid &&
    autonomySchemaValid &&
    scorePresent &&
    scoreInTierRange &&
    csaTierResolved &&
    veraTierMatchesScore &&
    declaredTierMatchesEvidence;

  const ok = profileComplete;

  let note: string | null = null;
  if (ok) {
    note = `Autonomy tier attestation verified — ${resolved?.id} (${resolved?.label}) backed by evidence portfolio score ${score}`;
  } else if (!portfolioSchemaValid) {
    note = `Expected evidence portfolio schema ${EVIDENCE_PORTFOLIO_SCHEMA}`;
  } else if (!declaredTierMatchesEvidence) {
    note = 'Declared CSA/VERA tier does not match evidence portfolio score';
  } else if (!veraTierMatchesScore) {
    note = 'VERA tierId does not match composite score band';
  } else {
    note = 'Autonomy tier attestation verification failed';
  }

  return {
    schema: AUTONOMY_TIER_ATTESTATION_SCHEMA,
    sku: AUTONOMY_TIER_ATTESTATION_SKU,
    ok,
    checks: {
      schemaValid,
      portfolioSchemaValid,
      autonomySchemaValid,
      scorePresent,
      scoreInTierRange,
      csaTierResolved,
      veraTierMatchesScore,
      declaredTierMatchesEvidence,
      profileComplete,
    },
    resolvedCsaTier: resolved,
    gtmLine:
      'GRC maps policies. Aevesa proves the agent earned its autonomy tier from receipt history — not calendar time.',
    note,
  };
}
