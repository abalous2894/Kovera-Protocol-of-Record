/** Wave 10 Track U — formal attribution anchor classes (Tamper-Evident ≠ Trustworthy, 2026). */

export const ATTRIBUTION_ANCHOR_IDS = [
  'input_provenance',
  'authenticated_delegation',
  'internal_state_probe',
  'execution_context',
  'human_oversight',
] as const;

export type AttributionAnchorId = (typeof ATTRIBUTION_ANCHOR_IDS)[number];

export const ATTRIBUTION_ANCHOR_LABELS: Record<AttributionAnchorId, string> = {
  input_provenance: 'Exogenous input provenance (ledger anchor + witness path)',
  authenticated_delegation: 'Authenticated delegation chain at intercept',
  internal_state_probe: 'Internal-state probe (memory commitment at material action)',
  execution_context: 'Execution context bind (MCP manifest fingerprint at invoke)',
  human_oversight: 'Human oversight anchor (HITL receipt or release)',
};

export default {
  ATTRIBUTION_ANCHOR_IDS,
  ATTRIBUTION_ANCHOR_LABELS,
};
