/** Wave 10 Track S — six carrier control IDs (CSA post–Silent-AI, Jan 2026). */

export const CARRIER_SIX_CONTROL_IDS = [
  'human_kill_switch',
  'hitl_inventory',
  'data_provenance',
  'accountable_executive',
  'deepfake_resistant_auth',
  'stack_enforcement',
] as const;

export type CarrierSixControlId = (typeof CARRIER_SIX_CONTROL_IDS)[number];

export const CARRIER_SIX_CONTROL_LABELS: Record<CarrierSixControlId, string> = {
  human_kill_switch: 'Documented human kill switch',
  hitl_inventory: 'Human-in-the-loop inventory',
  data_provenance: 'Data provenance / classification audit trail',
  accountable_executive: 'Named accountable AI executive attestation',
  deepfake_resistant_auth: 'Out-of-band / HITL authentication on high-risk actions',
  stack_enforcement: 'Enforcement evidence on owned stack (not policy-only)',
};

export default {
  CARRIER_SIX_CONTROL_IDS,
  CARRIER_SIX_CONTROL_LABELS,
};
