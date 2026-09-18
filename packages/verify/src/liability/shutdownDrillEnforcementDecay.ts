import {
  CHAIN_ENFORCEMENT_ROLLUP_SCHEMA,
  type ChainEnforcementRollupResult,
} from './chainEnforcementRollup.js';

export const SHUTDOWN_DRILL_ENFORCEMENT_DECAY_SCHEMA =
  'aevesa.shutdown-drill-enforcement-decay/v1' as const;

export const POST_KILL_SWITCH_EFFECTIVE_MODES = ['blocked'] as const;
export type PostKillSwitchEffectiveMode = (typeof POST_KILL_SWITCH_EFFECTIVE_MODES)[number];

export interface ShutdownDrillEnforcementDecay {
  schema: typeof SHUTDOWN_DRILL_ENFORCEMENT_DECAY_SCHEMA;
  session_id: string | null;
  pre_drill_chain_enforcement_mode: string;
  pre_drill_weakest_link_index: number | null;
  post_kill_switch_effective_mode: PostKillSwitchEffectiveMode;
  decay_note: string;
  chain_enforcement_rollup_schema: typeof CHAIN_ENFORCEMENT_ROLLUP_SCHEMA;
}

const STANDARD_DECAY_NOTE =
  'Kill-switch engages platform BLOCKED — effective enforcement is blocked during silence window. ' +
  'Pre-drill chain_enforcement_mode (including audit_only weakest link) is historical; drill does not retroactively upgrade observe-only hops.';

export function buildShutdownDrillEnforcementDecay(input: {
  session_id?: string | null;
  chain_enforcement: ChainEnforcementRollupResult;
  decay_note?: string;
}): ShutdownDrillEnforcementDecay {
  const chain = input.chain_enforcement;
  const mode = chain?.chain_enforcement_mode ?? 'unknown';
  const weakest = chain?.weakest_link_index ?? null;

  let note = input.decay_note?.trim() || STANDARD_DECAY_NOTE;
  if (mode === 'mixed' && weakest != null) {
    note = `Pre-drill mixed enforcement (weakest hop ${weakest} audit_only) → post-kill blocked. ${note}`;
  }

  return {
    schema: SHUTDOWN_DRILL_ENFORCEMENT_DECAY_SCHEMA,
    session_id: input.session_id != null ? String(input.session_id).trim() || null : null,
    pre_drill_chain_enforcement_mode: String(mode),
    pre_drill_weakest_link_index: weakest,
    post_kill_switch_effective_mode: 'blocked',
    decay_note: note,
    chain_enforcement_rollup_schema: CHAIN_ENFORCEMENT_ROLLUP_SCHEMA,
  };
}

export function validateShutdownDrillEnforcementDecay(
  raw: unknown,
  sessionScope?: string | null,
): { ok: boolean; note: string | null } {
  if (raw == null) return { ok: true, note: null };
  if (typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, note: 'enforcement_decay must be an object' };
  }
  const d = raw as Record<string, unknown>;
  if (d.schema !== SHUTDOWN_DRILL_ENFORCEMENT_DECAY_SCHEMA) {
    return { ok: false, note: `enforcement_decay.schema must be ${SHUTDOWN_DRILL_ENFORCEMENT_DECAY_SCHEMA}` };
  }
  if (d.post_kill_switch_effective_mode !== 'blocked') {
    return { ok: false, note: 'post_kill_switch_effective_mode must be blocked during drill silence window' };
  }
  if (d.chain_enforcement_rollup_schema !== CHAIN_ENFORCEMENT_ROLLUP_SCHEMA) {
    return { ok: false, note: `chain_enforcement_rollup_schema must be ${CHAIN_ENFORCEMENT_ROLLUP_SCHEMA}` };
  }
  const mode = String(d.pre_drill_chain_enforcement_mode || '').trim();
  if (!mode) {
    return { ok: false, note: 'pre_drill_chain_enforcement_mode required' };
  }
  const note = String(d.decay_note || '').trim();
  if (!note) {
    return { ok: false, note: 'decay_note required' };
  }
  const sessionId = d.session_id != null ? String(d.session_id).trim() : null;
  if (sessionScope && sessionId && sessionId !== sessionScope) {
    return { ok: false, note: 'enforcement_decay.session_id must match bundle session_scope when both set' };
  }
  return { ok: true, note: null };
}
