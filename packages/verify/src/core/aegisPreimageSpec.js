/**
 * Aegis ledger entryHash preimage specification — must match appendAuditLog in aegisTrust.js.
 */

export const AEGIS_LEDGER_PREIMAGE_SPEC = 'aegis/1';

/** @type {readonly string[]} */
export const AEGIS_ENTRY_HASH_INPUT_KEYS = [
  'agentId',
  'eventType',
  'severity',
  'payload',
  'timestamp',
  'prevHash',
  'contextHash',
  'governanceBinding',
];

/** @type {readonly string[]} */
export const AEGIS_CONTEXT_LINKAGE_KEYS = ['agentId', 'eventType', 'severity', 'payload', 'timestamp'];
