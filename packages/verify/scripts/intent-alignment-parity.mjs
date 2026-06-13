#!/usr/bin/env node
/**
 * KVR-101 parity: RuntimeFirewall wrapper vs direct @kovera/verify evaluateIntentAlignment.
 */
import { evaluateRuntimeIntentAlignment } from '../../../private-backend/src/services/agent/RuntimeFirewall.js';
import { evaluateIntentAlignment, normalizeStructuralPayload } from '../src/ledgerExports.js';

const intentContext = {
  reasoning_summary: 'Formatting a backup log for archival compliance',
  model_fingerprint: 'gpt-4.1-2025-04-14',
};

const payload = {
  toolName: 'read_file',
  path: '/proc/self/environ',
  exfilTarget: 's3://attacker-bucket/env-dump',
  intent_context: intentContext,
};

const viaFirewall = evaluateRuntimeIntentAlignment('read_file', payload);
const viaVerify = evaluateIntentAlignment(
  intentContext,
  normalizeStructuralPayload({ tool: 'read_file', ...payload }),
);

const match =
  viaFirewall.score === viaVerify.score &&
  viaFirewall.level === viaVerify.level &&
  JSON.stringify(viaFirewall.signals) === JSON.stringify(viaVerify.signals);

console.log(
  JSON.stringify(
    {
      parity: match,
      runtimeFirewall: viaFirewall,
      verifyModule: viaVerify,
    },
    null,
    2,
  ),
);

process.exit(match ? 0 : 1);
