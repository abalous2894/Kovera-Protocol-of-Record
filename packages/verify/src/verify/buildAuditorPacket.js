/**
 * aevesa.auditor-packet/v1 - single export shape for third-party auditors.
 */

import { stableStringify } from '../core/stableStringify.js';
import { sha256Utf8 } from '../core/sha256.js';

export const AUDITOR_PACKET_SCHEMA = 'aevesa.auditor-packet/v1';

/** Match JSON wire shape (drop undefined, ISO dates) so digest survives export + download. */
function jsonCanonicalize(value) {
  return JSON.parse(JSON.stringify(value));
}

/**
 * @param {object} packet - without packet_digest
 */
export function computeAuditorPacketDigest(packet) {
  const clone = jsonCanonicalize(packet);
  delete clone.packet_digest;
  delete clone.packetDigest;
  return sha256Utf8(stableStringify(clone));
}

/**
 * @param {{
 *   bundle?: object | null;
 *   receipt?: object | null;
 *   auditorReport?: object | null;
 *   executiveSummary?: string | null;
 *   entryHash?: string | null;
 *   generatedAt?: string;
 * }} input
 */
export function buildAuditorPacket(input) {
  const body = {
    schema: AUDITOR_PACKET_SCHEMA,
    generated_at: input.generatedAt ?? new Date().toISOString(),
    entry_hash:
      input.entryHash ??
      input.receipt?.proof?.primary_anchor?.entry_hash ??
      input.bundle?.manifest?.entry_hash ??
      input.bundle?.anchor?.entry_hash ??
      null,
    executive_summary: input.executiveSummary ?? input.auditorReport?.executive_summary ?? null,
    bundle: input.bundle ?? null,
    receipt: input.receipt ?? null,
    auditor_report: input.auditorReport ?? null,
    verify_hint: 'aevesa verify <this-file.json>  OR  paste at verify.aevesa.com',
    offline: true,
  };

  const canonicalBody = jsonCanonicalize(body);

  return {
    ...canonicalBody,
    packet_digest: computeAuditorPacketDigest(canonicalBody),
  };
}

/**
 * @param {unknown} packet
 */
export function verifyAuditorPacket(packet) {
  const errors = [];
  if (!packet || typeof packet !== 'object') {
    return { ok: false, errors: ['auditor packet must be an object'], note: 'invalid packet' };
  }

  const p = /** @type {Record<string, unknown>} */ (packet);
  if (p.schema !== AUDITOR_PACKET_SCHEMA) {
    errors.push(`schema must be ${AUDITOR_PACKET_SCHEMA}`);
  }

  const digest = String(p.packet_digest || p.packetDigest || '');
  if (digest && !/^[a-f0-9]{64}$/.test(digest)) {
    errors.push('packet_digest must be 64-char hex');
  } else if (digest) {
    const expected = computeAuditorPacketDigest(p);
    if (expected !== digest) errors.push('packet_digest mismatch - packet may be tampered');
  }

  if (!p.bundle && !p.receipt) {
    errors.push('auditor packet must include bundle and/or receipt');
  }

  return {
    ok: errors.length === 0,
    errors,
    executive_summary: p.executive_summary ?? null,
    note: errors.length ? 'Auditor packet structural verify failed' : 'Auditor packet envelope OK',
  };
}

export { computeAuditorPacketDigest as buildAuditorPacketDigest };

export default {
  AUDITOR_PACKET_SCHEMA,
  buildAuditorPacket,
  verifyAuditorPacket,
  computeAuditorPacketDigest,
};
