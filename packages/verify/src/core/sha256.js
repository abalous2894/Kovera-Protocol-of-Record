import { createHash } from 'node:crypto';

/**
 * @param {string} input
 */
export function sha256Utf8(input) {
  return createHash('sha256').update(String(input), 'utf8').digest('hex');
}

/** Alias used by receipt pack builders — canonical impl is {@link sha256Utf8}. */
export function sha256HexUtf8(input) {
  return sha256Utf8(input);
}

/**
 * @param {Buffer | Uint8Array} buf
 */
export function sha256Buffer(buf) {
  return createHash('sha256').update(buf).digest('hex');
}
