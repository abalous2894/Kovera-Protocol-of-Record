/**
 * Browser shim for node:crypto — sync SHA-256 via @noble/hashes; signature verify stubbed (Tier A uses alg none).
 */
import { sha256 } from '@noble/hashes/sha256';
import { utf8ToBytes } from '@noble/hashes/utils';

function toBytes(data, encoding) {
  if (typeof data === 'string') {
    return encoding === 'utf8' || encoding == null ? utf8ToBytes(data) : utf8ToBytes(data);
  }
  if (data instanceof Uint8Array) return data;
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  return new Uint8Array(data);
}

export function createHash(algorithm) {
  if (algorithm !== 'sha256') {
    throw new Error(`Browser crypto shim: unsupported algorithm ${algorithm}`);
  }
  const chunks = [];
  return {
    update(data, encoding) {
      chunks.push(toBytes(data, encoding));
      return this;
    },
    digest(encoding) {
      let len = 0;
      for (const c of chunks) len += c.length;
      const merged = new Uint8Array(len);
      let off = 0;
      for (const c of chunks) {
        merged.set(c, off);
        off += c.length;
      }
      const hex = Array.from(sha256(merged))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
      if (encoding === 'hex' || encoding == null) return hex;
      if (encoding === 'base64') {
        const bin = merged.length ? sha256(merged) : new Uint8Array(0);
        let s = '';
        for (const b of bin) s += String.fromCharCode(b);
        return btoa(s);
      }
      return Buffer.from(hex, 'hex');
    },
  };
}

export function createPublicKey() {
  throw new Error(
    'Ed25519/RS256 issuer key verification is not available in the browser bundle; use signature_alg none or verify server-side.',
  );
}

export function verify() {
  return false;
}
