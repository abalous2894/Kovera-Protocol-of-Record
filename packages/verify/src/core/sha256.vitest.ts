import { describe, expect, it } from 'vitest';
import { sha256Buffer, sha256HexUtf8, sha256Utf8 } from './sha256.js';

describe('sha256', () => {
  it('sha256Utf8 and sha256HexUtf8 agree on UTF-8 input', () => {
    const input = 'aevesa.quarterly-retest-receipt/v1';
    expect(sha256HexUtf8(input)).toBe(sha256Utf8(input));
    expect(sha256HexUtf8(input)).toMatch(/^[a-f0-9]{64}$/);
  });

  it('sha256Buffer hashes binary input', () => {
    const buf = new TextEncoder().encode('binary');
    expect(sha256Buffer(buf)).toMatch(/^[a-f0-9]{64}$/);
  });
});