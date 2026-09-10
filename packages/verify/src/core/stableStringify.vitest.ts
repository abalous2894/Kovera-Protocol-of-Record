import { describe, expect, it } from 'vitest';
import { stableStringify } from './stableStringify.js';

describe('stableStringify', () => {
  it('sorts object keys deterministically', () => {
    const a = stableStringify({ z: 1, a: 2, m: { b: 1, a: 2 } });
    const b = stableStringify({ a: 2, m: { a: 2, b: 1 }, z: 1 });
    expect(a).toBe(b);
    expect(a).toBe('{"a":2,"m":{"a":2,"b":1},"z":1}');
  });

  it('preserves array order', () => {
    expect(stableStringify([3, 1, 2])).toBe('[3,1,2]');
  });
});
