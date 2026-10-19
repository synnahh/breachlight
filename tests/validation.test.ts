import { describe, expect, it } from 'vitest';
import { isValidEmail, normaliseEmail } from '../shared/validation.js';

describe('isValidEmail', () => {
  it('accepts normal addresses', () => {
    for (const e of ['a@b.co', 'john.doe@example.com', 'x+tag@sub.domain.org']) {
      expect(isValidEmail(e)).toBe(true);
    }
  });

  it('rejects malformed addresses', () => {
    for (const e of ['', 'nope', 'a@b', 'a@@b.com', 'a b@c.com', 'a@b..com', 'a@b.c', 42, null]) {
      expect(isValidEmail(e as unknown)).toBe(false);
    }
  });

  it('normalises case and whitespace', () => {
    expect(normaliseEmail('  John@Example.COM ')).toBe('john@example.com');
  });
});
