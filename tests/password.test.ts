import { describe, expect, it } from 'vitest';
import {
  bandForOccurrences,
  buildPasswordResult,
  isValidHashPrefix,
  parseRangeResponse,
} from '../shared/passwordCheck.js';

describe('parseRangeResponse', () => {
  const body = [
    '003D68EB55068C33ACE09247EE4C639306B:3',
    '1E4C9B93F3F0682250B6CF8331B7EE68FD8:99',
    '0018A45C4D1DEF81644B54AB7F969B88D65:1',
  ].join('\r\n');

  it('finds a matching suffix and returns its count', () => {
    expect(parseRangeResponse(body, '1E4C9B93F3F0682250B6CF8331B7EE68FD8')).toBe(99);
  });

  it('is case-insensitive', () => {
    expect(parseRangeResponse(body.toLowerCase(), '1e4c9b93f3f0682250b6cf8331b7ee68fd8')).toBe(99);
  });

  it('returns 0 when not present', () => {
    expect(parseRangeResponse(body, 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')).toBe(0);
  });

  it('tolerates blank/garbage lines', () => {
    expect(parseRangeResponse('\n\ngarbage\nABC:notanumber\n', 'ABC')).toBe(1);
  });
});

describe('bandForOccurrences', () => {
  it('buckets counts', () => {
    expect(bandForOccurrences(0)).toBe('none');
    expect(bandForOccurrences(5)).toBe('low');
    expect(bandForOccurrences(50)).toBe('medium');
    expect(bandForOccurrences(5000)).toBe('high');
    expect(bandForOccurrences(500_000)).toBe('very_high');
  });
});

describe('buildPasswordResult', () => {
  it('never echoes a password and flags compromise', () => {
    const r = buildPasswordResult(2400);
    expect(r.compromised).toBe(true);
    expect(r.occurrences).toBe(2400);
    expect(JSON.stringify(r)).not.toMatch(/plaintext password value/i);
    expect(r.recommendedActions.length).toBeGreaterThan(0);
  });

  it('clean password gives safe-but-not-guaranteed messaging', () => {
    const r = buildPasswordResult(0);
    expect(r.compromised).toBe(false);
    expect(r.note.toLowerCase()).toContain('not a guarantee');
  });
});

describe('isValidHashPrefix', () => {
  it('accepts exactly 5 hex chars', () => {
    expect(isValidHashPrefix('AB12C')).toBe(true);
    expect(isValidHashPrefix('AB12')).toBe(false);
    expect(isValidHashPrefix('AB12CD')).toBe(false);
    expect(isValidHashPrefix('GHIJK')).toBe(false);
  });
});
