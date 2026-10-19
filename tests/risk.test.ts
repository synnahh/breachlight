import { describe, expect, it } from 'vitest';
import { mergeBreaches } from '../server/services/normalise.js';
import { assessRisk } from '../server/services/riskService.js';
import type { NormalisedBreach } from '../server/providers/types.js';

function nf(dataClasses: string[], extra: Partial<NormalisedBreach> = {}) {
  return mergeBreaches([
    {
      name: 'X',
      title: 'X',
      service: 'X',
      domain: 'x.example',
      breachDate: '2011-01-01',
      disclosureDate: null,
      firstSeenDate: null,
      description: null,
      dataClasses,
      passwordRisk: null,
      pwnCount: null,
      industry: null,
      confidence: 'high',
      confidenceReason: 't',
      associationType: 'confirmed',
      source: 't',
      providerId: 't',
      isDemoData: true,
      ...extra,
    },
  ])[0];
}
const ctx = (n = 1, p = 0) => ({ breachCountForEmail: n, passwordBreachCountForEmail: p });

describe('assessRisk', () => {
  it('recent password exposure = CRITICAL', () => {
    expect(
      assessRisk(nf(['Email addresses', 'Passwords'], { breachDate: new Date().toISOString() }), ctx())
        .severity,
    ).toBe('critical');
  });
  it('plaintext password = CRITICAL regardless of age', () => {
    expect(assessRisk(nf(['Passwords'], { passwordRisk: 'plaintext' }), ctx()).severity).toBe(
      'critical',
    );
  });
  it('old hashed password exposure = HIGH', () => {
    expect(assessRisk(nf(['Email addresses', 'Passwords']), ctx()).severity).toBe('high');
  });
  it('government ID = CRITICAL', () => {
    expect(assessRisk(nf(['Government issued IDs']), ctx()).severity).toBe('critical');
  });
  it('email + username + IP = MEDIUM', () => {
    expect(assessRisk(nf(['Email addresses', 'Usernames', 'IP addresses']), ctx()).severity).toBe(
      'medium',
    );
  });
  it('marketing metadata only = LOW', () => {
    expect(assessRisk(nf(['Marketing preferences']), ctx()).severity).toBe('low');
  });
  it('does NOT blanket-escalate a metadata finding just because the email is in many breaches', () => {
    expect(assessRisk(nf(['Email addresses']), ctx(20, 0)).severity).toBe('medium');
  });
  it('password finding + many breaches = CRITICAL', () => {
    expect(assessRisk(nf(['Passwords']), ctx(6, 6)).severity).toBe('critical');
  });
  it('always produces reasons and a "why it matters" explanation', () => {
    const r = assessRisk(nf(['Email addresses', 'Passwords']), ctx(1, 1));
    expect(r.reasons.length).toBeGreaterThan(0);
    expect(r.whyItMatters).toMatch(/password/i);
  });
});
