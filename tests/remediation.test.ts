import { describe, expect, it } from 'vitest';
import { mergeBreaches } from '../server/services/normalise.js';
import {
  buildAccountLinks,
  buildRecommendations,
  buildWizardSteps,
  generateActions,
} from '../server/services/remediationService.js';
import type { NormalisedBreach } from '../server/providers/types.js';

const raw = (
  dataClasses: string[],
  domain: string | null = 'adobe.com',
  passwordRisk: string | null = null,
): NormalisedBreach => ({
  name: 'Adobe',
  title: 'Adobe',
  service: 'Adobe',
  domain,
  breachDate: '2013-10-04',
  disclosureDate: null,
  firstSeenDate: null,
  description: null,
  dataClasses,
  passwordRisk,
  pwnCount: null,
  industry: null,
  confidence: 'high',
  confidenceReason: 't',
  associationType: 'confirmed',
  source: 't',
  providerId: 't',
  isDemoData: true,
});

const pw = mergeBreaches([raw(['Email addresses', 'Passwords', 'Usernames'], 'adobe.com', 'hashed')])[0];
const emailOnly = mergeBreaches([raw(['Email addresses'])])[0];

describe('buildRecommendations', () => {
  it('leads with password actions when passwords exposed', () => {
    const codes = buildRecommendations(pw).map((r) => r.code);
    expect(codes[0]).toBe('change_password');
    expect(codes).toContain('change_reused');
    expect(codes).toContain('enable_mfa');
  });
  it('email-only exposure recommends MFA + phishing awareness, not a password change', () => {
    const codes = buildRecommendations(emailOnly).map((r) => r.code);
    expect(codes).toContain('enable_mfa');
    expect(codes).toContain('monitor_phishing');
    expect(codes).not.toContain('change_password');
  });
});

describe('buildWizardSteps', () => {
  it('produces ordered steps with a security link on the password step', () => {
    const steps = buildWizardSteps(pw);
    expect(steps[0].key).toBe('password');
    expect(steps.some((s) => s.key === 'mfa')).toBe(true);
    expect(steps.some((s) => s.key === 'reuse')).toBe(true);
  });
});

describe('buildAccountLinks', () => {
  it('returns a known security page + derived root for a known domain', () => {
    const links = buildAccountLinks(pw);
    expect(links.some((l) => l.url === 'https://account.adobe.com/security' && !l.derived)).toBe(true);
    expect(links.some((l) => l.url === 'https://adobe.com/' && l.derived)).toBe(true);
  });
  it('never invents a URL for an invalid domain', () => {
    expect(buildAccountLinks(mergeBreaches([raw(['Passwords'], 'not a domain')])[0])).toEqual([]);
  });
});

describe('generateActions', () => {
  it('creates urgent password + reuse + MFA actions for a password finding', () => {
    const actions = generateActions(pw, 'critical', 'f1', 'e1');
    const titles = actions.map((a) => a.title.toLowerCase());
    expect(titles.some((t) => t.includes('change password'))).toBe(true);
    expect(titles.some((t) => t.includes('reused'))).toBe(true);
    expect(actions.every((a) => a.dedupeKey.length > 0)).toBe(true);
  });
  it('does NOT flood the tracker for low/medium metadata-only findings', () => {
    expect(generateActions(emailOnly, 'medium', 'f2', 'e2')).toEqual([]);
  });
});
