import { describe, expect, it } from 'vitest';
import {
  applyEnrichment,
  deriveExposureFlags,
  dedupeStrings,
  mergeBreaches,
} from '../server/services/normalise.js';
import type { NormalisedBreach } from '../server/providers/types.js';

function raw(p: Partial<NormalisedBreach> & { name: string }): NormalisedBreach {
  return {
    title: p.name,
    service: p.name,
    domain: null,
    breachDate: null,
    disclosureDate: null,
    firstSeenDate: null,
    description: null,
    dataClasses: [],
    passwordRisk: null,
    pwnCount: null,
    industry: null,
    confidence: 'high',
    confidenceReason: 'test',
    associationType: 'confirmed',
    source: 'test',
    providerId: 'test',
    isDemoData: false,
    ...p,
  };
}

describe('deriveExposureFlags', () => {
  it('maps data class labels + password risk to flags', () => {
    const f = deriveExposureFlags(
      ['Email addresses', 'Usernames', 'Phone numbers', 'Security questions and answers'],
      'plaintext',
    );
    expect(f.emailExposed).toBe(true);
    expect(f.usernameExposed).toBe(true);
    expect(f.phoneExposed).toBe(true);
    expect(f.securityQuestionsExposed).toBe(true);
    expect(f.passwordExposed).toBe(true); // from passwordRisk
  });
  it('does not set passwordExposed for unknown password risk alone', () => {
    expect(deriveExposureFlags(['Email addresses'], 'unknown').passwordExposed).toBe(false);
  });
});

describe('dedupeStrings', () => {
  it('is case-insensitive and trims', () => {
    expect(dedupeStrings(['Email', ' email ', 'EMAIL', 'Names'])).toEqual(['Email', 'Names']);
  });
});

describe('mergeBreaches', () => {
  it('merges records for the same breach across providers, keeping highest confidence', () => {
    const merged = mergeBreaches([
      raw({ name: 'Adobe', dataClasses: ['Email addresses'], confidence: 'low', providerId: 'a', source: 'A' }),
      raw({ name: 'adobe', dataClasses: ['Passwords'], confidence: 'high', providerId: 'b', source: 'B' }),
    ]);
    expect(merged).toHaveLength(1);
    expect(merged[0].dataClasses.sort()).toEqual(['Email addresses', 'Passwords']);
    expect(merged[0].confidence).toBe('high');
    expect(merged[0].providerIds.sort()).toEqual(['a', 'b']);
    expect(merged[0].flags.passwordExposed).toBe(true);
  });
});

describe('applyEnrichment', () => {
  it('fills gaps only and never overwrites known values', () => {
    const [f] = mergeBreaches([raw({ name: 'Dropbox', domain: null, dataClasses: ['Email addresses'] })]);
    const enriched = applyEnrichment(f, {
      name: 'Dropbox',
      domain: 'dropbox.com',
      breachDate: '2012-07-01',
      dataClasses: ['Passwords'],
    });
    expect(enriched.domain).toBe('dropbox.com');
    expect(enriched.breachDate).toBe('2012-07-01');
    expect(enriched.dataClasses.sort()).toEqual(['Email addresses', 'Passwords']);
    expect(enriched.flags.passwordExposed).toBe(true);
  });
});
