import { describe, expect, it } from 'vitest';
import { bandForScore, computeSecurityScore, type ScoreInput } from '../shared/scoring.js';
import { assessCombo } from '../shared/combo.js';

const base: ScoreInput = {
  criticalUnresolved: 0,
  highUnresolved: 0,
  mediumUnresolved: 0,
  lowUnresolved: 0,
  passwordExposuresUnresolved: 0,
  oldUnresolvedPasswordBreaches: 0,
  resolvedFindings: 0,
  totalFindings: 0,
  mfaActionsCompleted: 0,
  mfaActionsTotal: 0,
  reusedPasswordSignals: 0,
  passwordFoundInComboCheck: false,
};

describe('computeSecurityScore', () => {
  it('a clean profile scores 100 / strong', () => {
    const s = computeSecurityScore(base);
    expect(s.score).toBe(100);
    expect(s.band).toBe('strong');
    expect(s.factors).toEqual([]);
  });

  it('is deterministic and every penalty is itemised', () => {
    const s = computeSecurityScore({
      ...base,
      criticalUnresolved: 2,
      passwordExposuresUnresolved: 1,
      totalFindings: 3,
      resolvedFindings: 0,
    });
    // 100 - 30 (critical) - 10 (password) = 60
    expect(s.score).toBe(60);
    expect(s.factors.some((f) => f.label.includes('Critical') && f.delta === -30)).toBe(true);
    expect(s.factors.some((f) => f.delta === -10)).toBe(true);
  });

  it('rewards resolved findings and completed MFA actions', () => {
    const s = computeSecurityScore({
      ...base,
      totalFindings: 4,
      resolvedFindings: 4,
      mfaActionsTotal: 2,
      mfaActionsCompleted: 2,
    });
    expect(s.score).toBe(100);
    expect(s.factors.some((f) => f.delta > 0)).toBe(true);
  });

  it('clamps to 0-100', () => {
    expect(computeSecurityScore({ ...base, criticalUnresolved: 50 }).score).toBe(0);
    expect(bandForScore(0)).toBe('critical');
    expect(bandForScore(100)).toBe('strong');
  });
});

describe('assessCombo — three distinct facts', () => {
  it('email + password both exposed => CRITICAL', () => {
    const r = assessCombo({
      email: 'a@b.com',
      emailExposed: true,
      emailBreachCount: 3,
      emailConfidence: 'high',
      passwordOccurrences: 500,
    });
    expect(r.combinationRisk).toBe('critical');
    expect(r.passwordExposed).toBe(true);
    expect(r.emailExposed).toBe(true);
  });
  it('password exposed, email not => HIGH', () => {
    const r = assessCombo({
      email: 'a@b.com',
      emailExposed: false,
      emailBreachCount: 0,
      emailConfidence: 'medium',
      passwordOccurrences: 5,
    });
    expect(r.combinationRisk).toBe('high');
  });
  it('neither exposed => LOW, with a "not a guarantee" note', () => {
    const r = assessCombo({
      email: 'a@b.com',
      emailExposed: false,
      emailBreachCount: 0,
      emailConfidence: 'low',
      passwordOccurrences: 0,
    });
    expect(r.combinationRisk).toBe('low');
    expect(r.combinationRiskReason).toMatch(/not a guarantee/i);
  });
  it('never echoes the password and always gives recommended actions', () => {
    const r = assessCombo({
      email: 'a@b.com',
      emailExposed: true,
      emailBreachCount: 1,
      emailConfidence: 'high',
      passwordOccurrences: 9,
    });
    expect(r.recommendedActions.length).toBeGreaterThan(0);
    expect(JSON.stringify(r)).not.toContain('passwordOccurrences":"');
  });
});
