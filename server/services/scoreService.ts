import { computeSecurityScore, type ScoreInput } from '../../shared/scoring.js';
import type { BreachFinding, SecurityAction, SecurityScore } from '../../shared/types.js';
import { getMeta } from '../db.js';

const TWO_YEARS_MS = 2 * 365.25 * 24 * 60 * 60 * 1000;

export function buildScoreInput(
  findings: BreachFinding[],
  actions: SecurityAction[],
): ScoreInput {
  const unresolved = findings.filter((f) => f.status !== 'secured');
  const bySev = (s: string) => unresolved.filter((f) => f.severity === s).length;

  const passwordUnresolved = unresolved.filter((f) => f.passwordExposed);
  const oldPasswordUnresolved = passwordUnresolved.filter((f) => {
    const d = f.breachDate ?? f.disclosureDate;
    return d && Date.now() - new Date(d).getTime() > TWO_YEARS_MS;
  });

  const mfaActions = actions.filter((a) => /enable mfa/i.test(a.title));
  const mfaDone = mfaActions.filter((a) => a.status === 'completed').length;

  // "reuse signal" — number of distinct breaches with password data for any one email
  const pwByEmail = new Map<string, number>();
  for (const f of findings) {
    if (f.passwordExposed) pwByEmail.set(f.email, (pwByEmail.get(f.email) ?? 0) + 1);
  }
  const reusedPasswordSignals = Math.max(0, ...[...pwByEmail.values()], 0);

  return {
    criticalUnresolved: bySev('critical'),
    highUnresolved: bySev('high'),
    mediumUnresolved: bySev('medium'),
    lowUnresolved: bySev('low'),
    passwordExposuresUnresolved: passwordUnresolved.length,
    oldUnresolvedPasswordBreaches: oldPasswordUnresolved.length,
    resolvedFindings: findings.filter((f) => f.status === 'secured').length,
    totalFindings: findings.length,
    mfaActionsCompleted: mfaDone,
    mfaActionsTotal: mfaActions.length,
    reusedPasswordSignals,
    passwordFoundInComboCheck: getMeta('combo_password_found') === '1',
  };
}

export function securityScore(
  findings: BreachFinding[],
  actions: SecurityAction[],
): SecurityScore {
  return computeSecurityScore(buildScoreInput(findings, actions));
}
