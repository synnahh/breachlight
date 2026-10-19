// Deterministic Personal Security Score.
//
// This is a transparent rule-based score, NOT an AI number. It starts at 100
// and applies a fixed set of factors. Every factor is surfaced in the UI with
// its exact delta so the user can see how the number was built.

import type { ScoreFactor, SecurityScore, Severity } from './types.js';

export interface ScoreInput {
  criticalUnresolved: number;
  highUnresolved: number;
  mediumUnresolved: number;
  lowUnresolved: number;
  passwordExposuresUnresolved: number;
  oldUnresolvedPasswordBreaches: number; // password breach > 2y old, still open
  resolvedFindings: number;
  totalFindings: number;
  mfaActionsCompleted: number;
  mfaActionsTotal: number;
  reusedPasswordSignals: number; // cautious: multiple password breaches
  passwordFoundInComboCheck: boolean;
}

const CLAMP = (n: number) => Math.max(0, Math.min(100, Math.round(n)));

export function computeSecurityScore(input: ScoreInput): SecurityScore {
  const factors: ScoreFactor[] = [];
  let score = 100;

  const add = (label: string, delta: number, detail: string) => {
    if (delta === 0) return;
    score += delta;
    factors.push({ label, delta, detail });
  };

  add(
    'Critical breaches unresolved',
    -15 * input.criticalUnresolved,
    `${input.criticalUnresolved} critical finding(s) still open (-15 each)`,
  );
  add(
    'High-risk breaches unresolved',
    -8 * input.highUnresolved,
    `${input.highUnresolved} high finding(s) still open (-8 each)`,
  );
  add(
    'Medium-risk breaches unresolved',
    -3 * input.mediumUnresolved,
    `${input.mediumUnresolved} medium finding(s) still open (-3 each)`,
  );
  add(
    'Low-risk breaches unresolved',
    -1 * input.lowUnresolved,
    `${input.lowUnresolved} low finding(s) still open (-1 each)`,
  );
  add(
    'Passwords exposed in breaches',
    -10 * input.passwordExposuresUnresolved,
    `${input.passwordExposuresUnresolved} account(s) with exposed password data, not yet secured (-10 each)`,
  );
  add(
    'Old password breaches still open',
    -5 * input.oldUnresolvedPasswordBreaches,
    `${input.oldUnresolvedPasswordBreaches} password breach(es) over 2 years old still unresolved (-5 each)`,
  );
  if (input.passwordFoundInComboCheck) {
    add(
      'A checked password appears in breach datasets',
      -15,
      'You ran a credential check and the password was found in known breach data (-15)',
    );
  }
  if (input.reusedPasswordSignals >= 2) {
    add(
      'Password-reuse risk pattern',
      -8,
      `${input.reusedPasswordSignals} separate password breaches suggest reuse may increase risk (-8)`,
    );
  }

  // Positive factors
  if (input.totalFindings > 0) {
    const resolvedRatio = input.resolvedFindings / input.totalFindings;
    add(
      'Findings resolved',
      Math.round(15 * resolvedRatio),
      `${input.resolvedFindings}/${input.totalFindings} findings marked secured (+15 max)`,
    );
  }
  if (input.mfaActionsTotal > 0) {
    const mfaRatio = input.mfaActionsCompleted / input.mfaActionsTotal;
    add(
      'MFA actions completed',
      Math.round(10 * mfaRatio),
      `${input.mfaActionsCompleted}/${input.mfaActionsTotal} "enable MFA" actions completed (+10 max)`,
    );
  }

  score = CLAMP(score);

  return {
    score,
    band: bandForScore(score),
    factors,
    topRisks: buildTopRisks(input),
  };
}

export function bandForScore(score: number): SecurityScore['band'] {
  if (score < 30) return 'critical';
  if (score < 50) return 'poor';
  if (score < 70) return 'fair';
  if (score < 88) return 'good';
  return 'strong';
}

function buildTopRisks(input: ScoreInput): string[] {
  const risks: { text: string; weight: number }[] = [];
  if (input.passwordExposuresUnresolved > 0)
    risks.push({
      text: `${input.passwordExposuresUnresolved} account(s) with exposed passwords need a password change`,
      weight: 100,
    });
  if (input.passwordFoundInComboCheck)
    risks.push({ text: 'A password you checked appears in known breach datasets', weight: 95 });
  if (input.criticalUnresolved > 0)
    risks.push({
      text: `${input.criticalUnresolved} critical finding(s) still require action`,
      weight: 90,
    });
  if (input.oldUnresolvedPasswordBreaches > 0)
    risks.push({
      text: `${input.oldUnresolvedPasswordBreaches} old breach(es) still need a password change`,
      weight: 70,
    });
  if (input.mfaActionsTotal - input.mfaActionsCompleted > 0)
    risks.push({
      text: `${input.mfaActionsTotal - input.mfaActionsCompleted} service(s) without confirmed MFA`,
      weight: 60,
    });
  if (input.highUnresolved > 0)
    risks.push({
      text: `${input.highUnresolved} high-risk finding(s) still open`,
      weight: 50,
    });
  return risks.sort((a, b) => b.weight - a.weight).slice(0, 4).map((r) => r.text);
}

export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};
