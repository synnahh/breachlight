import type { Severity } from '../../shared/types.js';
import type { NormalisedFinding } from './normalise.js';

export interface RiskAssessment {
  severity: Severity;
  reasons: string[];
  whyItMatters: string;
}

const RECENT_YEARS = 3;

/**
 * Transparent heuristic risk scoring. NOT an authoritative number — a documented
 * rule set, surfaced in the UI so the user can see exactly why a finding is
 * rated as it is. Highest matching tier wins.
 */
export function assessRisk(
  finding: NormalisedFinding,
  context: { breachCountForEmail: number; passwordBreachCountForEmail: number } = {
    breachCountForEmail: 1,
    passwordBreachCountForEmail: 0,
  },
): RiskAssessment {
  const f = finding.flags;
  const reasons: string[] = [];
  const recent = isRecent(finding.breachDate ?? finding.disclosureDate);
  const extraSensitive = f.securityQuestionsExposed || f.locationExposed || f.sensitivePersonalExposed;

  // ── CRITICAL ──
  if (f.governmentIdExposed) reasons.push('Government-issued ID data was exposed');
  if (f.financialExposed) reasons.push('Financial or payment data was exposed');
  if (f.sensitivePersonalExposed)
    reasons.push('Sensitive personal data (health, biometric, etc.) was exposed');
  if (f.passwordExposed && finding.passwordRisk === 'plaintext')
    reasons.push('Passwords were exposed in plaintext or a weak format');
  if (f.passwordExposed && recent)
    reasons.push('Passwords/credentials were exposed in a recent breach');
  if (f.passwordExposed && extraSensitive)
    reasons.push('Passwords were exposed alongside other sensitive data');
  if (f.passwordExposed && context.breachCountForEmail >= 4)
    reasons.push(
      'Password data was exposed and this address appears in many breaches — reuse would be high-impact',
    );
  if (reasons.length > 0) return finalise('critical', reasons, finding, context);

  // ── HIGH ──
  if (f.passwordExposed) reasons.push('Passwords or credential hashes were exposed');
  if (f.securityQuestionsExposed)
    reasons.push('Security questions/answers or password hints were exposed');
  if (f.usernameExposed && f.emailExposed && finding.dataClasses.length >= 4)
    reasons.push('Usernames, emails and substantial additional profile data were exposed');
  if (reasons.length > 0) return finalise('high', reasons, finding, context);

  // ── MEDIUM ──
  if (f.emailExposed) reasons.push('Email address was exposed');
  if (f.usernameExposed) reasons.push('Username was exposed');
  if (f.ipExposed) reasons.push('IP address was exposed');
  if (f.phoneExposed) reasons.push('Phone number was exposed');
  if (finding.dataClasses.length >= 3) reasons.push('Several profile fields were exposed');
  if (reasons.length > 0) return finalise('medium', reasons, finding, context);

  // ── LOW ──
  return finalise('low', ['Only low-value metadata was exposed'], finding, context);
}

function finalise(
  severity: Severity,
  reasons: string[],
  finding: NormalisedFinding,
  context: { passwordBreachCountForEmail: number },
): RiskAssessment {
  return { severity, reasons, whyItMatters: whyItMatters(severity, finding, context) };
}

function whyItMatters(
  severity: Severity,
  finding: NormalisedFinding,
  context: { passwordBreachCountForEmail: number },
): string {
  const f = finding.flags;
  if (f.passwordExposed) {
    const reuse =
      context.passwordBreachCountForEmail >= 2
        ? ' Your email appears in more than one password breach, so if you reused that password, other accounts should be treated as at risk too.'
        : ' If you reused that password anywhere else, those accounts should be considered at risk.';
    return (
      `Password-related data appeared in this exposure.${reuse} ` +
      'Recommended priority: change the password now and enable MFA.'
    );
  }
  if (f.governmentIdExposed || f.financialExposed || f.sensitivePersonalExposed) {
    return 'Highly sensitive personal data was exposed. Beyond account security, watch for identity theft, fraud and targeted phishing.';
  }
  if (f.securityQuestionsExposed) {
    return 'Security questions and answers should now be treated as public. Anyone with them could reset your account, so change them and review account recovery.';
  }
  if (severity === 'medium') {
    return 'Your contact details were exposed. The main risk is a rise in targeted phishing and spam, and these details being combined with data from other breaches.';
  }
  return 'Only limited metadata was exposed. Low direct risk, but it still contributes to a profile that attackers can build from multiple breaches.';
}

export function isRecent(dateStr: string | null | undefined): boolean {
  if (!dateStr) return false;
  const d = new Date(dateStr);
  if (Number.isNaN(d.getTime())) return false;
  return Date.now() - d.getTime() <= RECENT_YEARS * 365.25 * 24 * 60 * 60 * 1000;
}

export const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
