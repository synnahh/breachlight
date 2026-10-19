import type {
  AccountLink,
  RecommendationItem,
  Severity,
  WizardStep,
} from '../../shared/types.js';
import type { NormalisedFinding } from './normalise.js';

// ── Recommendation engine (deterministic) ────────────────────────────────
// Each exposure category maps to a fixed set of recommendation codes. No AI.

const RECOMMENDATIONS: Record<string, RecommendationItem> = {
  change_password: {
    code: 'change_password',
    label: 'Change the password',
    detail: 'Set a new password on this service immediately.',
  },
  change_reused: {
    code: 'change_reused',
    label: 'Change this password everywhere it was reused',
    detail: 'Reused passwords let one breach unlock many accounts.',
  },
  unique_password: {
    code: 'unique_password',
    label: 'Use a unique password',
    detail: 'Every account should have its own password — a password manager makes this practical.',
  },
  enable_mfa: {
    code: 'enable_mfa',
    label: 'Enable multi-factor authentication (MFA)',
    detail: 'MFA blocks the large majority of account-takeover attempts.',
  },
  enable_passkey: {
    code: 'enable_passkey',
    label: 'Add a passkey if the service supports it',
    detail: 'Passkeys remove the password from the login and cannot be phished the same way.',
  },
  revoke_sessions: {
    code: 'revoke_sessions',
    label: 'Sign out active sessions',
    detail: 'Revoke logged-in devices you do not recognise.',
  },
  review_activity: {
    code: 'review_activity',
    label: 'Review recent login activity',
    detail: 'Check for logins from unfamiliar locations or devices.',
  },
  recovery_email: {
    code: 'recovery_email',
    label: 'Verify the recovery email',
    detail: 'Attackers often change recovery methods to lock you out.',
  },
  recovery_phone: {
    code: 'recovery_phone',
    label: 'Verify the recovery phone number',
    detail: 'Confirm it is still yours and consider carrier-level SIM protection.',
  },
  security_questions: {
    code: 'security_questions',
    label: 'Reset security questions and answers',
    detail: 'Treat the old answers as public knowledge.',
  },
  check_oauth: {
    code: 'check_oauth',
    label: 'Review connected apps / OAuth grants',
    detail: 'Remove third-party applications you no longer use.',
  },
  monitor_phishing: {
    code: 'monitor_phishing',
    label: 'Watch for phishing',
    detail: 'Expect more targeted email/SMS. Do not click links in unexpected messages.',
  },
  monitor_finance: {
    code: 'monitor_finance',
    label: 'Monitor financial statements',
    detail: 'Consider notifying your bank/card provider and watching for unusual activity.',
  },
  identity_monitoring: {
    code: 'identity_monitoring',
    label: 'Consider a credit freeze / fraud alert',
    detail: 'Government-ID exposure raises identity-theft risk.',
  },
  sim_security: {
    code: 'sim_security',
    label: 'Review SIM / carrier account security',
    detail: 'A leaked phone number can be used for SIM-swap attacks against SMS 2FA.',
  },
};

export function buildRecommendations(finding: NormalisedFinding): RecommendationItem[] {
  const f = finding.flags;
  const codes = new Set<string>();
  const add = (...c: string[]) => c.forEach((x) => codes.add(x));

  add('review_activity', 'enable_mfa', 'recovery_email');

  if (f.passwordExposed) add('change_password', 'change_reused', 'unique_password', 'revoke_sessions', 'enable_passkey');
  else add('unique_password');

  if (f.securityQuestionsExposed) add('security_questions', 'recovery_email');
  if (f.phoneExposed) add('recovery_phone', 'sim_security');
  if (f.emailExposed) add('monitor_phishing');
  if (f.financialExposed) add('monitor_finance');
  if (f.governmentIdExposed) add('identity_monitoring');
  if (f.sensitivePersonalExposed) add('monitor_phishing');
  add('check_oauth');

  // Deterministic ordering
  const ORDER = [
    'change_password',
    'change_reused',
    'unique_password',
    'enable_mfa',
    'enable_passkey',
    'security_questions',
    'revoke_sessions',
    'review_activity',
    'recovery_email',
    'recovery_phone',
    'sim_security',
    'check_oauth',
    'monitor_phishing',
    'monitor_finance',
    'identity_monitoring',
  ];
  return ORDER.filter((c) => codes.has(c)).map((c) => RECOMMENDATIONS[c]);
}

/** Plain-text remediation list (kept for compatibility / simple displays). */
export function buildRemediation(finding: NormalisedFinding): string[] {
  const service = finding.title || finding.name;
  return buildRecommendations(finding).map((r) => {
    if (r.code === 'change_password') return `Change your ${service} password immediately`;
    if (r.code === 'enable_mfa') return `Enable multi-factor authentication (MFA) on ${service}`;
    return r.label;
  });
}

// ── Remediation wizard ───────────────────────────────────────────────────

export function buildWizardSteps(finding: NormalisedFinding): WizardStep[] {
  const service = finding.title || finding.name;
  const links = buildAccountLinks(finding);
  const securityLink = links.find((l) => !l.derived) ?? links[0];
  const steps: WizardStep[] = [];

  if (finding.flags.passwordExposed) {
    steps.push({
      key: 'password',
      title: `Change your ${service} password`,
      detail: 'Use a new, unique password. If you have reused it elsewhere, change it there too.',
      link: securityLink,
    });
  } else {
    steps.push({
      key: 'password',
      title: `Review your ${service} password`,
      detail: 'If it is old, weak, or reused anywhere, change it now.',
      link: securityLink,
    });
  }
  steps.push({
    key: 'mfa',
    title: 'Enable multi-factor authentication',
    detail: 'Turn on MFA (authenticator app or passkey preferred over SMS).',
    link: securityLink,
  });
  steps.push({
    key: 'sessions',
    title: 'Review active sessions',
    detail: 'Sign out any device or session you do not recognise.',
  });
  steps.push({
    key: 'recovery',
    title: 'Check recovery email and phone',
    detail: 'Make sure the recovery contact details are current and belong to you.',
  });
  if (finding.flags.securityQuestionsExposed) {
    steps.push({
      key: 'questions',
      title: 'Reset security questions',
      detail: 'Choose new answers — the previous ones should be treated as public.',
    });
  }
  steps.push({
    key: 'reuse',
    title: 'Check for password reuse',
    detail: 'Use the Combo Finder or your password manager to find other accounts sharing this password.',
  });
  return steps;
}

// ── Auto checklist / action generation ───────────────────────────────────

export interface GeneratedAction {
  title: string;
  description: string;
  priority: 'urgent' | 'recommended';
  dedupeKey: string;
}

export function generateActions(
  finding: NormalisedFinding,
  severity: Severity,
  findingId: string,
  emailId: string,
): GeneratedAction[] {
  const service = finding.title || finding.name;
  const urgent = severity === 'critical' || severity === 'high';
  const priority: 'urgent' | 'recommended' = urgent ? 'urgent' : 'recommended';
  const actions: GeneratedAction[] = [];

  // Only generate a task list for findings that actually require action —
  // critical/high severity or any password exposure. Medium/low findings are
  // covered by the general guidance and the finding's own remediation list, so
  // we don't flood the action tracker.
  if (!urgent && !finding.flags.passwordExposed) return actions;

  if (finding.flags.passwordExposed) {
    actions.push({
      title: `Change password for ${service}`,
      description: `Password data was exposed in the ${service} breach. Change it here and anywhere it was reused.`,
      priority: 'urgent',
      dedupeKey: `${findingId}:change-password`,
    });
    actions.push({
      title: 'Change this password on any other account where it was reused',
      description: 'Reused passwords let attackers pivot from one breach to many accounts.',
      priority: 'urgent',
      dedupeKey: `${emailId}:reuse-sweep`,
    });
  }
  actions.push({
    title: `Enable MFA on ${service}`,
    description: 'Multi-factor authentication blocks most account-takeover attempts.',
    priority,
    dedupeKey: `${findingId}:mfa`,
  });
  actions.push({
    title: `Review active sessions & recent activity for ${service}`,
    description: 'Sign out unknown devices and check for logins you did not make.',
    priority,
    dedupeKey: `${findingId}:sessions`,
  });
  actions.push({
    title: `Verify recovery email & phone for ${service}`,
    description: 'Attackers often change recovery methods to lock you out.',
    priority: 'recommended',
    dedupeKey: `${findingId}:recovery`,
  });
  if (finding.flags.securityQuestionsExposed) {
    actions.push({
      title: `Reset security questions for ${service}`,
      description: 'The previous security answers should be considered public.',
      priority,
      dedupeKey: `${findingId}:security-questions`,
    });
  }
  if (finding.flags.phoneExposed) {
    actions.push({
      title: `Review SIM / carrier security for the number exposed by ${service}`,
      description: 'A leaked phone number enables SIM-swap attacks against SMS-based 2FA.',
      priority: 'recommended',
      dedupeKey: `${findingId}:sim`,
    });
  }
  return actions;
}

// ── Account links (never invented) ───────────────────────────────────────

const KNOWN_SECURITY_PATHS: Record<string, string> = {
  'adobe.com': 'https://account.adobe.com/security',
  'linkedin.com': 'https://www.linkedin.com/mypreferences/d/manage-account-security',
  'dropbox.com': 'https://www.dropbox.com/account/security',
  'twitter.com': 'https://twitter.com/settings/security',
  'x.com': 'https://x.com/settings/security',
  'facebook.com': 'https://www.facebook.com/settings?tab=security',
  'google.com': 'https://myaccount.google.com/security',
  'microsoft.com': 'https://account.microsoft.com/security',
  'yahoo.com': 'https://login.yahoo.com/account/security',
  'canva.com': 'https://www.canva.com/settings/login-and-security',
  'myspace.com': 'https://myspace.com/settings/account',
};

export function buildAccountLinks(finding: NormalisedFinding): AccountLink[] {
  const domain = normaliseDomain(finding.domain);
  if (!domain) return [];
  const links: AccountLink[] = [];
  const known = KNOWN_SECURITY_PATHS[domain];
  if (known) links.push({ label: `${domain} security settings`, url: known, derived: false });
  links.push({
    label: `${domain} (go to Account → Security → Password / MFA)`,
    url: `https://${domain}/`,
    derived: true,
  });
  return links;
}

function normaliseDomain(domain: string | null): string | null {
  if (!domain) return null;
  const d = domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(d)) return null;
  return d.replace(/^www\./, '');
}
