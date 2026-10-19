import type { DashboardSummary, Severity } from '../../shared/types.js';
import { baselineReady, optionalProvidersConfigured } from '../providers/index.js';
import {
  lastScanAt,
  lastScanId,
  listActions,
  listEmails,
  listFindings,
} from './storageService.js';
import { securityScore } from './scoreService.js';

export function getDashboard(): DashboardSummary {
  const emails = listEmails();
  const findings = listFindings();
  const actions = listActions();
  const active = findings.filter((f) => f.status !== 'secured');

  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of active) counts[f.severity]++;

  const actionsCompleted = actions.filter((a) => a.status === 'completed').length;
  const actionsApplicable = actions.filter((a) => a.status !== 'not_applicable');
  const actionProgressPercent =
    actionsApplicable.length === 0
      ? 100
      : Math.round((actionsCompleted / actionsApplicable.length) * 100);

  const urgentFindings = active
    .filter((f) => f.severity === 'critical' || f.severity === 'high' || f.passwordExposed)
    .slice(0, 6)
    .map((f) => ({
      id: f.id,
      service: f.service,
      severity: f.severity,
      headline: f.passwordExposed ? 'Password exposure' : `${f.severity} exposure`,
    }));

  const exposedAccounts = active.slice(0, 25).map((f) => ({
    id: f.id,
    service: f.service,
    exposure: exposureLabel(f),
    date: f.breachDate,
    severity: f.severity,
    status: f.status,
  }));

  return {
    score: securityScore(findings, actions),
    emailsMonitored: emails.length,
    findingsTotal: active.length,
    counts,
    servicesExposed: new Set(active.map((f) => f.service)).size,
    passwordExposures: active.filter((f) => f.passwordExposed).length,
    actionsTotal: actionsApplicable.length,
    actionsCompleted,
    actionProgressPercent,
    urgentFindings,
    exposedAccounts,
    lastScanAt: lastScanAt(),
    lastScanId: lastScanId(),
    baselineReady: baselineReady(),
    optionalProvidersConfigured: optionalProvidersConfigured(),
    notifications: buildNotifications(active, actions, lastScanAt()),
  };
}

function exposureLabel(f: {
  passwordExposed: boolean;
  emailExposed: boolean;
  usernameExposed: boolean;
  phoneExposed: boolean;
}): string {
  if (f.passwordExposed) return 'Password';
  if (f.phoneExposed) return 'Phone';
  if (f.usernameExposed) return 'Username';
  if (f.emailExposed) return 'Email';
  return 'Metadata';
}

function buildNotifications(
  active: { severity: Severity; passwordExposed: boolean }[],
  actions: { status: string }[],
  lastScan: string | null,
): string[] {
  const out: string[] = [];
  const openActions = actions.filter((a) => a.status === 'not_started' || a.status === 'in_progress').length;
  if (openActions > 0) out.push(`${openActions} security action(s) remain unresolved.`);
  const pw = active.filter((f) => f.passwordExposed).length;
  if (pw > 0) out.push(`${pw} account(s) still have exposed passwords that need changing.`);
  if (lastScan) {
    const days = Math.floor((Date.now() - new Date(lastScan).getTime()) / 86_400_000);
    if (days >= 30) out.push(`Your last security scan was ${days} days ago — consider running another.`);
  } else {
    out.push('You have not run a scan yet. Add an email and start a Standard scan.');
  }
  return out;
}
