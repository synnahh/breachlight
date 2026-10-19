import type {
  BreachFinding,
  CorrelationReport,
  TimelineEntry,
} from '../../shared/types.js';

/**
 * Cross-breach correlation. Uses cautious language — it never asserts that a
 * password was actually reused, only that the pattern of exposures raises risk.
 */
export function correlate(findings: BreachFinding[]): CorrelationReport {
  const withDates = findings.filter((f) => f.breachDate);
  const sorted = [...withDates].sort(
    (a, b) => new Date(a.breachDate!).getTime() - new Date(b.breachDate!).getTime(),
  );
  const passwordBreaches = sorted.filter((f) => f.passwordExposed);
  const firstPasswordDate = passwordBreaches[0]?.breachDate ?? null;
  const passwordBreachesAfterFirst = firstPasswordDate
    ? sorted.filter(
        (f) =>
          f.passwordExposed &&
          new Date(f.breachDate!).getTime() > new Date(firstPasswordDate).getTime(),
      ).length
    : 0;

  const patterns: string[] = [];
  if (findings.length >= 2) {
    patterns.push(`This identity appears in ${findings.length} separate breaches.`);
  }
  if (passwordBreaches.length >= 1) {
    patterns.push(
      `${passwordBreaches.length} of those breach(es) involved password data.`,
    );
  }
  if (passwordBreachesAfterFirst >= 1) {
    patterns.push(
      `${passwordBreachesAfterFirst} password breach(es) occurred after the earliest password exposure. ` +
        'If the same password was reused across that period, the risk compounds.',
    );
  }
  if (passwordBreaches.length >= 2) {
    patterns.push(
      'Multiple password exposures over time is a common sign of password reuse — using a unique password per site removes most of this risk.',
    );
  }
  const criticals = findings.filter((f) => f.severity === 'critical' && f.status !== 'secured');
  if (criticals.length >= 2) {
    patterns.push(
      `${criticals.length} critical findings are still unresolved — prioritise those before anything else.`,
    );
  }
  if (patterns.length === 0) {
    patterns.push('No cross-breach risk pattern detected in the current findings.');
  }

  const perEmailMap = new Map<string, Set<string>>();
  for (const f of findings) {
    if (!perEmailMap.has(f.email)) perEmailMap.set(f.email, new Set());
    perEmailMap.get(f.email)!.add(f.service);
  }

  return {
    breachCount: findings.length,
    passwordBreachCount: passwordBreaches.length,
    passwordBreachesAfterFirst,
    earliestBreach: sorted[0]?.breachDate ?? null,
    latestBreach: sorted[sorted.length - 1]?.breachDate ?? null,
    patterns,
    perEmail: [...perEmailMap.entries()].map(([email, services]) => ({
      email,
      services: [...services].sort(),
    })),
    timeline: buildTimeline(findings),
  };
}

export function buildTimeline(findings: BreachFinding[]): TimelineEntry[] {
  return findings
    .filter((f) => f.breachDate)
    .map((f) => ({
      year: new Date(f.breachDate!).getUTCFullYear(),
      service: f.service,
      severity: f.severity,
      passwordInvolved: f.passwordExposed,
    }))
    .filter((e) => Number.isFinite(e.year) && e.year > 1990)
    .sort((a, b) => a.year - b.year || a.service.localeCompare(b.service));
}
