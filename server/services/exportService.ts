import type { BreachFinding, Scan, SecurityAction } from '../../shared/types.js';

// Security report export. NEVER includes plaintext passwords or password hashes
// (the app never has them). Findings carry only breach metadata + status.

export interface ReportBundle {
  generatedAt: string;
  scan: Scan | null;
  findings: BreachFinding[];
  actions: SecurityAction[];
}

export function buildJsonReport(bundle: ReportBundle): string {
  const redactedFindings = bundle.findings.map((f) => ({
    service: f.service,
    domain: f.domain,
    email: f.email,
    breachName: f.breachName,
    breachDate: f.breachDate,
    disclosureDate: f.disclosureDate,
    firstSeenDate: f.firstSeenDate,
    dataClasses: f.dataClasses,
    passwordInvolved: f.passwordExposed,
    severity: f.severity,
    confidence: f.confidence,
    associationType: f.associationType,
    status: f.status,
    whyItMatters: f.whyItMatters,
    source: f.source,
  }));
  return JSON.stringify(
    {
      report: 'Breachlight — Security Report',
      generatedAt: bundle.generatedAt,
      scan: bundle.scan
        ? {
            id: bundle.scan.id,
            date: bundle.scan.finishedAt ?? bundle.scan.startedAt,
            depth: bundle.scan.depth,
            providersUsed: bundle.scan.providerOutcomes.map((p) => ({ label: p.label, ok: p.ok })),
            coverage: bundle.scan.coverage,
            summary: bundle.scan.summary,
          }
        : null,
      findings: redactedFindings,
      actions: bundle.actions.map((a) => ({
        title: a.title,
        priority: a.priority,
        status: a.status,
        finding: a.findingId,
      })),
      unresolvedActions: bundle.actions.filter(
        (a) => a.status === 'not_started' || a.status === 'in_progress',
      ).length,
      note: 'This report contains breach metadata and remediation status only. No passwords or password hashes are ever stored or exported.',
    },
    null,
    2,
  );
}

export function buildCsvReport(bundle: ReportBundle): string {
  const rows = [
    [
      'service',
      'domain',
      'email',
      'breach',
      'breach_date',
      'disclosure_date',
      'data_exposed',
      'password_involved',
      'severity',
      'confidence',
      'association',
      'status',
      'source',
    ],
    ...bundle.findings.map((f) => [
      f.service,
      f.domain ?? '',
      f.email,
      f.breachName,
      f.breachDate ?? '',
      f.disclosureDate ?? '',
      f.dataClasses.join(' | '),
      f.passwordExposed ? 'yes' : 'no',
      f.severity,
      f.confidence,
      f.associationType,
      f.status,
      f.source,
    ]),
  ];
  return rows.map((r) => r.map(csvCell).join(',')).join('\r\n');
}

function csvCell(v: string): string {
  let s = String(v ?? '');
  // Guard against CSV/formula injection when the file is opened in a spreadsheet.
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
