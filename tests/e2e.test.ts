import { beforeEach, describe, expect, it } from 'vitest';
import { startScan, scanEmailNow } from '../server/services/scanService.js';
import { getDashboard } from '../server/services/dashboardService.js';
import { correlate } from '../server/services/correlationService.js';
import { buildCsvReport, buildJsonReport } from '../server/services/exportService.js';
import {
  addEmail,
  getScan,
  listActions,
  listFindings,
  listFindingsForEmail,
  scanHistory,
  setActionStatus,
  setFindingStatus,
  wipeAllData,
} from '../server/services/storageService.js';

beforeEach(() => wipeAllData());

async function waitForScan(id: string) {
  for (let i = 0; i < 400; i++) {
    const s = getScan(id);
    if (s && s.status !== 'running') return s;
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error('scan did not finish');
}

describe('V2 end-to-end (demo provider)', () => {
  it('add email → deep scan → findings → correlation → remediation → resolve → dashboard', async () => {
    const email = addEmail('breach.victim.gamer@example.com', 'Primary');

    const started = startScan({ emailIds: [email.id], depth: 'deep' });
    expect('scanId' in started).toBe(true);
    const scanId = (started as { scanId: string }).scanId;

    const scan = await waitForScan(scanId);
    expect(scan.status).toBe('complete');
    expect(scan.error).toBeNull();
    expect(scan.stages.every((s) => s.status === 'ok' || s.status === 'skipped')).toBe(true);
    expect(scan.summary!.total).toBeGreaterThan(0);
    expect(scan.coverage.percent).toBeGreaterThan(0);
    expect(scan.coverage.sourcesTotal).toBeGreaterThan(0);

    const findings = listFindings();
    // severity spread — not everything is critical
    const severities = new Set(findings.map((f) => f.severity));
    expect(severities.size).toBeGreaterThan(1);
    expect(findings[0].severity).toBe('critical');
    expect(findings.every((f) => f.isDemoData)).toBe(true);
    expect(findings.every((f) => f.whyItMatters.length > 0 && f.recommendations.length > 0)).toBe(true);
    expect(findings.every((f) => f.wizardSteps.length > 0)).toBe(true);

    const corr = correlate(findings);
    expect(corr.breachCount).toBe(findings.length);
    expect(corr.timeline.length).toBeGreaterThan(0);
    expect(corr.patterns.length).toBeGreaterThan(0);

    // actions generated only for findings that need action
    const actions = listActions();
    expect(actions.length).toBeGreaterThan(0);
    expect(actions.some((a) => a.priority === 'urgent')).toBe(true);
    expect(actions.every((a) => a.status === 'not_started')).toBe(true);

    // advance an action through the lifecycle
    const done = setActionStatus(actions[0].id, 'in_progress');
    expect(done?.status).toBe('in_progress');
    setActionStatus(actions[0].id, 'completed');

    // securing a finding closes its actions
    const pwFinding = findings.find((f) => f.passwordExposed)!;
    setFindingStatus(pwFinding.id, 'secured');
    expect(
      listActions().filter((a) => a.findingId === pwFinding.id && a.status !== 'completed'),
    ).toHaveLength(0);

    const dash = getDashboard();
    expect(dash.emailsMonitored).toBe(1);
    expect(dash.findingsTotal).toBe(findings.length - 1);
    expect(dash.score.factors.length).toBeGreaterThan(0);
    expect(dash.lastScanId).toBe(scanId);

    // history + export
    const history = scanHistory();
    expect(history[0].id).toBe(scanId);
    const bundle = { generatedAt: new Date().toISOString(), scan, findings, actions: listActions() };
    const json = buildJsonReport(bundle);
    expect(json).not.toMatch(/passwordHash|plaintext password value/i);
    expect(JSON.parse(json).findings.length).toBe(findings.length);
    expect(buildCsvReport(bundle).split('\r\n').length).toBe(findings.length + 1);
  });

  it('quick scan uses fewer stages and still produces findings', async () => {
    const email = addEmail('breach.victim@example.com');
    const started = startScan({ emailIds: [email.id], depth: 'quick' });
    const scanId = (started as { scanId: string }).scanId;
    const scan = await waitForScan(scanId);
    expect(scan.status).toBe('complete');
    expect(scan.stages.some((s) => s.key === 'correlate')).toBe(false);
    expect(listFindingsForEmail(email.id).length).toBeGreaterThan(0);
  });

  it('re-scanning does not duplicate findings and preserves user status', async () => {
    const email = addEmail('repeat.victim@example.com');
    const first = await scanEmailNow(email.id, 'standard');
    expect('scan' in first).toBe(true);
    const f0 = listFindingsForEmail(email.id)[0];
    setFindingStatus(f0.id, 'in_progress');

    await scanEmailNow(email.id, 'standard');
    const after = listFindingsForEmail(email.id);
    expect(after.length).toBe((first as any).findings.length);
    expect(after.find((f) => f.id === f0.id)?.status).toBe('in_progress');
  });

  it('a clean address yields zero findings but a successful scan', async () => {
    const email = addEmail('clean.person@example.com');
    const started = startScan({ emailIds: [email.id], depth: 'standard' });
    const scan = await waitForScan((started as { scanId: string }).scanId);
    expect(scan.status).toBe('complete');
    expect(scan.summary!.total).toBe(0);
  });

  it('scanning with no valid emails is a handled error, not a crash', () => {
    const r = startScan({ emailIds: ['does-not-exist'], depth: 'standard' });
    expect('error' in r).toBe(true);
  });
});
