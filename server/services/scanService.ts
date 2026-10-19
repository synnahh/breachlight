import { randomUUID } from 'node:crypto';
import type {
  CoverageReport,
  HistoricalComparison,
  ProviderScanOutcome,
  Scan,
  ScanDepth,
  ScanOptions,
  ScanStage,
  ScanSummary,
  Severity,
} from '../../shared/types.js';
import { isValidEmail, normaliseEmail } from '../../shared/validation.js';
import { logger } from '../logger.js';
import {
  catalogue,
  domainSecurity,
  emailProvidersForDepth,
  markError,
  markSuccess,
  pwnedPasswords,
  useCorrelation,
  useDomainSecurity,
  type EmailProvider,
  type NormalisedBreach,
} from '../providers/index.js';
import { correlate } from './correlationService.js';
import { applyEnrichment, mergeBreaches, type NormalisedFinding } from './normalise.js';
import { generateActions } from './remediationService.js';
import { assessRisk, SEVERITY_ORDER } from './riskService.js';
import {
  createAction,
  createScan,
  getEmail,
  getScan,
  lastCompletedScan,
  listFindingsForEmail,
  listFindingsForScan,
  markScanned,
  recordScanTime,
  saveDomainSecurity,
  setLastScanId,
  updateScan,
  upsertFinding,
} from './storageService.js';

const DEFAULT_OPTIONS: ScanOptions = {
  passwordCheck: true,
  crossBreachCorrelation: true,
  domainSecurity: true,
  historicalComparison: true,
};

export interface StartScanInput {
  emailIds: string[];
  depth: ScanDepth;
  options?: Partial<ScanOptions>;
}

const MIN_PROVIDER_GAP_MS = process.env.NODE_ENV === 'test' ? 0 : 900;
let lastProviderCall = 0;
async function paceProvider(): Promise<void> {
  const wait = lastProviderCall + MIN_PROVIDER_GAP_MS - Date.now();
  if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  lastProviderCall = Date.now();
}

/** Start a scan. Returns the scan id immediately; work runs in the background. */
export function startScan(input: StartScanInput): { scanId: string } | { error: string } {
  const emails = input.emailIds
    .map((id) => getEmail(id))
    .filter((e): e is NonNullable<typeof e> => !!e);
  if (emails.length === 0) return { error: 'No valid emails selected for scanning.' };
  for (const e of emails) {
    if (!isValidEmail(e.email)) return { error: `Stored address "${e.email}" is not valid.` };
  }

  const depth: ScanDepth = ['quick', 'standard', 'deep', 'maximum'].includes(input.depth)
    ? input.depth
    : 'standard';
  const options: ScanOptions = { ...DEFAULT_OPTIONS, ...(input.options ?? {}) };
  const scanId = randomUUID();

  const stages: ScanStage[] = [
    { key: 'validate', label: 'Validating email(s)', status: 'pending' },
    { key: 'providers', label: 'Querying breach providers', status: 'pending' },
    { key: 'metadata', label: 'Processing & enriching breach metadata', status: 'pending' },
    { key: 'risk', label: 'Assessing risk & confidence', status: 'pending' },
    ...(useCorrelation(depth) && options.crossBreachCorrelation
      ? [{ key: 'correlate', label: 'Correlating exposures', status: 'pending' as const }]
      : []),
    ...(useDomainSecurity(depth) && options.domainSecurity
      ? [{ key: 'domain', label: 'Checking domain security posture', status: 'pending' as const }]
      : []),
    { key: 'remediation', label: 'Generating remediation plan', status: 'pending' },
    { key: 'report', label: 'Finalising report', status: 'pending' },
  ];

  createScan({
    id: scanId,
    depth,
    options,
    emailIds: emails.map((e) => e.id),
    emailAddresses: emails.map((e) => e.email),
    stages,
  });

  // Run in the background — never block the request.
  setImmediate(() => {
    runScan(scanId, emails.map((e) => e.id), depth, options).catch((err) => {
      logger.error('Scan crashed', { scanId, message: (err as Error).message });
      const scan = getScan(scanId);
      if (scan && scan.status === 'running') {
        updateScan(scanId, {
          status: 'failed',
          finishedAt: new Date().toISOString(),
          error: 'The scan failed unexpectedly. Saved findings were not modified.',
        });
      }
    });
  });

  return { scanId };
}

async function runScan(
  scanId: string,
  emailIds: string[],
  depth: ScanDepth,
  options: ScanOptions,
): Promise<void> {
  const scan = getScan(scanId)!;
  const stages = scan.stages;
  const setStage = (key: string, status: ScanStage['status'], detail?: string) => {
    const s = stages.find((x) => x.key === key);
    if (s) {
      s.status = status;
      if (detail) s.detail = detail;
    }
    updateScan(scanId, { stages });
  };

  setStage('validate', 'ok');

  // ── Providers ──────────────────────────────────────────────────────────
  setStage('providers', 'running');
  const emailProviders = emailProvidersForDepth(depth);
  const providerOutcomes: ProviderScanOutcome[] = [];
  const attempted: string[] = [];
  const succeeded: string[] = [];

  // password provider is a "source" for coverage purposes too
  attempted.push(pwnedPasswords.id);
  if (options.passwordCheck && pwnedPasswords.isConfigured()) succeeded.push(pwnedPasswords.id);

  /** email -> raw breaches from all providers */
  const rawByEmail = new Map<string, NormalisedBreach[]>();
  for (const id of emailIds) rawByEmail.set(id, []);

  for (const provider of emailProviders) {
    attempted.push(provider.id);
    let ok = false;
    let count = 0;
    let error: string | null = null;
    for (const emailId of emailIds) {
      const email = getEmail(emailId)!;
      try {
        await paceProvider();
        const results = await provider.scanEmail(normaliseEmail(email.email));
        rawByEmail.get(emailId)!.push(...results);
        count += results.length;
        ok = true;
      } catch (err) {
        markError(provider.id, err);
        error = err instanceof Error ? err.message : String(err);
        logger.warn('Provider email lookup failed', { provider: provider.id, error });
      }
    }
    if (ok) {
      markSuccess(provider.id);
      succeeded.push(provider.id);
    }
    providerOutcomes.push({
      id: provider.id,
      label: provider.label,
      ok,
      count,
      error: ok ? null : error,
      skipped: false,
    });
  }
  setStage(
    'providers',
    providerOutcomes.some((o) => o.ok) || emailProviders.length === 0 ? 'ok' : 'failed',
    `${succeeded.length}/${attempted.length} sources responded`,
  );

  // ── Metadata / enrichment ──────────────────────────────────────────────
  setStage('metadata', 'running');
  const findingsByEmail = new Map<string, NormalisedFinding[]>();
  const catalogueReady = await catalogue.ready().catch(() => false);
  for (const [emailId, raw] of rawByEmail) {
    let merged = mergeBreaches(raw);
    if (catalogueReady && (depth === 'standard' || depth === 'deep' || depth === 'maximum')) {
      merged = await Promise.all(
        merged.map(async (f) => {
          const enr = await catalogue.enrich(f.domain || f.name).catch(() => null);
          return applyEnrichment(f, enr);
        }),
      );
    }
    findingsByEmail.set(emailId, merged);
  }
  if (catalogueReady) {
    attempted.push(catalogue.id);
    succeeded.push(catalogue.id);
    markSuccess(catalogue.id);
    providerOutcomes.push({
      id: catalogue.id,
      label: catalogue.label,
      ok: true,
      count: 0,
      error: null,
      skipped: false,
    });
  }
  setStage('metadata', 'ok');

  // ── Risk + persistence ─────────────────────────────────────────────────
  setStage('risk', 'running');
  let newCount = 0;
  for (const [emailId, findings] of findingsByEmail) {
    const passwordBreaches = findings.filter((f) => f.flags.passwordExposed).length;
    for (const nf of findings) {
      const risk = assessRisk(nf, {
        breachCountForEmail: findings.length,
        passwordBreachCountForEmail: passwordBreaches,
      });
      const { id, isNew } = upsertFinding({
        scanId,
        emailId,
        finding: nf,
        severity: risk.severity,
        severityReasons: risk.reasons,
        whyItMatters: risk.whyItMatters,
      });
      if (isNew) newCount++;
      for (const action of generateActions(nf, risk.severity, id, emailId)) {
        createAction({ findingId: id, emailId, ...action });
      }
    }
    markScanned(emailId);
  }
  setStage('risk', 'ok', `${newCount} new finding(s)`);

  const scanFindings = listFindingsForScan(scanId);

  // ── Correlation ────────────────────────────────────────────────────────
  if (useCorrelation(depth) && options.crossBreachCorrelation) {
    setStage('correlate', 'ok', correlate(scanFindings).patterns[0]);
  }

  // ── Domain security ────────────────────────────────────────────────────
  if (useDomainSecurity(depth) && options.domainSecurity && !domainSecurity.isConfigured()) {
    setStage('domain', 'skipped', 'disabled');
  } else if (useDomainSecurity(depth) && options.domainSecurity) {
    setStage('domain', 'running');
    attempted.push(domainSecurity.id);
    const domains = [...new Set(scanFindings.map((f) => f.domain).filter(Boolean))] as string[];
    let checked = 0;
    const cap = depth === 'maximum' ? 12 : 6;
    for (const d of domains.slice(0, cap)) {
      try {
        await paceProvider();
        const info = await domainSecurity.checkDomain(d);
        saveDomainSecurity(info);
        checked++;
      } catch (err) {
        markError(domainSecurity.id, err);
      }
    }
    if (checked > 0 || domains.length === 0) {
      // Nothing to check is not a failure — don't penalise coverage for it.
      if (checked > 0) markSuccess(domainSecurity.id);
      succeeded.push(domainSecurity.id);
    }
    providerOutcomes.push({
      id: domainSecurity.id,
      label: domainSecurity.label,
      ok: checked > 0,
      count: checked,
      error: null,
      skipped: domains.length === 0,
    });
    setStage('domain', checked > 0 || domains.length === 0 ? 'ok' : 'failed', `${checked} domain(s)`);
  }

  // ── Remediation + report ───────────────────────────────────────────────
  setStage('remediation', 'ok');
  setStage('report', 'running');

  const coverage = buildCoverage(attempted, succeeded, providerOutcomes);
  const summary = buildSummary(scanFindings);
  let comparison: HistoricalComparison | null = null;
  if (options.historicalComparison) comparison = buildComparison(scanId, scanFindings);

  recordScanTime();
  setLastScanId(scanId);
  updateScan(scanId, {
    status: 'complete',
    finishedAt: new Date().toISOString(),
    stages: stages.map((s) => (s.status === 'pending' || s.status === 'running' ? { ...s, status: 'ok' } : s)),
    providerOutcomes,
    coverage,
    summary,
    comparison,
  });
  logger.info('Scan complete', { scanId, findings: scanFindings.length, coverage: coverage.percent });
}

function buildCoverage(
  attempted: string[],
  succeeded: string[],
  outcomes: ProviderScanOutcome[],
): CoverageReport {
  const total = new Set(attempted).size;
  const ok = new Set(succeeded).size;
  const percent = total === 0 ? 0 : Math.round((ok / total) * 100);
  const unavailable = outcomes.filter((o) => !o.ok && !o.skipped).map((o) => o.label);
  return {
    percent,
    sourcesAvailable: ok,
    sourcesTotal: total,
    unavailable,
    note:
      percent === 100
        ? 'All configured sources responded.'
        : `${unavailable.length || 'Some'} source(s) were unavailable — results should be treated as incomplete.`,
  };
}

function buildSummary(findings: import('../../shared/types.js').BreachFinding[]): ScanSummary {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) counts[f.severity]++;
  const unresolved = findings.filter((f) => f.status !== 'secured');
  const requireAction = unresolved.filter(
    (f) => f.severity === 'critical' || f.severity === 'high' || f.passwordExposed,
  );
  const topPriorities = [...requireAction]
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])
    .slice(0, 3)
    .map((f) => f.service);
  return {
    total: findings.length,
    counts,
    requireAction: requireAction.length,
    passwordExposures: unresolved.filter((f) => f.passwordExposed).length,
    resolved: findings.filter((f) => f.status === 'secured').length,
    unresolved: unresolved.length,
    servicesIdentified: new Set(findings.map((f) => f.service)).size,
    topPriorities,
  };
}

function buildComparison(
  scanId: string,
  currentFindings: import('../../shared/types.js').BreachFinding[],
): HistoricalComparison | null {
  const prev = lastCompletedScan(scanId);
  if (!prev || !prev.summary) return null;
  const prevServices = new Set(listFindingsForScan(prev.id).map((f) => f.service));
  const curServices = new Set(currentFindings.map((f) => f.service));
  return {
    previousScanId: prev.id,
    previousDate: prev.finishedAt ?? prev.startedAt,
    previousExposures: prev.summary.total,
    currentExposures: currentFindings.length,
    exposureDelta: currentFindings.length - prev.summary.total,
    actionsCompletedSince: 0,
    noLongerReturned: [...prevServices].filter((s) => !curServices.has(s)),
    newlyAppeared: [...curServices].filter((s) => !prevServices.has(s)),
  };
}

// Legacy single-email helper retained for compatibility (used by tests).
export async function scanEmailNow(emailId: string, depth: ScanDepth = 'standard') {
  const started = startScan({ emailIds: [emailId], depth });
  if ('error' in started) return { error: started.error };
  // Wait for completion (used in tests / simple flows only).
  for (let i = 0; i < 200; i++) {
    const s = getScan(started.scanId);
    if (s && s.status !== 'running') {
      return {
        scanId: started.scanId,
        scan: s,
        findings: listFindingsForEmail(emailId),
      };
    }
    await new Promise((r) => setTimeout(r, 25));
  }
  return { error: 'Scan timed out', scanId: started.scanId };
}
