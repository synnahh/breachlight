import { Router } from 'express';
import { z } from 'zod';
import { config, hibpConfigured } from './config.js';
import { logger } from './logger.js';
import { isValidEmail } from '../shared/validation.js';
import { isValidHashPrefix, parseRangeResponse } from '../shared/passwordCheck.js';
import { assessCombo } from '../shared/combo.js';
import {
  allProviderStatuses,
  baselineReady,
  optionalProvidersConfigured,
} from './providers/index.js';
import { ProviderError } from './providers/types.js';
import { startScan, scanEmailNow } from './services/scanService.js';
import { getDashboard } from './services/dashboardService.js';
import { correlate } from './services/correlationService.js';
import {
  emailExposure,
  noteComboPasswordFound,
  storedPasswordExposures,
} from './services/comboService.js';
import { fetchHashRange } from './services/passwordService.js';
import { buildCsvReport, buildJsonReport } from './services/exportService.js';
import {
  addEmail,
  createAction,
  getFinding,
  getScan,
  listActions,
  listDomainSecurity,
  listEmails,
  listFindings,
  listFindingsForScan,
  listScans,
  privacyReport,
  removeEmail,
  scanHistory,
  setActionStatus,
  setFindingStatus,
  setManyFindingStatus,
  updateEmailLabel,
  wipeAllData,
} from './services/storageService.js';
import { allSettings, setSetting } from './db.js';

export const api = Router();

const ok = (res: any, data: unknown, status = 200) => res.status(status).json({ ok: true, data });
const fail = (res: any, status: number, error: string) => res.status(status).json({ ok: false, error });

// ── Status / data sources ────────────────────────────────────────────────
api.get('/status', (_req, res) =>
  ok(res, {
    baselineReady: baselineReady(),
    optionalProvidersConfigured: optionalProvidersConfigured(),
    passwordCheckEnabled: config.passwordCheckEnabled,
    hibpConfigured: hibpConfigured(),
    demoProviderEnabled: config.demoProviderEnabled,
  }),
);
api.get('/data-sources', (_req, res) => ok(res, allProviderStatuses()));
api.get('/dashboard', (_req, res) => ok(res, getDashboard()));
api.get('/privacy', (_req, res) => ok(res, privacyReport()));
api.get('/settings', (_req, res) =>
  ok(res, {
    values: allSettings(),
    config: {
      passwordCheckEnabled: config.passwordCheckEnabled,
      demoProviderEnabled: config.demoProviderEnabled,
      hibpConfigured: hibpConfigured(),
      databaseFile: config.databaseFile,
    },
  }),
);
api.put('/settings/:key', (req, res) => {
  const parsed = z.object({ value: z.string().max(2000) }).safeParse(req.body);
  if (!parsed.success) return fail(res, 400, 'A value is required.');
  const allowed = ['default_scan_depth', 'default_options', 'notifications_enabled'];
  if (!allowed.includes(req.params.key)) return fail(res, 400, 'Unknown setting.');
  setSetting(req.params.key, parsed.data.value);
  ok(res, { saved: true });
});

// ── Emails ───────────────────────────────────────────────────────────────
api.get('/emails', (_req, res) => ok(res, listEmails()));
api.post('/emails', (req, res) => {
  const parsed = z
    .object({ email: z.string(), label: z.string().max(40).optional() })
    .safeParse(req.body);
  if (!parsed.success) return fail(res, 400, 'Email is required.');
  if (!isValidEmail(parsed.data.email)) return fail(res, 400, 'That is not a valid email address.');
  ok(res, addEmail(parsed.data.email, parsed.data.label ?? null), 201);
});
api.patch('/emails/:id', (req, res) => {
  const parsed = z.object({ label: z.string().max(40).nullable() }).safeParse(req.body);
  if (!parsed.success) return fail(res, 400, 'Invalid label.');
  const updated = updateEmailLabel(req.params.id, parsed.data.label);
  if (!updated) return fail(res, 404, 'Email not found.');
  ok(res, updated);
});
api.delete('/emails/:id', (req, res) => {
  if (!removeEmail(req.params.id)) return fail(res, 404, 'Email not found.');
  ok(res, { removed: true });
});

// ── Scans ────────────────────────────────────────────────────────────────
const scanBody = z.object({
  emailIds: z.array(z.string()).min(1).max(50),
  depth: z.enum(['quick', 'standard', 'deep', 'maximum']).default('standard'),
  options: z
    .object({
      passwordCheck: z.boolean().optional(),
      crossBreachCorrelation: z.boolean().optional(),
      domainSecurity: z.boolean().optional(),
      historicalComparison: z.boolean().optional(),
    })
    .optional(),
});

api.post('/scans', (req, res) => {
  const parsed = scanBody.safeParse(req.body);
  if (!parsed.success) return fail(res, 400, 'emailIds and a valid depth are required.');
  const started = startScan(parsed.data);
  if ('error' in started) return fail(res, 400, started.error);
  ok(res, { scanId: started.scanId }, 202);
});

api.get('/scans', (_req, res) => ok(res, scanHistory(50)));
api.get('/scans/all', (_req, res) => ok(res, listScans(50)));
api.get('/scans/:id', (req, res) => {
  const scan = getScan(req.params.id);
  if (!scan) return fail(res, 404, 'Scan not found.');
  ok(res, { scan, findings: scan.status === 'complete' ? listFindingsForScan(scan.id) : [] });
});
api.get('/scans/:id/export', (req, res) => {
  const scan = getScan(req.params.id);
  const findings = scan ? listFindingsForScan(scan.id) : listFindings();
  const bundle = {
    generatedAt: new Date().toISOString(),
    scan,
    findings,
    actions: listActions(),
  };
  const format = String(req.query.format || 'json').toLowerCase();
  if (format === 'csv') {
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="security-report.csv"');
    return res.send(buildCsvReport(bundle));
  }
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', 'attachment; filename="security-report.json"');
  res.send(buildJsonReport(bundle));
});

// ── Findings ─────────────────────────────────────────────────────────────
api.get('/findings', (_req, res) => ok(res, listFindings()));
api.get('/findings/correlation', (_req, res) => ok(res, correlate(listFindings())));
api.get('/findings/:id', (req, res) => {
  const f = getFinding(req.params.id);
  if (!f) return fail(res, 404, 'Finding not found.');
  ok(res, f);
});
api.patch('/findings/:id/status', (req, res) => {
  const parsed = z.object({ status: z.enum(['open', 'in_progress', 'secured']) }).safeParse(req.body);
  if (!parsed.success) return fail(res, 400, 'Invalid status.');
  const updated = setFindingStatus(req.params.id, parsed.data.status);
  if (!updated) return fail(res, 404, 'Finding not found.');
  ok(res, updated);
});
api.post('/findings/bulk-status', (req, res) => {
  const parsed = z
    .object({ ids: z.array(z.string()).min(1).max(200), status: z.enum(['open', 'in_progress', 'secured']) })
    .safeParse(req.body);
  if (!parsed.success) return fail(res, 400, 'ids and status are required.');
  ok(res, { updated: setManyFindingStatus(parsed.data.ids, parsed.data.status) });
});

// ── Actions ──────────────────────────────────────────────────────────────
api.get('/actions', (_req, res) => ok(res, listActions()));
api.post('/actions', (req, res) => {
  const parsed = z
    .object({ title: z.string().min(1).max(200), description: z.string().max(1000).optional() })
    .safeParse(req.body);
  if (!parsed.success) return fail(res, 400, 'A task title is required.');
  createAction({
    findingId: null,
    emailId: null,
    title: parsed.data.title,
    description: parsed.data.description ?? '',
    priority: 'recommended',
    dedupeKey: `custom:${parsed.data.title.toLowerCase()}:${Date.now()}`,
  });
  ok(res, { created: true }, 201);
});
api.patch('/actions/:id/status', (req, res) => {
  const parsed = z
    .object({ status: z.enum(['not_started', 'in_progress', 'completed', 'not_applicable']) })
    .safeParse(req.body);
  if (!parsed.success) return fail(res, 400, 'Invalid status.');
  const updated = setActionStatus(req.params.id, parsed.data.status);
  if (!updated) return fail(res, 404, 'Action not found.');
  ok(res, updated);
});

// ── Domain security ──────────────────────────────────────────────────────
api.get('/domain-security', (_req, res) => ok(res, listDomainSecurity()));

// ── Password range proxy (k-anonymity) ───────────────────────────────────
api.get('/password/range/:prefix', async (req, res) => {
  if (!config.passwordCheckEnabled) return fail(res, 403, 'Password checking is disabled.');
  if (!isValidHashPrefix(req.params.prefix)) return fail(res, 400, 'Invalid hash prefix.');
  try {
    res.type('text/plain').send(await fetchHashRange(req.params.prefix));
  } catch (e) {
    const kind = e instanceof ProviderError ? e.kind : 'unavailable';
    const status = kind === 'rate_limited' ? 429 : kind === 'timeout' ? 504 : 502;
    fail(res, status, `Password service error (${kind}).`);
  }
});

// ── Combo finder ─────────────────────────────────────────────────────────
// The browser hashes the password and sends ONLY the 5-char prefix + suffix
// hash-tail for local comparison here (never the plaintext, never the full hash
// in a way the server logs). Server does the email lookup and combines.
api.post('/combo', async (req, res) => {
  const parsed = z
    .object({
      email: z.string(),
      prefix: z.string(),
      suffix: z.string().regex(/^[0-9A-Fa-f]{35}$/),
    })
    .safeParse(req.body);
  if (!parsed.success) return fail(res, 400, 'email, prefix and suffix are required.');
  if (!isValidEmail(parsed.data.email)) return fail(res, 400, 'Invalid email address.');
  if (!isValidHashPrefix(parsed.data.prefix)) return fail(res, 400, 'Invalid hash prefix.');

  let passwordOccurrences = 0;
  let passwordError: string | null = null;
  if (config.passwordCheckEnabled) {
    try {
      const body = await fetchHashRange(parsed.data.prefix);
      passwordOccurrences = parseRangeResponse(body, parsed.data.suffix);
    } catch (e) {
      passwordError = e instanceof ProviderError ? e.kind : 'unavailable';
    }
  }

  let email;
  try {
    email = await emailExposure(parsed.data.email);
  } catch {
    email = {
      email: parsed.data.email,
      exposed: false,
      breachCount: 0,
      services: [],
      passwordBreaches: [],
      confidence: 'low' as const,
      source: 'unavailable',
    };
  }

  const result = assessCombo({
    email: parsed.data.email,
    emailExposed: email.exposed,
    emailBreachCount: email.breachCount,
    emailConfidence: email.confidence,
    passwordOccurrences,
  });
  noteComboPasswordFound(passwordOccurrences > 0);

  ok(res, {
    ...result,
    emailSource: email.source,
    passwordError,
    services: email.services,
    passwordBreaches: email.passwordBreaches,
  });
});

// Every stored finding where password data was exposed — "where do I go to
// change my password", surfaced independently of a combo check.
api.get('/password-exposures', (_req, res) => ok(res, storedPasswordExposures()));

// ── Danger zone ──────────────────────────────────────────────────────────
api.post('/wipe', (_req, res) => {
  wipeAllData();
  logger.info('All local data wiped by user request');
  ok(res, { wiped: true });
});

// ── Legacy single-email scan (kept for simple callers / tests) ────────────
api.post('/emails/:id/scan', async (req, res) => {
  const depthRaw = typeof req.query.depth === 'string' ? req.query.depth : 'standard';
  const depth = (['quick', 'standard', 'deep', 'maximum'] as const).includes(depthRaw as any)
    ? (depthRaw as 'quick' | 'standard' | 'deep' | 'maximum')
    : 'standard';
  const result = await scanEmailNow(req.params.id, depth);
  if ('error' in result && result.error && !('scan' in result)) {
    return fail(res, 400, result.error);
  }
  ok(res, result);
});
