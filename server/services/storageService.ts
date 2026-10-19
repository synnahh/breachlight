import { randomUUID } from 'node:crypto';
import { config } from '../config.js';
import { db, getMeta, setMeta } from '../db.js';
import type {
  BreachFinding,
  DomainSecurityInfo,
  EmailRecord,
  FindingStatus,
  PrivacyReport,
  Scan,
  ScanHistoryEntry,
  SecurityAction,
  Severity,
  ActionStatus,
} from '../../shared/types.js';
import { baselineReady, optionalProvidersConfigured } from '../providers/index.js';
import {
  buildAccountLinks,
  buildRecommendations,
  buildRemediation,
  buildWizardSteps,
} from './remediationService.js';
import { deriveExposureFlags, type NormalisedFinding } from './normalise.js';
import { SEVERITY_ORDER } from './riskService.js';

const now = () => new Date().toISOString();
const jbool = (n: number) => !!n;
function parseArray(json: string): string[] {
  try {
    const v = JSON.parse(json);
    return Array.isArray(v) ? v.filter((x) => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

// ── Emails ───────────────────────────────────────────────────────────────

interface EmailRow {
  id: string;
  email: string;
  label: string | null;
  created_at: string;
  last_scanned_at: string | null;
}
const mapEmail = (r: EmailRow): EmailRecord => ({
  id: r.id,
  email: r.email,
  label: r.label,
  createdAt: r.created_at,
  lastScannedAt: r.last_scanned_at,
});

export function listEmails(): EmailRecord[] {
  return db
    .prepare('SELECT * FROM emails ORDER BY created_at ASC')
    .all<EmailRow>()
    .map(mapEmail);
}
export function getEmail(id: string): EmailRecord | null {
  const r = db.prepare('SELECT * FROM emails WHERE id = ?').get<EmailRow>(id);
  return r ? mapEmail(r) : null;
}
export function getEmailByAddress(email: string): EmailRecord | null {
  const r = db.prepare('SELECT * FROM emails WHERE email = ?').get<EmailRow>(email.toLowerCase());
  return r ? mapEmail(r) : null;
}
export function addEmail(email: string, label?: string | null): EmailRecord {
  const normalised = email.trim().toLowerCase();
  const existing = getEmailByAddress(normalised);
  if (existing) {
    if (label !== undefined && label !== existing.label) {
      db.prepare('UPDATE emails SET label = ? WHERE id = ?').run(label ?? null, existing.id);
      return getEmail(existing.id)!;
    }
    return existing;
  }
  const id = randomUUID();
  db.prepare('INSERT INTO emails (id, email, label, created_at) VALUES (?, ?, ?, ?)').run(
    id,
    normalised,
    label ?? null,
    now(),
  );
  return getEmail(id)!;
}
export function updateEmailLabel(id: string, label: string | null): EmailRecord | null {
  const info = db.prepare('UPDATE emails SET label = ? WHERE id = ?').run(label, id);
  return info.changes ? getEmail(id) : null;
}
export function removeEmail(id: string): boolean {
  return db.prepare('DELETE FROM emails WHERE id = ?').run(id).changes > 0;
}
export function markScanned(id: string): void {
  db.prepare('UPDATE emails SET last_scanned_at = ? WHERE id = ?').run(now(), id);
}

// ── Findings ─────────────────────────────────────────────────────────────

interface FindingRow {
  id: string;
  scan_id: string | null;
  email_id: string;
  service: string;
  breach_name: string;
  title: string;
  domain: string | null;
  breach_date: string | null;
  disclosure_date: string | null;
  first_seen_date: string | null;
  description: string | null;
  data_classes: string;
  password_exposed: number;
  email_exposed: number;
  username_exposed: number;
  ip_exposed: number;
  location_exposed: number;
  phone_exposed: number;
  secq_exposed: number;
  financial_exposed: number;
  govid_exposed: number;
  sensitive_exposed: number;
  password_risk: string | null;
  severity: Severity;
  severity_reasons: string;
  why_matters: string;
  confidence: BreachFinding['confidence'];
  confidence_reason: string;
  association_type: BreachFinding['associationType'];
  source: string;
  provider_ids: string;
  is_demo_data: number;
  pwn_count: number | null;
  industry: string | null;
  status: FindingStatus;
  discovered_at: string;
  last_seen_at: string;
  email?: string;
}

function toNormalisedFinding(r: FindingRow): NormalisedFinding {
  const dataClasses = parseArray(r.data_classes);
  return {
    name: r.breach_name,
    title: r.title,
    service: r.service,
    domain: r.domain,
    breachDate: r.breach_date,
    disclosureDate: r.disclosure_date,
    firstSeenDate: r.first_seen_date,
    description: r.description,
    dataClasses,
    passwordRisk: r.password_risk,
    pwnCount: r.pwn_count,
    industry: r.industry,
    confidence: r.confidence,
    confidenceReason: r.confidence_reason,
    associationType: r.association_type,
    source: r.source,
    providerId: parseArray(r.provider_ids)[0] ?? '',
    providerIds: parseArray(r.provider_ids),
    isDemoData: jbool(r.is_demo_data),
    flags: deriveExposureFlags(dataClasses, r.password_risk),
  };
}

function mapFinding(r: FindingRow): BreachFinding {
  const nf = toNormalisedFinding(r);
  return {
    id: r.id,
    scanId: r.scan_id,
    emailId: r.email_id,
    email: r.email ?? '',
    service: r.service,
    breachName: r.breach_name,
    title: r.title,
    domain: r.domain,
    breachDate: r.breach_date,
    disclosureDate: r.disclosure_date,
    firstSeenDate: r.first_seen_date,
    description: r.description,
    dataClasses: nf.dataClasses,
    passwordExposed: jbool(r.password_exposed),
    emailExposed: jbool(r.email_exposed),
    usernameExposed: jbool(r.username_exposed),
    ipExposed: jbool(r.ip_exposed),
    locationExposed: jbool(r.location_exposed),
    phoneExposed: jbool(r.phone_exposed),
    securityQuestionsExposed: jbool(r.secq_exposed),
    financialExposed: jbool(r.financial_exposed),
    governmentIdExposed: jbool(r.govid_exposed),
    sensitivePersonalExposed: jbool(r.sensitive_exposed),
    passwordRisk: r.password_risk,
    severity: r.severity,
    severityReasons: parseArray(r.severity_reasons),
    whyItMatters: r.why_matters,
    confidence: r.confidence,
    confidenceReason: r.confidence_reason,
    associationType: r.association_type,
    source: r.source,
    providerIds: parseArray(r.provider_ids),
    isDemoData: jbool(r.is_demo_data),
    pwnCount: r.pwn_count,
    industry: r.industry,
    status: r.status,
    discoveredAt: r.discovered_at,
    lastSeenAt: r.last_seen_at,
    remediation: buildRemediation(nf),
    recommendations: buildRecommendations(nf),
    links: buildAccountLinks(nf),
    wizardSteps: buildWizardSteps(nf),
  };
}

const FINDINGS_SELECT = `SELECT f.*, e.email AS email FROM findings f JOIN emails e ON e.id = f.email_id`;

function sortFindings(a: BreachFinding, b: BreachFinding): number {
  const s = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
  if (s !== 0) return s;
  return (b.breachDate ?? '').localeCompare(a.breachDate ?? '');
}

export function listFindings(): BreachFinding[] {
  return db.prepare(FINDINGS_SELECT).all<FindingRow>().map(mapFinding).sort(sortFindings);
}
export function listFindingsForEmail(emailId: string): BreachFinding[] {
  return db
    .prepare(`${FINDINGS_SELECT} WHERE f.email_id = ?`)
    .all<FindingRow>(emailId)
    .map(mapFinding)
    .sort(sortFindings);
}
export function listFindingsForScan(scanId: string): BreachFinding[] {
  return db
    .prepare(`${FINDINGS_SELECT} WHERE f.scan_id = ?`)
    .all<FindingRow>(scanId)
    .map(mapFinding)
    .sort(sortFindings);
}
export function getFinding(id: string): BreachFinding | null {
  const r = db.prepare(`${FINDINGS_SELECT} WHERE f.id = ?`).get<FindingRow>(id);
  return r ? mapFinding(r) : null;
}

export interface UpsertFindingInput {
  scanId: string | null;
  emailId: string;
  finding: NormalisedFinding;
  severity: Severity;
  severityReasons: string[];
  whyItMatters: string;
}

export function upsertFinding(input: UpsertFindingInput): { id: string; isNew: boolean } {
  const nf = input.finding;
  const existing = db
    .prepare('SELECT id FROM findings WHERE email_id = ? AND breach_name = ?')
    .get<{ id: string }>(input.emailId, nf.name);

  const cols = {
    scanId: input.scanId,
    emailId: input.emailId,
    service: nf.service || nf.title || nf.name,
    breachName: nf.name,
    title: nf.title || nf.name,
    domain: nf.domain,
    breachDate: nf.breachDate,
    disclosureDate: nf.disclosureDate,
    firstSeenDate: nf.firstSeenDate,
    description: nf.description,
    dataClasses: JSON.stringify(nf.dataClasses),
    passwordExposed: nf.flags.passwordExposed ? 1 : 0,
    emailExposed: nf.flags.emailExposed ? 1 : 0,
    usernameExposed: nf.flags.usernameExposed ? 1 : 0,
    ipExposed: nf.flags.ipExposed ? 1 : 0,
    locationExposed: nf.flags.locationExposed ? 1 : 0,
    phoneExposed: nf.flags.phoneExposed ? 1 : 0,
    secqExposed: nf.flags.securityQuestionsExposed ? 1 : 0,
    financialExposed: nf.flags.financialExposed ? 1 : 0,
    govidExposed: nf.flags.governmentIdExposed ? 1 : 0,
    sensitiveExposed: nf.flags.sensitivePersonalExposed ? 1 : 0,
    passwordRisk: nf.passwordRisk,
    severity: input.severity,
    severityReasons: JSON.stringify(input.severityReasons),
    whyMatters: input.whyItMatters,
    confidence: nf.confidence,
    confidenceReason: nf.confidenceReason,
    associationType: nf.associationType,
    source: nf.source,
    providerIds: JSON.stringify(nf.providerIds ?? []),
    isDemoData: nf.isDemoData ? 1 : 0,
    pwnCount: nf.pwnCount,
    industry: nf.industry,
  };

  if (existing) {
    db.prepare(
      `UPDATE findings SET
        scan_id=@scanId, service=@service, title=@title, domain=@domain, breach_date=@breachDate,
        disclosure_date=@disclosureDate, first_seen_date=@firstSeenDate, description=@description,
        data_classes=@dataClasses, password_exposed=@passwordExposed, email_exposed=@emailExposed,
        username_exposed=@usernameExposed, ip_exposed=@ipExposed, location_exposed=@locationExposed,
        phone_exposed=@phoneExposed, secq_exposed=@secqExposed, financial_exposed=@financialExposed,
        govid_exposed=@govidExposed, sensitive_exposed=@sensitiveExposed, password_risk=@passwordRisk,
        severity=@severity, severity_reasons=@severityReasons, why_matters=@whyMatters,
        confidence=@confidence, confidence_reason=@confidenceReason, association_type=@associationType,
        source=@source, provider_ids=@providerIds, is_demo_data=@isDemoData, pwn_count=@pwnCount,
        industry=@industry, last_seen_at=@lastSeen
       WHERE id=@id`,
    ).run({ ...cols, id: existing.id, lastSeen: now() });
    return { id: existing.id, isNew: false };
  }

  const id = randomUUID();
  db.prepare(
    `INSERT INTO findings (
      id, scan_id, email_id, service, breach_name, title, domain, breach_date, disclosure_date,
      first_seen_date, description, data_classes, password_exposed, email_exposed, username_exposed,
      ip_exposed, location_exposed, phone_exposed, secq_exposed, financial_exposed, govid_exposed,
      sensitive_exposed, password_risk, severity, severity_reasons, why_matters, confidence,
      confidence_reason, association_type, source, provider_ids, is_demo_data, pwn_count, industry,
      status, discovered_at, last_seen_at
    ) VALUES (
      @id, @scanId, @emailId, @service, @breachName, @title, @domain, @breachDate, @disclosureDate,
      @firstSeenDate, @description, @dataClasses, @passwordExposed, @emailExposed, @usernameExposed,
      @ipExposed, @locationExposed, @phoneExposed, @secqExposed, @financialExposed, @govidExposed,
      @sensitiveExposed, @passwordRisk, @severity, @severityReasons, @whyMatters, @confidence,
      @confidenceReason, @associationType, @source, @providerIds, @isDemoData, @pwnCount, @industry,
      'open', @ts, @ts
    )`,
  ).run({ ...cols, id, ts: now() });
  return { id, isNew: true };
}

export function setFindingStatus(id: string, status: FindingStatus): BreachFinding | null {
  const info = db.prepare('UPDATE findings SET status = ? WHERE id = ?').run(status, id);
  if (!info.changes) return null;
  if (status === 'secured') {
    db.prepare(
      "UPDATE actions SET status='completed', completed_at=? WHERE finding_id=? AND status NOT IN ('completed','not_applicable')",
    ).run(now(), id);
  }
  return getFinding(id);
}

export function setManyFindingStatus(ids: string[], status: FindingStatus): number {
  let n = 0;
  for (const id of ids) if (setFindingStatus(id, status)) n++;
  return n;
}

// ── Actions ──────────────────────────────────────────────────────────────

interface ActionRow {
  id: string;
  finding_id: string | null;
  email_id: string | null;
  title: string;
  description: string;
  priority: 'urgent' | 'recommended';
  status: ActionStatus;
  created_at: string;
  completed_at: string | null;
}
const mapAction = (r: ActionRow): SecurityAction => ({
  id: r.id,
  findingId: r.finding_id,
  emailId: r.email_id,
  title: r.title,
  description: r.description,
  priority: r.priority,
  status: r.status,
  createdAt: r.created_at,
  completedAt: r.completed_at,
});

export function listActions(): SecurityAction[] {
  return db
    .prepare(
      `SELECT * FROM actions ORDER BY
        CASE priority WHEN 'urgent' THEN 0 ELSE 1 END,
        CASE status WHEN 'not_started' THEN 0 WHEN 'in_progress' THEN 1 WHEN 'completed' THEN 2 ELSE 3 END,
        created_at ASC`,
    )
    .all<ActionRow>()
    .map(mapAction);
}
export function createAction(a: {
  findingId: string | null;
  emailId: string | null;
  title: string;
  description: string;
  priority: 'urgent' | 'recommended';
  dedupeKey: string;
}): void {
  db.prepare(
    `INSERT INTO actions (id, finding_id, email_id, title, description, priority, status, created_at, dedupe_key)
     VALUES (?, ?, ?, ?, ?, ?, 'not_started', ?, ?)
     ON CONFLICT(dedupe_key) DO UPDATE SET
       title=excluded.title, description=excluded.description, priority=excluded.priority`,
  ).run(randomUUID(), a.findingId, a.emailId, a.title, a.description, a.priority, now(), a.dedupeKey);
}
export function setActionStatus(id: string, status: ActionStatus): SecurityAction | null {
  const completedAt = status === 'completed' ? now() : null;
  const info = db
    .prepare('UPDATE actions SET status = ?, completed_at = ? WHERE id = ?')
    .run(status, completedAt, id);
  if (!info.changes) return null;
  return mapAction(db.prepare('SELECT * FROM actions WHERE id = ?').get<ActionRow>(id)!);
}

// ── Scans ────────────────────────────────────────────────────────────────

interface ScanRow {
  id: string;
  status: Scan['status'];
  depth: Scan['depth'];
  options_json: string;
  email_ids_json: string;
  email_addrs_json: string;
  started_at: string;
  finished_at: string | null;
  stages_json: string;
  provider_json: string;
  coverage_json: string;
  summary_json: string | null;
  comparison_json: string | null;
  error: string | null;
}
function mapScan(r: ScanRow): Scan {
  const j = <T,>(s: string | null, d: T): T => {
    if (!s) return d;
    try {
      return JSON.parse(s) as T;
    } catch {
      return d;
    }
  };
  return {
    id: r.id,
    status: r.status,
    depth: r.depth,
    options: j(r.options_json, {} as Scan['options']),
    emailIds: j(r.email_ids_json, [] as string[]),
    emailAddresses: j(r.email_addrs_json, [] as string[]),
    startedAt: r.started_at,
    finishedAt: r.finished_at,
    stages: j(r.stages_json, [] as Scan['stages']),
    providerOutcomes: j(r.provider_json, [] as Scan['providerOutcomes']),
    coverage: j(r.coverage_json, {} as Scan['coverage']),
    summary: j(r.summary_json, null as Scan['summary']),
    comparison: j(r.comparison_json, null as Scan['comparison']),
    error: r.error,
  };
}

export function createScan(s: Pick<Scan, 'id' | 'depth' | 'options' | 'emailIds' | 'emailAddresses' | 'stages'>): void {
  db.prepare(
    `INSERT INTO scans (id, status, depth, options_json, email_ids_json, email_addrs_json, started_at, stages_json)
     VALUES (?, 'running', ?, ?, ?, ?, ?, ?)`,
  ).run(
    s.id,
    s.depth,
    JSON.stringify(s.options),
    JSON.stringify(s.emailIds),
    JSON.stringify(s.emailAddresses),
    now(),
    JSON.stringify(s.stages),
  );
}
export function updateScan(id: string, patch: Partial<Scan>): void {
  const cur = getScan(id);
  if (!cur) return;
  const merged = { ...cur, ...patch };
  db.prepare(
    `UPDATE scans SET status=@status, finished_at=@finishedAt, stages_json=@stages,
       provider_json=@providers, coverage_json=@coverage, summary_json=@summary,
       comparison_json=@comparison, error=@error WHERE id=@id`,
  ).run({
    id,
    status: merged.status,
    finishedAt: merged.finishedAt,
    stages: JSON.stringify(merged.stages),
    providers: JSON.stringify(merged.providerOutcomes),
    coverage: JSON.stringify(merged.coverage),
    summary: merged.summary ? JSON.stringify(merged.summary) : null,
    comparison: merged.comparison ? JSON.stringify(merged.comparison) : null,
    error: merged.error,
  });
}
export function getScan(id: string): Scan | null {
  const r = db.prepare('SELECT * FROM scans WHERE id = ?').get<ScanRow>(id);
  return r ? mapScan(r) : null;
}
export function listScans(limit = 30): Scan[] {
  return db
    .prepare('SELECT * FROM scans ORDER BY started_at DESC LIMIT ?')
    .all<ScanRow>(limit)
    .map(mapScan);
}
export function scanHistory(limit = 30): ScanHistoryEntry[] {
  return listScans(limit)
    .filter((s) => s.status === 'complete')
    .map((s) => ({
      id: s.id,
      date: s.finishedAt ?? s.startedAt,
      depth: s.depth,
      exposures: s.summary?.total ?? 0,
      unresolved: s.summary?.unresolved ?? 0,
      coverage: s.coverage?.percent ?? 0,
      emailAddresses: s.emailAddresses,
    }));
}
export function lastCompletedScan(beforeId?: string): Scan | null {
  const scans = listScans(50).filter((s) => s.status === 'complete');
  return (beforeId ? scans.filter((s) => s.id !== beforeId) : scans)[0] ?? null;
}

// ── Domain security cache ────────────────────────────────────────────────

export function saveDomainSecurity(info: DomainSecurityInfo): void {
  db.prepare(
    `INSERT INTO domain_security (domain, info_json, checked_at) VALUES (?, ?, ?)
     ON CONFLICT(domain) DO UPDATE SET info_json=excluded.info_json, checked_at=excluded.checked_at`,
  ).run(info.domain, JSON.stringify(info), info.checkedAt);
}
export function getDomainSecurity(domain: string): DomainSecurityInfo | null {
  const r = db
    .prepare('SELECT info_json FROM domain_security WHERE domain = ?')
    .get<{ info_json: string }>(domain);
  if (!r) return null;
  try {
    return JSON.parse(r.info_json) as DomainSecurityInfo;
  } catch {
    return null;
  }
}
export function listDomainSecurity(): DomainSecurityInfo[] {
  return db
    .prepare('SELECT info_json FROM domain_security ORDER BY checked_at DESC')
    .all<{ info_json: string }>()
    .flatMap((r) => {
      try {
        return [JSON.parse(r.info_json) as DomainSecurityInfo];
      } catch {
        return [];
      }
    });
}

// ── Meta / misc ──────────────────────────────────────────────────────────

export function recordScanTime(): void {
  setMeta('last_scan_at', now());
}
export function lastScanAt(): string | null {
  return getMeta('last_scan_at');
}
export function lastScanId(): string | null {
  return getMeta('last_scan_id');
}
export function setLastScanId(id: string): void {
  setMeta('last_scan_id', id);
}

export function privacyReport(): PrivacyReport {
  const count = (t: string) =>
    db.prepare(`SELECT COUNT(*) c FROM ${t}`).get<{ c: number }>()!.c;
  const providers: PrivacyReport['externalProvidersUsed'] = [
    { id: 'xposedornot', label: 'XposedOrNot', sends: 'the email address being scanned' },
    { id: 'hibp-catalogue', label: 'Public Breach Catalogue', sends: 'nothing account-specific (downloads a public list)' },
    { id: 'pwned-passwords', label: 'Pwned Passwords', sends: 'only a 5-character SHA-1 prefix of a password' },
    { id: 'domain-security', label: 'Domain Security Check', sends: 'a plain HTTPS request to breached services’ domains' },
  ];
  if (config.hibpApiKey) {
    providers.push({ id: 'hibp', label: 'Have I Been Pwned (authenticated)', sends: 'the email address being scanned' });
  }
  return {
    emailsStoredLocally: count('emails'),
    scansStoredLocally: count('scans'),
    findingsStoredLocally: count('findings'),
    passwordsStored: false,
    passwordPlaintextLogged: false,
    externalProvidersUsed: providers,
    databaseFile: config.databaseFile,
  };
}

export function wipeAllData(): void {
  db.exec(
    'DELETE FROM actions; DELETE FROM findings; DELETE FROM scans; DELETE FROM emails; DELETE FROM domain_security; DELETE FROM meta;',
  );
}

export { baselineReady, optionalProvidersConfigured };
