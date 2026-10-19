// Shared domain types used by both the backend and the frontend.
// V2: the model is centred on Scans, Findings (actionable account records),
// Security Actions, a deterministic Security Score, and provider Coverage.

export type Severity = 'critical' | 'high' | 'medium' | 'low';

/** Lifecycle of a single finding. */
export type FindingStatus = 'open' | 'in_progress' | 'secured';

/** V2 action lifecycle (replaces V1 open/in_progress/done). */
export type ActionStatus = 'not_started' | 'in_progress' | 'completed' | 'not_applicable';
export type ActionPriority = 'urgent' | 'recommended';

export type Confidence = 'high' | 'medium' | 'low';

/** Whether a legit source *confirmed* a breach or only *suggests* an association. */
export type AssociationType = 'confirmed' | 'possible';

export type ScanDepth = 'quick' | 'standard' | 'deep' | 'maximum';

export interface ScanOptions {
  passwordCheck: boolean;
  crossBreachCorrelation: boolean;
  domainSecurity: boolean;
  historicalComparison: boolean;
}

// ─────────────────────────────────────────────────────────────────────────

export interface EmailRecord {
  id: string;
  email: string;
  label: string | null; // "Primary", "Work", …
  createdAt: string;
  lastScannedAt: string | null;
}

export interface AccountLink {
  label: string;
  url: string;
  derived: boolean; // true = derived from domain, not an officially published URL
}

export interface BreachFinding {
  id: string;
  scanId: string | null;
  emailId: string;
  email: string;

  // Identity of the exposed account / service
  service: string; // human service name ("Adobe")
  breachName: string; // machine name
  title: string;
  domain: string | null;

  // Dates
  breachDate: string | null;
  disclosureDate: string | null;
  firstSeenDate: string | null;

  description: string | null;

  // Exposure
  dataClasses: string[];
  passwordExposed: boolean;
  emailExposed: boolean;
  usernameExposed: boolean;
  ipExposed: boolean;
  locationExposed: boolean;
  phoneExposed: boolean;
  securityQuestionsExposed: boolean;
  financialExposed: boolean;
  governmentIdExposed: boolean;
  sensitivePersonalExposed: boolean;
  passwordRisk: string | null; // provider hint: plaintext / hashed / unknown

  // Assessment
  severity: Severity;
  severityReasons: string[];
  whyItMatters: string;
  confidence: Confidence;
  confidenceReason: string;
  associationType: AssociationType;

  // Provenance
  source: string; // provider label(s)
  providerIds: string[];
  isDemoData: boolean;
  pwnCount: number | null;
  industry: string | null;

  // Lifecycle
  status: FindingStatus;
  discoveredAt: string;
  lastSeenAt: string;

  // Guidance
  remediation: string[];
  recommendations: RecommendationItem[];
  links: AccountLink[];
  wizardSteps: WizardStep[];
}

export interface RecommendationItem {
  code: string;
  label: string;
  detail: string;
}

export interface WizardStep {
  key: string;
  title: string;
  detail: string;
  link?: AccountLink;
}

export interface SecurityAction {
  id: string;
  findingId: string | null;
  emailId: string | null;
  title: string;
  description: string;
  priority: ActionPriority;
  status: ActionStatus;
  createdAt: string;
  completedAt: string | null;
}

// ── Providers ────────────────────────────────────────────────────────────

export type ProviderKind = 'email' | 'password' | 'catalogue' | 'domain';

export interface ProviderRuntimeStatus {
  id: string;
  label: string;
  kind: ProviderKind;
  /** Human summary: "Available", "Optional", "Rate limited", "Needs API key" … */
  state: 'available' | 'optional' | 'rate_limited' | 'error' | 'disabled';
  requiresAuth: boolean;
  authenticated: boolean;
  configured: boolean;
  isDemoData: boolean;
  lastSuccessAt: string | null;
  lastErrorAt: string | null;
  lastError: string | null;
  rateLimitedUntil: string | null;
  note: string;
}

// ── Scans ────────────────────────────────────────────────────────────────

export interface ScanStage {
  key: string;
  label: string;
  status: 'pending' | 'running' | 'ok' | 'failed' | 'skipped';
  detail?: string;
}

export interface ProviderScanOutcome {
  id: string;
  label: string;
  ok: boolean;
  count: number;
  error: string | null;
  skipped: boolean;
}

export interface ScanSummary {
  total: number;
  counts: Record<Severity, number>;
  requireAction: number;
  passwordExposures: number;
  resolved: number;
  unresolved: number;
  servicesIdentified: number;
  topPriorities: string[];
}

export interface HistoricalComparison {
  previousScanId: string;
  previousDate: string;
  previousExposures: number;
  currentExposures: number;
  exposureDelta: number;
  actionsCompletedSince: number;
  noLongerReturned: string[]; // service names present before, absent now (NOT "resolved")
  newlyAppeared: string[];
}

export interface Scan {
  id: string;
  status: 'running' | 'complete' | 'failed';
  depth: ScanDepth;
  options: ScanOptions;
  emailIds: string[];
  emailAddresses: string[];
  startedAt: string;
  finishedAt: string | null;
  stages: ScanStage[];
  providerOutcomes: ProviderScanOutcome[];
  coverage: CoverageReport;
  summary: ScanSummary | null;
  comparison: HistoricalComparison | null;
  error: string | null;
}

export interface CoverageReport {
  percent: number; // 0-100
  sourcesAvailable: number;
  sourcesTotal: number;
  unavailable: string[];
  note: string;
}

export interface ScanHistoryEntry {
  id: string;
  date: string;
  depth: ScanDepth;
  exposures: number;
  unresolved: number;
  coverage: number;
  emailAddresses: string[];
}

// ── Security score ───────────────────────────────────────────────────────

export interface ScoreFactor {
  label: string;
  delta: number;
  detail: string;
}

export interface SecurityScore {
  score: number; // 0-100
  band: 'critical' | 'poor' | 'fair' | 'good' | 'strong';
  factors: ScoreFactor[];
  topRisks: string[];
}

// ── Correlation ──────────────────────────────────────────────────────────

export interface CorrelationReport {
  breachCount: number;
  passwordBreachCount: number;
  passwordBreachesAfterFirst: number;
  earliestBreach: string | null;
  latestBreach: string | null;
  patterns: string[]; // cautious natural-language observations
  perEmail: { email: string; services: string[] }[];
  timeline: TimelineEntry[];
}

export interface TimelineEntry {
  year: number;
  service: string;
  severity: Severity;
  passwordInvolved: boolean;
}

// ── Domain security ──────────────────────────────────────────────────────

export interface DomainSecurityInfo {
  domain: string;
  reachable: boolean;
  https: boolean;
  hsts: boolean;
  redirectsToHttps: boolean;
  headers: Record<string, boolean>; // header name -> present
  grade: 'A' | 'B' | 'C' | 'D' | 'F' | 'unknown';
  notes: string[];
  checkedAt: string;
}

// ── Combo finder ─────────────────────────────────────────────────────────

/**
 * A specific service where PASSWORD data was exposed — i.e. somewhere the user
 * should go and change their password. This is what turns "your password is
 * compromised" into "go here, and here, and change it".
 */
export interface PasswordExposureSite {
  service: string;
  /** Which monitored address this exposure belongs to. */
  email: string;
  domain: string | null;
  breachDate: string | null;
  /** Provider hint: plaintext / hashed / unknown */
  passwordRisk: string | null;
  dataClasses: string[];
  links: AccountLink[];
  /** Set when this site matches a stored finding, so it can be actioned inline. */
  findingId: string | null;
  status: FindingStatus | null;
  severity: Severity | null;
}

export interface EmailExposureSummary {
  email: string;
  exposed: boolean;
  breachCount: number;
  services: string[];
  /** Subset of the breaches above where password data was involved. */
  passwordBreaches: PasswordExposureSite[];
  confidence: Confidence;
  source: string;
}

export interface ComboResult {
  email: string;
  emailExposed: boolean;
  emailBreachCount: number;
  passwordExposed: boolean;
  passwordOccurrences: number | null;
  combinationRisk: Severity;
  combinationRiskReason: string;
  recommendedActions: string[];
  notes: string[];
  checkedAt: string;
}

/** What the /api/combo endpoint actually returns. */
export interface ComboResponse extends ComboResult {
  emailSource: string;
  passwordError: string | null;
  services: string[];
  /** Where to actually go and change the password. */
  passwordBreaches: PasswordExposureSite[];
}

// ── Password check (unchanged from V1) ───────────────────────────────────

export interface PasswordCheckResult {
  compromised: boolean;
  exposureBand: 'none' | 'low' | 'medium' | 'high' | 'very_high';
  occurrences: number | null;
  checkedAt: string;
  method: string;
  note: string;
  recommendedActions: string[];
}

// ── Dashboard ────────────────────────────────────────────────────────────

export interface DashboardSummary {
  score: SecurityScore;
  emailsMonitored: number;
  findingsTotal: number;
  counts: Record<Severity, number>;
  servicesExposed: number;
  passwordExposures: number;
  actionsTotal: number;
  actionsCompleted: number;
  actionProgressPercent: number;
  urgentFindings: {
    id: string;
    service: string;
    severity: Severity;
    headline: string;
  }[];
  exposedAccounts: {
    id: string;
    service: string;
    exposure: string;
    date: string | null;
    severity: Severity;
    status: FindingStatus;
  }[];
  lastScanAt: string | null;
  lastScanId: string | null;
  baselineReady: boolean;
  optionalProvidersConfigured: number;
  notifications: string[];
}

export interface PrivacyReport {
  emailsStoredLocally: number;
  scansStoredLocally: number;
  findingsStoredLocally: number;
  passwordsStored: false;
  passwordPlaintextLogged: false;
  externalProvidersUsed: { id: string; label: string; sends: string }[];
  databaseFile: string;
}
