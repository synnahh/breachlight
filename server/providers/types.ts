// Provider abstraction. The rest of the application does not care which
// provider produced a result — it only consumes NormalisedBreach / the typed
// domain-security and email-exposure shapes.

import type {
  Confidence,
  DomainSecurityInfo,
  ProviderKind,
  ProviderRuntimeStatus,
} from '../../shared/types.js';

export interface NormalisedBreach {
  /** Stable machine name, unique per breach (e.g. "Adobe"). */
  name: string;
  title: string;
  service: string;
  domain: string | null;
  breachDate: string | null; // YYYY-MM-DD
  disclosureDate: string | null;
  firstSeenDate: string | null;
  description: string | null;
  dataClasses: string[];
  /** Provider hint about password treatment: 'plaintext' | 'hashed' | 'unknown' | null */
  passwordRisk: string | null;
  pwnCount: number | null;
  industry: string | null;
  /** How sure the provider is that THIS email is really in THIS breach. */
  confidence: Confidence;
  confidenceReason: string;
  associationType: 'confirmed' | 'possible';
  source: string; // provider label
  providerId: string;
  isDemoData: boolean;
}

export interface EmailProvider {
  readonly id: string;
  readonly label: string;
  readonly kind: 'email';
  readonly requiresAuth: boolean;
  isConfigured(): boolean;
  isDemoData(): boolean;
  scanEmail(email: string): Promise<NormalisedBreach[]>;
}

export interface DomainProvider {
  readonly id: string;
  readonly label: string;
  readonly kind: 'domain';
  readonly requiresAuth: boolean;
  isConfigured(): boolean;
  isDemoData(): boolean;
  checkDomain(domain: string): Promise<DomainSecurityInfo>;
}

export interface CatalogueProvider {
  readonly id: string;
  readonly label: string;
  readonly kind: 'catalogue';
  readonly requiresAuth: boolean;
  isConfigured(): boolean;
  isDemoData(): boolean;
  /** Look up canonical metadata for a breach by (fuzzy) name/domain. */
  enrich(nameOrDomain: string): Promise<Partial<NormalisedBreach> | null>;
  ready(): Promise<boolean>;
}

export type AnyProvider = EmailProvider | DomainProvider | CatalogueProvider;

// ── Runtime status tracking ──────────────────────────────────────────────

interface MutableStatus {
  lastSuccessAt: string | null;
  lastErrorAt: string | null;
  lastError: string | null;
  rateLimitedUntil: number | null;
}

const runtime = new Map<string, MutableStatus>();

function slot(id: string): MutableStatus {
  let s = runtime.get(id);
  if (!s) {
    s = { lastSuccessAt: null, lastErrorAt: null, lastError: null, rateLimitedUntil: null };
    runtime.set(id, s);
  }
  return s;
}

export function markSuccess(id: string): void {
  const s = slot(id);
  s.lastSuccessAt = new Date().toISOString();
  s.rateLimitedUntil = null;
}

export function markError(id: string, err: unknown): void {
  const s = slot(id);
  s.lastErrorAt = new Date().toISOString();
  s.lastError = err instanceof Error ? err.message : String(err);
  if (err instanceof ProviderError && err.kind === 'rate_limited') {
    s.rateLimitedUntil = Date.now() + (err.retryAfterMs ?? 60_000);
  }
}

export function isRateLimited(id: string): boolean {
  const until = runtime.get(id)?.rateLimitedUntil ?? null;
  return until != null && until > Date.now();
}

export function buildRuntimeStatus(
  p: { id: string; label: string; kind: ProviderKind; requiresAuth: boolean },
  configured: boolean,
  isDemoData: boolean,
): ProviderRuntimeStatus {
  const s = slot(p.id);
  const rateLimited = isRateLimited(p.id);
  let state: ProviderRuntimeStatus['state'] = 'available';
  if (!configured) state = p.requiresAuth ? 'optional' : 'disabled';
  else if (rateLimited) state = 'rate_limited';
  else if (s.lastError && !s.lastSuccessAt) state = 'error';

  return {
    id: p.id,
    label: p.label,
    kind: p.kind,
    state,
    requiresAuth: p.requiresAuth,
    authenticated: p.requiresAuth && configured,
    configured,
    isDemoData,
    lastSuccessAt: s.lastSuccessAt,
    lastErrorAt: s.lastErrorAt,
    lastError: s.lastError,
    rateLimitedUntil: s.rateLimitedUntil ? new Date(s.rateLimitedUntil).toISOString() : null,
    note: buildNote(p, configured, isDemoData, rateLimited),
  };
}

function buildNote(
  p: { requiresAuth: boolean; kind: ProviderKind },
  configured: boolean,
  isDemoData: boolean,
  rateLimited: boolean,
): string {
  if (isDemoData) return 'Synthetic DEMO DATA — for testing the interface only.';
  if (!configured && p.requiresAuth) return 'Optional — add an API key to enable.';
  if (!configured) return 'Disabled in settings.';
  if (rateLimited) return 'Temporarily rate limited by the source. Results may be incomplete.';
  if (!p.requiresAuth) return 'Public source — no API key required.';
  return 'Configured.';
}

// ── Errors ───────────────────────────────────────────────────────────────

export type ProviderErrorKind =
  | 'unauthorized'
  | 'rate_limited'
  | 'unavailable'
  | 'timeout'
  | 'malformed'
  | 'not_configured';

export class ProviderError extends Error {
  constructor(
    public kind: ProviderErrorKind,
    message: string,
    public retryAfterMs?: number,
  ) {
    super(message);
    this.name = 'ProviderError';
  }
}

export async function fetchJson(
  url: string,
  init: RequestInit & { timeoutMs?: number } = {},
): Promise<unknown> {
  const res = await fetchWithTimeout(url, init);
  const text = await res.text();
  try {
    return text ? JSON.parse(text) : null;
  } catch {
    throw new ProviderError('malformed', `Non-JSON response from ${hostOf(url)}`);
  }
}

export async function fetchWithTimeout(
  url: string,
  init: RequestInit & { timeoutMs?: number } = {},
): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), init.timeoutMs ?? 15_000);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } catch (err) {
    if ((err as Error).name === 'AbortError') {
      throw new ProviderError('timeout', `Request to ${hostOf(url)} timed out`);
    }
    throw new ProviderError('unavailable', `Could not reach ${hostOf(url)}`);
  } finally {
    clearTimeout(timeout);
  }
}

export function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}
