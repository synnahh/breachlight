import { config } from '../config.js';
import {
  fetchJson,
  ProviderError,
  type EmailProvider,
  type NormalisedBreach,
} from './types.js';

// XposedOrNot (https://xposedornot.com) — a public, no-API-key breach
// intelligence service. We send ONLY the email address being scanned, over
// HTTPS. Two endpoints are used:
//   /v1/check-email/{email}        → list of breach names (fast)
//   /v1/breach-analytics?email=…   → detailed per-breach metadata + risk
const BASE = 'https://api.xposedornot.com/v1';

interface XonBreachDetail {
  breach?: string;
  details?: string;
  domain?: string;
  industry?: string;
  password_risk?: string;
  xposed_data?: string; // semicolon-separated
  xposed_date?: string; // "2013"
  xposed_records?: number;
  added?: string; // ISO datetime
}

/** Short-lived cache keyed by email, so a Deep scan does not re-hit the API. */
const cache = new Map<string, { at: number; data: NormalisedBreach[] }>();
const TTL = 5 * 60 * 1000;

export class XposedOrNotProvider implements EmailProvider {
  readonly id = 'xposedornot';
  readonly label = 'XposedOrNot (public breach intelligence)';
  readonly kind = 'email' as const;
  readonly requiresAuth = false;

  isConfigured(): boolean {
    return config.xposedOrNotEnabled;
  }
  isDemoData(): boolean {
    return false;
  }

  async scanEmail(email: string): Promise<NormalisedBreach[]> {
    if (!this.isConfigured()) throw new ProviderError('not_configured', 'XposedOrNot is disabled');

    const key = email.toLowerCase();
    const hit = cache.get(key);
    if (hit && Date.now() - hit.at < TTL) return hit.data;

    const analytics = await this.fetchAnalytics(email);
    let breaches: NormalisedBreach[];

    if (analytics.length > 0) {
      breaches = analytics;
    } else {
      // Fall back to the lighter endpoint — some accounts only resolve there.
      const names = await this.fetchNames(email);
      breaches = names.map((name) => this.fromName(name));
    }

    cache.set(key, { at: Date.now(), data: breaches });
    return breaches;
  }

  private async fetchAnalytics(email: string): Promise<NormalisedBreach[]> {
    let raw: any;
    try {
      raw = await fetchJson(`${BASE}/breach-analytics?email=${encodeURIComponent(email)}`, {
        headers: { 'user-agent': config.userAgent, accept: 'application/json' },
        timeoutMs: 15_000,
      });
    } catch (err) {
      if (err instanceof ProviderError && err.kind === 'malformed') return [];
      throw err;
    }
    const details: XonBreachDetail[] = raw?.ExposedBreaches?.breaches_details ?? [];
    if (!Array.isArray(details)) return [];
    return details
      .filter((d) => d && typeof d.breach === 'string')
      .map((d) => this.fromDetail(d));
  }

  private async fetchNames(email: string): Promise<string[]> {
    const raw: any = await fetchJson(`${BASE}/check-email/${encodeURIComponent(email)}`, {
      headers: { 'user-agent': config.userAgent, accept: 'application/json' },
      timeoutMs: 12_000,
    });
    if (raw?.Error) return []; // "Not found" etc.
    const outer = raw?.breaches;
    const list = Array.isArray(outer?.[0]) ? outer[0] : Array.isArray(outer) ? outer : [];
    return list.filter((x: unknown): x is string => typeof x === 'string');
  }

  private fromDetail(d: XonBreachDetail): NormalisedBreach {
    const name = (d.breach ?? 'Unknown').trim();
    const year = d.xposed_date && /^\d{4}$/.test(d.xposed_date) ? d.xposed_date : null;
    const dataClasses = (d.xposed_data ?? '')
      .split(';')
      .map((s) => s.trim())
      .filter(Boolean);
    return {
      name,
      title: name,
      service: name,
      domain: cleanDomain(d.domain),
      breachDate: year ? `${year}-01-01` : null,
      disclosureDate: d.added ?? null,
      firstSeenDate: d.added ?? null,
      description: stripHtml(d.details),
      dataClasses,
      passwordRisk: normalisePasswordRisk(d.password_risk),
      pwnCount: typeof d.xposed_records === 'number' ? d.xposed_records : null,
      industry: d.industry || null,
      confidence: 'high',
      confidenceReason: 'Direct match from XposedOrNot breach intelligence.',
      associationType: 'confirmed',
      source: this.label,
      providerId: this.id,
      isDemoData: false,
    };
  }

  private fromName(name: string): NormalisedBreach {
    return {
      name: name.trim(),
      title: name.trim(),
      service: name.trim(),
      domain: null,
      breachDate: null,
      disclosureDate: null,
      firstSeenDate: null,
      description: null,
      dataClasses: [],
      passwordRisk: null,
      pwnCount: null,
      industry: null,
      confidence: 'high',
      confidenceReason: 'Listed for this email by XposedOrNot (name only — metadata pending enrichment).',
      associationType: 'confirmed',
      source: this.label,
      providerId: this.id,
      isDemoData: false,
    };
  }
}

function normalisePasswordRisk(v: string | undefined): string | null {
  if (!v) return null;
  const s = v.toLowerCase();
  if (s.includes('plain')) return 'plaintext';
  if (s.includes('easy') || s.includes('hard') || s.includes('hash') || s.includes('crack'))
    return 'hashed';
  if (s === 'unknown') return 'unknown';
  return s;
}

function cleanDomain(d: string | undefined): string | null {
  if (!d) return null;
  const x = d.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
  return /^[a-z0-9.-]+\.[a-z]{2,}$/.test(x) ? x : null;
}

function stripHtml(s: string | undefined): string | null {
  if (!s) return null;
  return s.replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim() || null;
}
