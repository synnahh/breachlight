import { config, hibpConfigured } from '../config.js';
import {
  fetchWithTimeout,
  ProviderError,
  type EmailProvider,
  type NormalisedBreach,
} from './types.js';

const BASE = 'https://haveibeenpwned.com/api/v3';

interface HibpBreach {
  Name: string;
  Title?: string;
  Domain?: string;
  BreachDate?: string;
  AddedDate?: string;
  ModifiedDate?: string;
  PwnCount?: number;
  Description?: string;
  DataClasses?: string[];
}

/**
 * Have I Been Pwned "breachedaccount" — OPTIONAL authenticated provider.
 * Sends ONLY the scanned email address, over HTTPS, to the official API.
 */
export class HibpProvider implements EmailProvider {
  readonly id = 'hibp';
  readonly label = 'Have I Been Pwned (authenticated)';
  readonly kind = 'email' as const;
  readonly requiresAuth = true;

  isConfigured(): boolean {
    return hibpConfigured();
  }
  isDemoData(): boolean {
    return false;
  }

  async scanEmail(email: string): Promise<NormalisedBreach[]> {
    if (!this.isConfigured()) {
      throw new ProviderError('not_configured', 'HIBP_API_KEY is not set');
    }
    const url = `${BASE}/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`;
    const res = await fetchWithTimeout(url, {
      headers: {
        'hibp-api-key': config.hibpApiKey,
        'user-agent': config.userAgent,
        accept: 'application/json',
      },
      timeoutMs: 15_000,
    });

    if (res.status === 404) return [];
    if (res.status === 401) throw new ProviderError('unauthorized', 'Invalid HIBP API key');
    if (res.status === 429) {
      const retry = Number(res.headers.get('retry-after') || '3');
      throw new ProviderError('rate_limited', 'HIBP rate limit hit', retry * 1000);
    }
    if (!res.ok) throw new ProviderError('unavailable', `HIBP error ${res.status}`);

    let raw: unknown;
    try {
      raw = await res.json();
    } catch {
      throw new ProviderError('malformed', 'HIBP returned a non-JSON response');
    }
    if (!Array.isArray(raw)) throw new ProviderError('malformed', 'HIBP response was not an array');

    return (raw as HibpBreach[])
      .filter((b) => b && typeof b.Name === 'string')
      .map((b) => ({
        name: b.Name,
        title: b.Title || b.Name,
        service: b.Title || b.Name,
        domain: b.Domain ? b.Domain.toLowerCase() : null,
        breachDate: b.BreachDate || null,
        disclosureDate: b.AddedDate || null,
        firstSeenDate: b.AddedDate || b.ModifiedDate || null,
        description: b.Description ? b.Description.replace(/<[^>]*>/g, '').trim() : null,
        dataClasses: Array.isArray(b.DataClasses) ? b.DataClasses : [],
        passwordRisk: null,
        pwnCount: typeof b.PwnCount === 'number' ? b.PwnCount : null,
        industry: null,
        confidence: 'high' as const,
        confidenceReason: 'Direct match from Have I Been Pwned (authenticated).',
        associationType: 'confirmed' as const,
        source: this.label,
        providerId: this.id,
        isDemoData: false,
      }));
  }
}
