import { config } from '../config.js';
import { fetchWithTimeout, ProviderError } from './types.js';

// Pwned Passwords k-anonymity range API. No API key. Accepts ONLY a 5-hex-char
// SHA-1 prefix — the plaintext password and full hash never reach this code.
const RANGE_URL = 'https://api.pwnedpasswords.com/range/';

const cache = new Map<string, { body: string; expires: number }>();
const CACHE_TTL_MS = 10 * 60 * 1000;

export class PwnedPasswordsProvider {
  readonly id = 'pwned-passwords';
  readonly label = 'Password Exposure Check (Pwned Passwords, k-anonymity)';
  readonly kind = 'password' as const;
  readonly requiresAuth = false;

  isConfigured(): boolean {
    return config.passwordCheckEnabled;
  }
  isDemoData(): boolean {
    return false;
  }

  async fetchRange(prefix: string): Promise<string> {
    if (!/^[0-9A-Fa-f]{5}$/.test(prefix)) {
      throw new ProviderError('malformed', 'Invalid hash prefix');
    }
    const key = prefix.toUpperCase();
    const cached = cache.get(key);
    if (cached && cached.expires > Date.now()) return cached.body;

    const res = await fetchWithTimeout(RANGE_URL + key, {
      headers: { 'user-agent': config.userAgent, 'Add-Padding': 'true' },
      timeoutMs: 10_000,
    });
    if (res.status === 429) {
      const retry = Number(res.headers.get('retry-after') || '2');
      throw new ProviderError('rate_limited', 'Pwned Passwords rate limit hit', retry * 1000);
    }
    if (!res.ok) throw new ProviderError('unavailable', `Pwned Passwords error ${res.status}`);

    const body = await res.text();
    cache.set(key, { body, expires: Date.now() + CACHE_TTL_MS });
    return body;
  }
}
