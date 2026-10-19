import { config } from '../config.js';
import { fetchWithTimeout, ProviderError, type DomainProvider } from './types.js';
import type { DomainSecurityInfo } from '../../shared/types.js';

// Passive, low-impact domain security posture check. One HTTPS request (plus at
// most one HTTP request to observe redirect behaviour). No scanning, no probing
// of paths, no private infrastructure. This is NOT a pen-testing tool.
const SECURITY_HEADERS = [
  'strict-transport-security',
  'content-security-policy',
  'x-content-type-options',
  'x-frame-options',
  'referrer-policy',
  'permissions-policy',
];

const cache = new Map<string, { at: number; data: DomainSecurityInfo }>();
const TTL = 30 * 60 * 1000;

// SSRF guard. `normaliseHost` already requires an alphabetic TLD, which rejects
// bare IPv4/IPv6/decimal literals; this blocks internal DNS names and the
// well-known cloud metadata hostnames as defence in depth.
const PRIVATE =
  /(^localhost$)|(\.local$)|(\.internal$)|(\.localdomain$)|(^metadata\.)|(metadata\.google\.internal$)|(^169\.254\.)|(^127\.)|(^10\.)|(^192\.168\.)|(^172\.(1[6-9]|2\d|3[01])\.)/i;

export class DomainSecurityProvider implements DomainProvider {
  readonly id = 'domain-security';
  readonly label = 'Domain Security Check (passive)';
  readonly kind = 'domain' as const;
  readonly requiresAuth = false;

  isConfigured(): boolean {
    return config.domainSecurityEnabled;
  }
  isDemoData(): boolean {
    return false;
  }

  async checkDomain(domain: string): Promise<DomainSecurityInfo> {
    if (!this.isConfigured()) throw new ProviderError('not_configured', 'Domain checks disabled');
    const host = normaliseHost(domain);
    if (!host || PRIVATE.test(host)) {
      return blank(host || domain, ['Domain skipped (not a public hostname).']);
    }

    const hit = cache.get(host);
    if (hit && Date.now() - hit.at < TTL) return hit.data;

    const notes: string[] = [];
    let reachable = false;
    let https = false;
    let hsts = false;
    let redirectsToHttps = false;
    const headers: Record<string, boolean> = {};

    try {
      const res = await fetchWithTimeout(`https://${host}/`, {
        method: 'GET',
        redirect: 'follow',
        headers: { 'user-agent': config.userAgent },
        timeoutMs: 8000,
      });
      reachable = true;
      https = res.url.startsWith('https://');
      for (const h of SECURITY_HEADERS) headers[h] = res.headers.has(h);
      hsts = res.headers.has('strict-transport-security');
    } catch {
      notes.push('HTTPS request did not succeed (site may block automated requests).');
    }

    if (reachable) {
      try {
        const httpRes = await fetchWithTimeout(`http://${host}/`, {
          method: 'GET',
          redirect: 'manual',
          headers: { 'user-agent': config.userAgent },
          timeoutMs: 6000,
        });
        const loc = httpRes.headers.get('location') || '';
        redirectsToHttps =
          (httpRes.status >= 300 && httpRes.status < 400 && loc.startsWith('https://')) ||
          httpRes.type === 'opaqueredirect';
      } catch {
        /* http not reachable — fine */
      }
    }

    if (https && !hsts) notes.push('HTTPS works but HSTS is not enabled.');
    if (reachable && !redirectsToHttps) notes.push('HTTP does not clearly redirect to HTTPS.');
    for (const h of SECURITY_HEADERS) {
      if (h !== 'strict-transport-security' && headers[h] === false) {
        notes.push(`Missing security header: ${h}`);
      }
    }

    const info: DomainSecurityInfo = {
      domain: host,
      reachable,
      https,
      hsts,
      redirectsToHttps,
      headers,
      grade: grade({ reachable, https, hsts, redirectsToHttps, headers }),
      notes: notes.length ? notes : ['No obvious transport-security issues observed.'],
      checkedAt: new Date().toISOString(),
    };
    cache.set(host, { at: Date.now(), data: info });
    return info;
  }
}

function grade(x: {
  reachable: boolean;
  https: boolean;
  hsts: boolean;
  redirectsToHttps: boolean;
  headers: Record<string, boolean>;
}): DomainSecurityInfo['grade'] {
  if (!x.reachable) return 'unknown';
  let points = 0;
  if (x.https) points += 2;
  if (x.hsts) points += 1;
  if (x.redirectsToHttps) points += 1;
  points += SECURITY_HEADERS.filter((h) => x.headers[h]).length; // 0-6
  if (points >= 8) return 'A';
  if (points >= 6) return 'B';
  if (points >= 4) return 'C';
  if (points >= 2) return 'D';
  return 'F';
}

function normaliseHost(d: string): string | null {
  const x = d.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
  return /^[a-z0-9.-]+\.[a-z]{2,}$/.test(x) ? x : null;
}

function blank(domain: string, notes: string[]): DomainSecurityInfo {
  return {
    domain,
    reachable: false,
    https: false,
    hsts: false,
    redirectsToHttps: false,
    headers: {},
    grade: 'unknown',
    notes,
    checkedAt: new Date().toISOString(),
  };
}
