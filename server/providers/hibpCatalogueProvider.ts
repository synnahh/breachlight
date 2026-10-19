import fs from 'node:fs';
import path from 'node:path';
import { config } from '../config.js';
import { logger } from '../logger.js';
import { BUNDLED_CATALOGUE } from './catalogueData.js';
import {
  fetchJson,
  ProviderError,
  type CatalogueProvider,
  type NormalisedBreach,
} from './types.js';

// Public breach CATALOGUE (metadata only, no per-account data, no API key).
// HIBP publishes the full list of tracked breaches at /api/v3/breaches with
// no authentication. We cache it to disk and use it to enrich breach names
// returned by other providers into full findings (domain, dates, data classes,
// scale). Works offline via a small bundled snapshot until the first fetch.
const URL = 'https://haveibeenpwned.com/api/v3/breaches';
const REFRESH_MS = 7 * 24 * 60 * 60 * 1000;

interface HibpCatalogueEntry {
  Name: string;
  Title?: string;
  Domain?: string;
  BreachDate?: string;
  AddedDate?: string;
  ModifiedDate?: string;
  PwnCount?: number;
  Description?: string;
  DataClasses?: string[];
  IsStealerLog?: boolean;
  IsSpamList?: boolean;
}

export class HibpCatalogueProvider implements CatalogueProvider {
  readonly id = 'hibp-catalogue';
  readonly label = 'Public Breach Catalogue (HIBP, no key)';
  readonly kind = 'catalogue' as const;
  readonly requiresAuth = false;

  private index = new Map<string, Partial<NormalisedBreach>>();
  private byDomain = new Map<string, Partial<NormalisedBreach>>();
  private loaded = false;
  private loadingPromise: Promise<void> | null = null;

  private get cacheFile(): string {
    return path.join(path.dirname(config.databaseFile), 'breach-catalogue.json');
  }

  isConfigured(): boolean {
    return config.catalogueEnabled;
  }
  isDemoData(): boolean {
    return false;
  }

  async ready(): Promise<boolean> {
    if (!this.isConfigured()) return false;
    await this.ensureLoaded();
    return this.index.size > 0;
  }

  async enrich(nameOrDomain: string): Promise<Partial<NormalisedBreach> | null> {
    if (!this.isConfigured()) return null;
    await this.ensureLoaded();
    const key = norm(nameOrDomain);
    return (
      this.index.get(key) ??
      this.byDomain.get(key) ??
      this.byDomain.get(key.replace(/\..*$/, '')) ??
      null
    );
  }

  private async ensureLoaded(): Promise<void> {
    if (this.loaded) return;
    if (this.loadingPromise) return this.loadingPromise;
    this.loadingPromise = this.load();
    await this.loadingPromise;
    this.loaded = true;
  }

  private async load(): Promise<void> {
    // 1. bundled snapshot — always available
    this.ingest(Object.values(BUNDLED_CATALOGUE));

    // 2. disk cache
    let cached: HibpCatalogueEntry[] | null = null;
    let cacheAge = Infinity;
    try {
      const stat = fs.statSync(this.cacheFile);
      cacheAge = Date.now() - stat.mtimeMs;
      cached = JSON.parse(fs.readFileSync(this.cacheFile, 'utf8'));
      if (Array.isArray(cached)) this.ingest(cached.map(fromHibp));
    } catch {
      /* no cache yet */
    }

    // 3. refresh from network if stale (best-effort, never fatal)
    if (!config.isTest && (cacheAge > REFRESH_MS || !cached)) {
      try {
        const raw = await fetchJson(URL, {
          headers: { 'user-agent': config.userAgent, accept: 'application/json' },
          timeoutMs: 20_000,
        });
        if (Array.isArray(raw)) {
          const entries = raw as HibpCatalogueEntry[];
          this.ingest(entries.map(fromHibp));
          try {
            fs.mkdirSync(path.dirname(this.cacheFile), { recursive: true });
            fs.writeFileSync(this.cacheFile, JSON.stringify(entries));
          } catch (e) {
            logger.warn('Could not write breach catalogue cache', { error: String(e) });
          }
          logger.info('Breach catalogue refreshed', { count: entries.length });
        }
      } catch (e) {
        logger.warn('Breach catalogue refresh failed; using bundled/cached data', {
          error: e instanceof ProviderError ? e.kind : String(e),
        });
      }
    }
  }

  private ingest(entries: Array<Partial<NormalisedBreach>>): void {
    for (const e of entries) {
      if (!e.name) continue;
      this.index.set(norm(e.name), e);
      if (e.title) this.index.set(norm(e.title), e);
      if (e.domain) this.byDomain.set(norm(e.domain), e);
    }
  }
}

function fromHibp(e: HibpCatalogueEntry): Partial<NormalisedBreach> {
  return {
    name: e.Name,
    title: e.Title || e.Name,
    service: e.Title || e.Name,
    domain: e.Domain ? e.Domain.toLowerCase() : null,
    breachDate: e.BreachDate || null,
    disclosureDate: e.AddedDate || null,
    firstSeenDate: e.AddedDate || e.ModifiedDate || null,
    description: e.Description ? e.Description.replace(/<[^>]*>/g, '').trim() : null,
    dataClasses: Array.isArray(e.DataClasses) ? e.DataClasses : [],
    pwnCount: typeof e.PwnCount === 'number' ? e.PwnCount : null,
    passwordRisk: null,
  };
}

function norm(s: string): string {
  return s.trim().toLowerCase().replace(/[^a-z0-9.]/g, '');
}
