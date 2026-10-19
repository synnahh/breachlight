import 'dotenv/config';
import path from 'node:path';

function bool(v: string | undefined, def: boolean): boolean {
  if (v === undefined || v === '') return def;
  return ['1', 'true', 'yes', 'on'].includes(v.toLowerCase());
}

export const config = {
  port: Number(process.env.PORT || 5174),
  webPort: Number(process.env.WEB_PORT || 5173),
  databaseFile: path.resolve(
    process.cwd(),
    process.env.DATABASE_FILE || './data/scanner.db',
  ),
  isProd: process.env.NODE_ENV === 'production',
  isTest: process.env.NODE_ENV === 'test',

  // ── Providers ──────────────────────────────────────────────────────────
  // Baseline (no key, on by default):
  //   xposedornot  – public per-email breach intelligence
  //   hibp-catalogue – public catalogue of all breaches (metadata enrichment)
  //   pwned-passwords – k-anonymity password exposure
  //   domain-security – passive HTTPS / header inspection
  xposedOrNotEnabled: bool(process.env.XPOSEDORNOT_ENABLED, true),
  catalogueEnabled: bool(process.env.BREACH_CATALOGUE_ENABLED, true),
  passwordCheckEnabled: bool(process.env.PASSWORD_CHECK_ENABLED, true),
  domainSecurityEnabled: bool(process.env.DOMAIN_SECURITY_ENABLED, true),

  // Optional authenticated provider:
  hibpApiKey: (process.env.HIBP_API_KEY || '').trim(),

  // Demo/testing provider — OFF by default, never mixed with real results.
  demoProviderEnabled: bool(process.env.DEMO_PROVIDER_ENABLED, false),

  // Network etiquette
  userAgent: 'breachlight (local personal security tool)',
  providerConcurrency: Number(process.env.PROVIDER_CONCURRENCY || 4),
} as const;

export function hibpConfigured(): boolean {
  return config.hibpApiKey.length > 0;
}
