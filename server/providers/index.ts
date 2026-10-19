import type { ProviderRuntimeStatus, ScanDepth } from '../../shared/types.js';
import { DomainSecurityProvider } from './domainSecurityProvider.js';
import { HibpCatalogueProvider } from './hibpCatalogueProvider.js';
import { HibpProvider } from './hibpProvider.js';
import { MockProvider } from './mockProvider.js';
import { PwnedPasswordsProvider } from './pwnedPasswordsProvider.js';
import { XposedOrNotProvider } from './xposedOrNotProvider.js';
import { buildRuntimeStatus, type EmailProvider } from './types.js';

// Singletons
export const xposedOrNot = new XposedOrNotProvider();
export const hibp = new HibpProvider();
export const demo = new MockProvider();
export const catalogue = new HibpCatalogueProvider();
export const domainSecurity = new DomainSecurityProvider();
export const pwnedPasswords = new PwnedPasswordsProvider();

const ALL_EMAIL: EmailProvider[] = [xposedOrNot, hibp, demo];

/** Email providers that are enabled/configured right now. */
export function activeEmailProviders(): EmailProvider[] {
  return ALL_EMAIL.filter((p) => p.isConfigured());
}

/**
 * Which email providers a given scan depth uses. Depth changes *how much* work
 * is done, not whether results are real.
 *   quick    – fastest single source
 *   standard – all no-auth email sources + catalogue enrichment
 *   deep     – + authenticated providers + domain security + correlation
 *   maximum  – everything, all monitored emails, full correlation
 */
export function emailProvidersForDepth(depth: ScanDepth): EmailProvider[] {
  const active = activeEmailProviders();
  if (depth === 'quick') {
    // Prefer the public per-email source; fall back to whatever is active.
    const primary = active.find((p) => p.id === 'xposedornot') ?? active[0];
    return primary ? [primary] : [];
  }
  return active;
}

export function useDomainSecurity(depth: ScanDepth): boolean {
  return depth === 'deep' || depth === 'maximum';
}
export function useCorrelation(depth: ScanDepth): boolean {
  return depth !== 'quick';
}

export function allProviderStatuses(): ProviderRuntimeStatus[] {
  return [
    buildRuntimeStatus(xposedOrNot, xposedOrNot.isConfigured(), false),
    buildRuntimeStatus(pwnedPasswords, pwnedPasswords.isConfigured(), false),
    buildRuntimeStatus(catalogue, catalogue.isConfigured(), false),
    buildRuntimeStatus(domainSecurity, domainSecurity.isConfigured(), false),
    buildRuntimeStatus(hibp, hibp.isConfigured(), false),
    buildRuntimeStatus(demo, demo.isConfigured(), true),
  ];
}

export function baselineReady(): boolean {
  // "Baseline" = at least one no-auth email source + password check available.
  const emailBaseline = activeEmailProviders().some((p) => !p.requiresAuth && !p.isDemoData());
  return emailBaseline && pwnedPasswords.isConfigured();
}

export function optionalProvidersConfigured(): number {
  return [hibp].filter((p) => p.isConfigured()).length;
}

export * from './types.js';
