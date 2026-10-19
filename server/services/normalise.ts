import type { AssociationType, Confidence } from '../../shared/types.js';
import type { NormalisedBreach } from '../providers/types.js';

export interface ExposureFlags {
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
}

const MATCHERS: Array<[keyof ExposureFlags, RegExp]> = [
  ['passwordExposed', /passwords?|password hashes|credentials|auth tokens?/i],
  ['emailExposed', /email addresses?/i],
  ['usernameExposed', /usernames?|user ?names/i],
  ['ipExposed', /ip addresses?/i],
  ['locationExposed', /geographic locations?|physical addresses?|geolocation/i],
  ['phoneExposed', /phone numbers?|mobile/i],
  ['securityQuestionsExposed', /security questions? and answers?|password hints?/i],
  ['financialExposed', /bank account|credit cards?|payment (info|histories)|financial/i],
  ['governmentIdExposed', /government issued ids?|social security|passport|driver'?s licen[cs]es?|national ids?|tax/i],
  ['sensitivePersonalExposed', /health|medical|biometric|sexual orientation|political|religious|ethnic/i],
];

export function deriveExposureFlags(dataClasses: string[], passwordRisk?: string | null): ExposureFlags {
  const flags: ExposureFlags = {
    passwordExposed: false,
    emailExposed: false,
    usernameExposed: false,
    ipExposed: false,
    locationExposed: false,
    phoneExposed: false,
    securityQuestionsExposed: false,
    financialExposed: false,
    governmentIdExposed: false,
    sensitivePersonalExposed: false,
  };
  for (const cls of dataClasses) {
    for (const [key, rx] of MATCHERS) if (rx.test(cls)) flags[key] = true;
  }
  if (passwordRisk && passwordRisk !== 'unknown') flags.passwordExposed = true;
  return flags;
}

export interface NormalisedFinding extends NormalisedBreach {
  flags: ExposureFlags;
  providerIds: string[];
}

const CONF_RANK: Record<Confidence, number> = { high: 3, medium: 2, low: 1 };

export function dedupeStrings(items: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const item of items) {
    const key = item.trim().toLowerCase();
    if (!key || seen.has(key)) continue;
    seen.add(key);
    out.push(item.trim());
  }
  return out;
}

/**
 * Merge breach records for one email — possibly from multiple providers and/or
 * catalogue enrichment — into one finding per breach. Confidence is the highest
 * any contributing source claimed.
 */
export function mergeBreaches(records: NormalisedBreach[]): NormalisedFinding[] {
  const byKey = new Map<string, NormalisedFinding>();

  for (const r of records) {
    const key = norm(r.name || r.domain || r.title);
    if (!key) continue;
    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, {
        ...r,
        dataClasses: dedupeStrings(r.dataClasses),
        providerIds: [r.providerId].filter(Boolean),
        flags: deriveExposureFlags(r.dataClasses, r.passwordRisk),
      });
      continue;
    }
    // Merge into existing
    existing.dataClasses = dedupeStrings([...existing.dataClasses, ...r.dataClasses]);
    existing.domain = existing.domain ?? r.domain;
    existing.breachDate = existing.breachDate ?? r.breachDate;
    existing.disclosureDate = existing.disclosureDate ?? r.disclosureDate;
    existing.firstSeenDate = earliest(existing.firstSeenDate, r.firstSeenDate);
    existing.description = existing.description ?? r.description;
    existing.pwnCount = existing.pwnCount ?? r.pwnCount;
    existing.industry = existing.industry ?? r.industry;
    existing.passwordRisk = strongerPasswordRisk(existing.passwordRisk, r.passwordRisk);
    existing.title = existing.title || r.title;
    existing.service = existing.service || r.service;
    if (!existing.providerIds.includes(r.providerId) && r.providerId) {
      existing.providerIds.push(r.providerId);
      existing.source = `${existing.source}, ${r.source}`;
    }
    if (CONF_RANK[r.confidence] > CONF_RANK[existing.confidence]) {
      existing.confidence = r.confidence;
      existing.confidenceReason = r.confidenceReason;
    }
    if (r.associationType === 'confirmed') existing.associationType = 'confirmed';
    existing.flags = deriveExposureFlags(existing.dataClasses, existing.passwordRisk);
  }

  return [...byKey.values()];
}

/** Apply catalogue enrichment to a merged finding (fills gaps only). */
export function applyEnrichment(
  finding: NormalisedFinding,
  enrichment: Partial<NormalisedBreach> | null,
): NormalisedFinding {
  if (!enrichment) return finding;
  const merged: NormalisedFinding = {
    ...finding,
    domain: finding.domain ?? enrichment.domain ?? null,
    title: finding.title || enrichment.title || finding.name,
    service: finding.service || enrichment.service || finding.name,
    breachDate: finding.breachDate ?? enrichment.breachDate ?? null,
    disclosureDate: finding.disclosureDate ?? enrichment.disclosureDate ?? null,
    firstSeenDate: finding.firstSeenDate ?? enrichment.firstSeenDate ?? null,
    description: finding.description ?? enrichment.description ?? null,
    pwnCount: finding.pwnCount ?? enrichment.pwnCount ?? null,
    dataClasses: dedupeStrings([...finding.dataClasses, ...(enrichment.dataClasses ?? [])]),
  };
  merged.flags = deriveExposureFlags(merged.dataClasses, merged.passwordRisk);
  if (enrichment.name && finding.confidence === 'low') {
    merged.confidence = 'medium';
    merged.confidenceReason = 'Name matched an entry in the public breach catalogue.';
  }
  return merged;
}

export function associationLabel(t: AssociationType): string {
  return t === 'confirmed' ? 'Confirmed breach exposure' : 'Possible service association';
}

function norm(s: string): string {
  return (s || '').trim().toLowerCase().replace(/[^a-z0-9.]/g, '');
}
function earliest(a: string | null, b: string | null): string | null {
  if (!a) return b;
  if (!b) return a;
  return new Date(a) <= new Date(b) ? a : b;
}
function strongerPasswordRisk(a: string | null, b: string | null): string | null {
  const rank = (x: string | null) => (x === 'plaintext' ? 3 : x === 'hashed' ? 2 : x === 'unknown' ? 1 : 0);
  return rank(a) >= rank(b) ? a : b;
}
