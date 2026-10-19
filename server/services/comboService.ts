import type {
  BreachFinding,
  EmailExposureSummary,
  PasswordExposureSite,
} from '../../shared/types.js';
import { setMeta } from '../db.js';
import { activeEmailProviders, catalogue, markError, markSuccess } from '../providers/index.js';
import type { NormalisedBreach } from '../providers/types.js';
import { applyEnrichment, mergeBreaches, type NormalisedFinding } from './normalise.js';
import { buildAccountLinks } from './remediationService.js';
import { listFindings } from './storageService.js';

/**
 * Look up whether an email appears in breach data, for the Combo Finder.
 * Uses the same no-auth providers as a scan. Never stores the email as a
 * monitored address unless the user explicitly added it.
 *
 * Crucially this also returns WHICH of those breaches involved password data,
 * with a security link for each — so a "your password is exposed" result is
 * immediately actionable.
 */
export async function emailExposure(email: string): Promise<EmailExposureSummary> {
  const providers = activeEmailProviders().filter((p) => !p.isDemoData());
  const raw: NormalisedBreach[] = [];
  let anyOk = false;
  let source = 'none';

  for (const p of providers) {
    try {
      const results = await p.scanEmail(email.toLowerCase());
      raw.push(...results);
      anyOk = true;
      source = p.label;
      markSuccess(p.id);
      if (results.length > 0) break; // first source with data is enough here
    } catch (err) {
      markError(p.id, err);
    }
  }

  let merged = mergeBreaches(raw);
  // Enrich so we get domains/dates (and therefore usable security links) even
  // when the provider only returned a breach name.
  if (await catalogue.ready().catch(() => false)) {
    merged = await Promise.all(
      merged.map(async (f) =>
        applyEnrichment(f, await catalogue.enrich(f.domain || f.name).catch(() => null)),
      ),
    );
  }

  const stored = listFindings().filter((f) => f.email.toLowerCase() === email.toLowerCase());
  const passwordBreaches = merged
    .filter((f) => f.flags.passwordExposed)
    .map((f) => toExposureSite(f, email, stored))
    .sort(byRecency);

  const exposed = merged.length > 0;
  return {
    email,
    exposed,
    breachCount: merged.length,
    services: merged.map((f) => f.service || f.name).sort(),
    passwordBreaches,
    confidence: anyOk ? (exposed ? 'high' : 'medium') : 'low',
    source: anyOk ? source : 'no source available',
  };
}

function toExposureSite(
  f: NormalisedFinding,
  email: string,
  stored: BreachFinding[],
): PasswordExposureSite {
  const match = stored.find((s) => s.breachName.toLowerCase() === f.name.toLowerCase());
  return {
    service: f.service || f.name,
    email,
    domain: f.domain,
    breachDate: f.breachDate,
    passwordRisk: f.passwordRisk,
    dataClasses: f.dataClasses,
    links: buildAccountLinks(f),
    findingId: match?.id ?? null,
    status: match?.status ?? null,
    severity: match?.severity ?? null,
  };
}

/**
 * Every stored finding where password data was exposed, as an actionable
 * "go change your password here" list. Used by the password-only checker so a
 * COMPROMISED result points straight at the accounts that need securing.
 */
export function storedPasswordExposures(): PasswordExposureSite[] {
  return listFindings()
    .filter((f) => f.passwordExposed)
    .map((f) => ({
      service: f.service,
      email: f.email,
      domain: f.domain,
      breachDate: f.breachDate,
      passwordRisk: f.passwordRisk,
      dataClasses: f.dataClasses,
      links: f.links,
      findingId: f.id,
      status: f.status,
      severity: f.severity,
    }))
    .sort(byRecency);
}

function byRecency(a: PasswordExposureSite, b: PasswordExposureSite): number {
  const d = (b.breachDate ?? '').localeCompare(a.breachDate ?? '');
  if (d !== 0) return d;
  return a.service.localeCompare(b.service) || a.email.localeCompare(b.email);
}

/** Record (privacy-safe) that a combo check found the password in breach data. */
export function noteComboPasswordFound(found: boolean): void {
  setMeta('combo_password_found', found ? '1' : '0');
}
