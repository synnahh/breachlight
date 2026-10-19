import { beforeEach, describe, expect, it } from 'vitest';
import { emailExposure, storedPasswordExposures } from '../server/services/comboService.js';
import { scanEmailNow } from '../server/services/scanService.js';
import { addEmail, listFindings, setFindingStatus, wipeAllData } from '../server/services/storageService.js';

beforeEach(() => wipeAllData());

describe('password exposure — "where do I go and change it"', () => {
  it('lists every stored finding whose breach included password data, newest first', async () => {
    const email = addEmail('breach.victim.gamer@example.com');
    await scanEmailNow(email.id, 'standard');

    const sites = storedPasswordExposures();
    const pwFindings = listFindings().filter((f) => f.passwordExposed);

    expect(sites).toHaveLength(pwFindings.length);
    expect(sites.length).toBeGreaterThan(0);

    // every site is actionable: named service + owning email + finding + status
    expect(sites.every((s) => s.service.length > 0)).toBe(true);
    expect(sites.every((s) => s.email === 'breach.victim.gamer@example.com')).toBe(true);
    expect(sites.every((s) => s.findingId !== null)).toBe(true);
    expect(sites.every((s) => s.status === 'open')).toBe(true);

    // and points somewhere the user can actually go
    expect(sites.every((s) => s.links.length > 0)).toBe(true);

    // newest breach first
    const dates = sites.map((s) => s.breachDate ?? '');
    expect([...dates].sort().reverse()).toEqual(dates);
  });

  it('excludes findings with no password data', async () => {
    const email = addEmail('breach.victim@example.com');
    await scanEmailNow(email.id, 'standard');
    const services = storedPasswordExposures().map((s) => s.service);
    // DemoMail Newsletter is email-only — it must not appear as a password exposure
    expect(services).not.toContain('DemoMail Newsletter');
    expect(services.length).toBeGreaterThan(0);
  });

  it('reflects remediation status so secured accounts can be filtered out', async () => {
    const email = addEmail('breach.victim@example.com');
    await scanEmailNow(email.id, 'standard');
    const first = storedPasswordExposures()[0];
    setFindingStatus(first.findingId!, 'secured');
    const after = storedPasswordExposures().find((s) => s.findingId === first.findingId);
    expect(after?.status).toBe('secured');
    expect(storedPasswordExposures().filter((s) => s.status !== 'secured').length).toBe(
      storedPasswordExposures().length - 1,
    );
  });

  it('keeps the same service listed separately per monitored email', async () => {
    const a = addEmail('breach.victim@example.com');
    const b = addEmail('shop.victim@example.com');
    await scanEmailNow(a.id, 'standard');
    await scanEmailNow(b.id, 'standard');

    const sites = storedPasswordExposures();
    const demoShop = sites.filter((s) => s.service === 'DemoShop');
    expect(demoShop).toHaveLength(2);
    expect(new Set(demoShop.map((s) => s.email))).toEqual(
      new Set(['breach.victim@example.com', 'shop.victim@example.com']),
    );
    // rows must be uniquely identifiable for the UI
    const keys = sites.map((s) => `${s.email}::${s.service}`);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it('emailExposure returns the password-involved breaches for a combo check', async () => {
    const summary = await emailExposure('breach.victim.gamer@example.com');
    expect(summary.exposed).toBe(false); // demo provider is excluded from combo lookups
    expect(summary.passwordBreaches).toEqual([]);
    expect(Array.isArray(summary.services)).toBe(true);
  });
});
