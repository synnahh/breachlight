import { afterEach, describe, expect, it, vi } from 'vitest';
import { MockProvider } from '../server/providers/mockProvider.js';
import { XposedOrNotProvider } from '../server/providers/xposedOrNotProvider.js';

describe('MockProvider (DEMO DATA)', () => {
  const p = new MockProvider();
  it('is flagged as demo data', () => {
    expect(p.isDemoData()).toBe(true);
    expect(p.kind).toBe('email');
  });
  it('returns deterministic synthetic breaches with a severity spread', async () => {
    const a = await p.scanEmail('breach.victim.gamer@example.com');
    const b = await p.scanEmail('breach.victim.gamer@example.com');
    expect(a).toEqual(b);
    expect(a.length).toBeGreaterThanOrEqual(4);
    expect(a.every((x) => x.isDemoData)).toBe(true);
  });
  it('returns nothing for a "clean" address', async () => {
    expect(await p.scanEmail('clean.user@example.com')).toEqual([]);
  });
});

describe('XposedOrNotProvider (public, no key)', () => {
  const provider = new XposedOrNotProvider();
  vi.spyOn(provider, 'isConfigured').mockReturnValue(true);
  afterEach(() => vi.unstubAllGlobals());

  it('normalises a breach-analytics payload into findings', async () => {
    const payload = {
      ExposedBreaches: {
        breaches_details: [
          {
            breach: 'Adobe',
            details: '<p>Big <a href="#">breach</a></p>',
            domain: 'adobe.com',
            industry: 'Technology',
            password_risk: 'plaintext',
            xposed_data: 'Email addresses;Passwords;Usernames',
            xposed_date: '2013',
            xposed_records: 153000000,
            added: '2013-12-04T00:00:00Z',
          },
        ],
      },
    };
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(new Response(JSON.stringify(payload), { status: 200 })),
    );
    const out = await provider.scanEmail('someone-unique-xyz@example.com');
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({
      name: 'Adobe',
      domain: 'adobe.com',
      passwordRisk: 'plaintext',
      confidence: 'high',
      associationType: 'confirmed',
      isDemoData: false,
    });
    expect(out[0].description).toBe('Big breach');
    expect(out[0].dataClasses).toContain('Passwords');
  });

  it('returns [] when the account is not found', async () => {
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        // breach-analytics: nulls
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ ExposedBreaches: null }), { status: 200 }),
        )
        // check-email fallback: Error
        .mockResolvedValueOnce(new Response(JSON.stringify({ Error: 'Not found' }), { status: 200 })),
    );
    expect(await provider.scanEmail('nobody-unique-abc@example.com')).toEqual([]);
  });

  it('propagates a ProviderError when the source is unreachable', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(Object.assign(new Error('down'), { name: 'TypeError' })));
    await expect(provider.scanEmail('x-unique-777@example.com')).rejects.toMatchObject({
      name: 'ProviderError',
    });
  });
});
