import { config } from '../config.js';
import { ProviderError, type EmailProvider, type NormalisedBreach } from './types.js';

// ─────────────────────────────────────────────────────────────────────────
//  DEMO DATA — entirely synthetic. OFF by default (DEMO_PROVIDER_ENABLED).
//  Never mixed with real provider results: findings are tagged isDemoData and
//  the UI shows a DEMO badge on every one.
// ─────────────────────────────────────────────────────────────────────────

interface DemoBreach extends NormalisedBreach {
  appliesTo: string[];
}

const D = (b: Partial<NormalisedBreach> & { name: string; appliesTo: string[] }): DemoBreach => ({
  title: b.name,
  service: b.name,
  domain: null,
  breachDate: null,
  disclosureDate: null,
  firstSeenDate: null,
  description: null,
  dataClasses: [],
  passwordRisk: null,
  pwnCount: null,
  industry: null,
  confidence: 'high',
  confidenceReason: 'Synthetic demo record.',
  associationType: 'confirmed',
  source: 'DEMO provider',
  providerId: 'demo',
  isDemoData: true,
  ...b,
});

const DEMO_BREACHES: DemoBreach[] = [
  D({
    name: 'DemoCloud',
    domain: 'democloud.example',
    breachDate: '2024-02-11',
    disclosureDate: '2024-05-03T00:00:00Z',
    description: 'DEMO DATA: fictional cloud provider — demonstrates a CRITICAL finding.',
    dataClasses: ['Email addresses', 'Passwords', 'Password hints', 'Names', 'Phone numbers'],
    passwordRisk: 'plaintext',
    pwnCount: 4200000,
    appliesTo: ['cloud', 'victim', 'breach'],
  }),
  D({
    name: 'DemoShop',
    domain: 'demoshop.example',
    breachDate: '2019-08-20',
    disclosureDate: '2019-11-30T00:00:00Z',
    description: 'DEMO DATA: fictional shop — demonstrates a HIGH finding with hashed passwords.',
    dataClasses: ['Email addresses', 'Passwords', 'Usernames', 'Purchases'],
    passwordRisk: 'hashed',
    pwnCount: 890000,
    appliesTo: ['shop', 'victim', 'breach'],
  }),
  D({
    name: 'DemoForum',
    domain: 'demoforum.example',
    breachDate: '2016-01-05',
    disclosureDate: '2016-07-14T00:00:00Z',
    description: 'DEMO DATA: fictional forum — demonstrates a MEDIUM finding.',
    dataClasses: ['Email addresses', 'Usernames', 'IP addresses', 'Geographic locations'],
    pwnCount: 320000,
    appliesTo: ['*'],
  }),
  D({
    name: 'DemoMail Newsletter',
    domain: 'demomail.example',
    breachDate: '2021-03-30',
    disclosureDate: '2021-04-10T00:00:00Z',
    description: 'DEMO DATA: fictional newsletter — demonstrates a LOW finding.',
    dataClasses: ['Email addresses'],
    pwnCount: 50000,
    appliesTo: ['*'],
  }),
  D({
    name: 'DemoGamesNetwork',
    domain: 'demogames.example',
    breachDate: '2023-09-01',
    disclosureDate: '2023-10-01T00:00:00Z',
    description: 'DEMO DATA: fictional gaming network.',
    dataClasses: ['Email addresses', 'Usernames', 'Security questions and answers'],
    pwnCount: 610000,
    appliesTo: ['gamer'],
  }),
];

export class MockProvider implements EmailProvider {
  readonly id = 'demo';
  readonly label = 'Demo provider (synthetic data)';
  readonly kind = 'email' as const;
  readonly requiresAuth = false;

  isConfigured(): boolean {
    return config.demoProviderEnabled || config.isTest;
  }
  isDemoData(): boolean {
    return true;
  }

  async scanEmail(email: string): Promise<NormalisedBreach[]> {
    if (!this.isConfigured()) throw new ProviderError('not_configured', 'Demo provider disabled');
    const local = email.split('@')[0]?.toLowerCase() ?? '';
    if (local.includes('clean') || local.includes('safe')) return [];
    return DEMO_BREACHES.filter((b) =>
      b.appliesTo.some((t) => t === '*' || local.includes(t)),
    ).map(({ appliesTo: _a, ...rest }) => ({ ...rest }));
  }
}
