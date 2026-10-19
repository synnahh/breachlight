import type { NormalisedBreach } from './types.js';

// A small offline snapshot of well-known breaches so the catalogue provider is
// useful on the very first run before it has fetched the live public catalogue.
// Sourced from Have I Been Pwned's PUBLIC breaches endpoint (no credentials).
// Not stolen data — only breach *metadata*.
export const BUNDLED_CATALOGUE: Record<string, Partial<NormalisedBreach>> = {
  adobe: {
    name: 'Adobe',
    title: 'Adobe',
    service: 'Adobe',
    domain: 'adobe.com',
    breachDate: '2013-10-04',
    disclosureDate: '2013-12-04T00:00:00Z',
    description:
      'In October 2013, 153 million Adobe accounts were breached, exposing internal IDs, usernames, emails, encrypted passwords and plaintext password hints.',
    dataClasses: ['Email addresses', 'Password hints', 'Passwords', 'Usernames'],
    passwordRisk: 'hashed',
    pwnCount: 152445165,
  },
  linkedin: {
    name: 'LinkedIn',
    title: 'LinkedIn',
    service: 'LinkedIn',
    domain: 'linkedin.com',
    breachDate: '2012-05-05',
    disclosureDate: '2016-05-21T00:00:00Z',
    description:
      'In May 2012, LinkedIn was breached and ~164 million email addresses and passwords were exposed; the data surfaced publicly in 2016.',
    dataClasses: ['Email addresses', 'Passwords'],
    passwordRisk: 'hashed',
    pwnCount: 164611595,
  },
  dropbox: {
    name: 'Dropbox',
    title: 'Dropbox',
    service: 'Dropbox',
    domain: 'dropbox.com',
    breachDate: '2012-07-01',
    disclosureDate: '2016-08-30T00:00:00Z',
    description:
      'In mid-2012 Dropbox was breached, exposing ~68 million records with email addresses and salted, hashed passwords.',
    dataClasses: ['Email addresses', 'Passwords'],
    passwordRisk: 'hashed',
    pwnCount: 68648009,
  },
  myspace: {
    name: 'MySpace',
    title: 'MySpace',
    service: 'MySpace',
    domain: 'myspace.com',
    breachDate: '2008-07-01',
    disclosureDate: '2016-05-31T00:00:00Z',
    description:
      'Prior to 2009, MySpace was breached; ~360 million accounts with emails, usernames and weakly hashed passwords surfaced in 2016.',
    dataClasses: ['Email addresses', 'Passwords', 'Usernames'],
    passwordRisk: 'hashed',
    pwnCount: 359420698,
  },
  '000webhost': {
    name: '000webhost',
    title: '000webhost',
    service: '000webhost',
    domain: '000webhost.com',
    breachDate: '2015-03-01',
    disclosureDate: '2015-10-26T23:35:45Z',
    description:
      'In March 2015 the free web host 000webhost was breached, exposing ~15 million records with names, emails and plaintext passwords.',
    dataClasses: ['Email addresses', 'IP addresses', 'Names', 'Passwords'],
    passwordRisk: 'plaintext',
    pwnCount: 14936670,
  },
  canva: {
    name: 'Canva',
    title: 'Canva',
    service: 'Canva',
    domain: 'canva.com',
    breachDate: '2019-05-24',
    disclosureDate: '2019-05-30T00:00:00Z',
    description:
      'In May 2019 Canva suffered a breach exposing ~137 million records including names, usernames, emails and bcrypt password hashes.',
    dataClasses: ['Email addresses', 'Geographic locations', 'Names', 'Passwords', 'Usernames'],
    passwordRisk: 'hashed',
    pwnCount: 137272116,
  },
};
