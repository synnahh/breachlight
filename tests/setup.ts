import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';

// Every test run gets its own throwaway SQLite file, the demo provider on, and
// the network providers off so tests never touch the internet.
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'breach-scanner-test-'));
process.env.DATABASE_FILE = path.join(dir, 'test.db');
process.env.NODE_ENV = 'test';
process.env.DEMO_PROVIDER_ENABLED = 'true';
process.env.XPOSEDORNOT_ENABLED = 'false';
process.env.BREACH_CATALOGUE_ENABLED = 'false';
process.env.DOMAIN_SECURITY_ENABLED = 'false';
process.env.PASSWORD_CHECK_ENABLED = 'true';
