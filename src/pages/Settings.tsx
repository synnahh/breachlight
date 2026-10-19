import { useEffect, useState } from 'react';
import { api } from '../api';
import type { PrivacyReport } from '../../shared/types';
import { Banner, Section } from '../components/ui';

export default function Settings() {
  const [settings, setSettings] = useState<{
    values: Record<string, string>;
    config: Record<string, unknown>;
  } | null>(null);
  const [privacy, setPrivacy] = useState<PrivacyReport | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  const load = () => {
    api.settings().then(setSettings).catch(() => setSettings(null));
    api.privacy().then(setPrivacy).catch(() => setPrivacy(null));
  };
  useEffect(() => {
    load();
  }, []);

  async function save(key: string, value: string) {
    await api.saveSetting(key, value);
    setMsg('Saved.');
    load();
  }
  async function wipe() {
    if (!confirm('Permanently delete ALL local emails, scans, findings and actions?')) return;
    await api.wipe();
    setMsg('All local data deleted.');
    load();
  }

  return (
    <div className="space-y-6">
      {msg && <Banner tone="success">{msg}</Banner>}

      <Section title="Scan defaults">
        <div className="card space-y-3">
          <label className="block text-sm">
            <span className="label">Default scan depth</span>
            <select
              className="input"
              value={settings?.values.default_scan_depth ?? 'standard'}
              onChange={(e) => save('default_scan_depth', e.target.value)}
            >
              <option value="quick">Quick</option>
              <option value="standard">Standard</option>
              <option value="deep">Deep</option>
              <option value="maximum">Maximum</option>
            </select>
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={(settings?.values.notifications_enabled ?? 'true') === 'true'}
              onChange={(e) => save('notifications_enabled', String(e.target.checked))}
            />
            Show dashboard reminders / notifications
          </label>
        </div>
      </Section>

      <Section title="Data sources">
        <div className="card space-y-2 text-sm text-muted">
          <p>
            Provider toggles and the optional HIBP API key are configured in <code>.env</code> (see{' '}
            <code>README.md → Configuration</code>) and take effect on restart:
          </p>
          <ul className="ml-4 list-disc">
            <li>
              Password check: {String(settings?.config.passwordCheckEnabled)} — always uses the free
              k-anonymity range API (no key).
            </li>
            <li>
              HIBP (authenticated): {settings?.config.hibpConfigured ? 'configured' : 'not set'} —
              optional. Add <code>HIBP_API_KEY</code> to enable.
            </li>
            <li>Demo provider: {String(settings?.config.demoProviderEnabled)} — synthetic data only.</li>
          </ul>
        </div>
      </Section>

      <Section title="Privacy & data">
        <div className="card space-y-2 text-sm">
          {privacy ? (
            <>
              <ul className="ml-4 list-disc text-muted">
                <li>Emails stored locally: {privacy.emailsStoredLocally}</li>
                <li>Scans stored locally: {privacy.scansStoredLocally}</li>
                <li>Findings stored locally: {privacy.findingsStoredLocally}</li>
                <li>Passwords stored: never</li>
                <li>Password plaintext logged: never</li>
              </ul>
              <div className="text-xs text-muted">
                <div className="font-medium">External providers used:</div>
                <ul className="ml-4 list-disc">
                  {privacy.externalProvidersUsed.map((p) => (
                    <li key={p.id}>
                      {p.label} — sends {p.sends}
                    </li>
                  ))}
                </ul>
              </div>
              <p className="text-xs text-muted">Database file: {privacy.databaseFile}</p>
            </>
          ) : (
            <p className="text-muted">Loading…</p>
          )}
          <button className="btn btn-danger" onClick={wipe}>
            Delete all local data
          </button>
        </div>
      </Section>

      <Section title="About & limitations">
        <div className="card space-y-1 text-xs text-muted">
          <p>
            This is a defensive personal-security tool. It identifies exposure, explains risk, and
            helps you secure accounts. It never tests credentials against services, enumerates
            accounts, bypasses API restrictions, or acquires stolen credential dumps.
          </p>
          <p>
            Breach databases are incomplete. “No breaches found” means nothing matched the queried
            source(s) — not that an account was never compromised. A breach result does not
            necessarily mean your current password is still in use. No tool can guarantee an account
            is safe.
          </p>
        </div>
      </Section>
    </div>
  );
}
