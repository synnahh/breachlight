import { useEffect, useState } from 'react';
import { api } from '../api';
import { checkCombo, checkPassword } from '../lib/passwordClient';
import type {
  ComboResponse,
  PasswordCheckResult,
  PasswordExposureSite,
} from '../../shared/types';
import { isValidEmail } from '../../shared/validation';
import { Banner, Section, SeverityBadge } from '../components/ui';
import PasswordExposureList from '../components/PasswordExposureList';

export default function PasswordTools() {
  return (
    <div className="space-y-6">
      <ComboFinder />
      <PasswordChecker />
      <div className="card text-xs text-muted">
        Both tools hash the password in this browser with SHA-1 and send only the first 5 characters
        of the hash to the Pwned Passwords range API. The plaintext password and the full hash never
        leave this machine, are never stored, and are never logged. A compromised password is never
        displayed. Appearing in a breach dataset does not necessarily mean one of your specific
        accounts was taken over — but the password should be treated as public.
      </div>
    </div>
  );
}

function ComboFinder() {
  const [email, setEmail] = useState('');
  const [pw, setPw] = useState('');
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ComboResponse | null>(null);

  async function run(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setResult(null);
    if (!isValidEmail(email.trim())) return setError('Enter a valid email address.');
    if (!pw) return setError('Enter a password.');
    setBusy(true);
    try {
      const r = await checkCombo(email.trim(), pw);
      setResult(r);
      setPw('');
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function refresh() {
    if (!result) return;
    try {
      const sites = await api.passwordExposures();
      setResult({ ...result, passwordBreaches: mergeStatuses(result.passwordBreaches, sites) });
    } catch {
      /* non-fatal */
    }
  }

  return (
    <Section title="Combo Finder — credential exposure check">
      <p className="text-sm text-muted">
        Checks whether an email/password combination has appeared in legitimate breach intelligence.
        The password is never used to log into any website.
      </p>
      <form onSubmit={run} className="card space-y-3">
        <div>
          <label className="label" htmlFor="combo-email">
            Email
          </label>
          <input
            id="combo-email"
            className="input"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </div>
        <div>
          <label className="label" htmlFor="combo-pw">
            Password
          </label>
          <div className="flex gap-2">
            <input
              id="combo-pw"
              className="input"
              type={show ? 'text' : 'password'}
              autoComplete="off"
              value={pw}
              onChange={(e) => setPw(e.target.value)}
            />
            <button type="button" className="btn shrink-0" onClick={() => setShow((s) => !s)}>
              {show ? 'Hide' : 'Show'}
            </button>
          </div>
        </div>
        <button className="btn btn-primary" disabled={busy}>
          {busy ? 'Checking…' : 'Check exposure'}
        </button>
      </form>

      {error && <Banner tone="error">{error}</Banner>}

      {result && (
        <div className="card space-y-3">
          <div className="grid gap-2 sm:grid-cols-3">
            <Fact label="Email exposed" ok={!result.emailExposed}>
              {result.emailExposed
                ? `Found in ${result.emailBreachCount} breach(es)`
                : 'Not found'}
            </Fact>
            <Fact label="Password exposed" ok={!result.passwordExposed}>
              {result.passwordExposed
                ? `Found (~${result.passwordOccurrences?.toLocaleString()})`
                : 'Not found'}
            </Fact>
            <div className="rounded-lg border border-border bg-bg p-2">
              <div className="text-[10px] uppercase tracking-wide text-muted">Combination risk</div>
              <div className="mt-1">
                <SeverityBadge severity={result.combinationRisk} />
              </div>
            </div>
          </div>
          <p className="text-sm">{result.combinationRiskReason}</p>
          <div>
            <div className="text-xs font-semibold uppercase tracking-wide text-muted">
              Recommended action
            </div>
            <ol className="list-inside list-decimal text-sm">
              {result.recommendedActions.map((a) => (
                <li key={a}>{a}</li>
              ))}
            </ol>
          </div>
          <ul className="ml-4 list-disc text-xs text-muted">
            {result.notes.map((n) => (
              <li key={n}>{n}</li>
            ))}
          </ul>
          <p className="text-xs text-muted">Email source: {result.emailSource}</p>
        </div>
      )}

      {result && result.passwordBreaches.length > 0 && (
        <PasswordExposureList sites={result.passwordBreaches} onChanged={refresh} />
      )}

      {result && result.emailExposed && result.passwordBreaches.length === 0 && (
        <Banner tone="info">
          This email appears in {result.emailBreachCount} breach(es), but none of the queried
          sources reported password data in them. Review the full findings for these services:{' '}
          {result.services.slice(0, 12).join(', ')}
          {result.services.length > 12 ? ` +${result.services.length - 12} more` : ''}.
        </Banner>
      )}
    </Section>
  );
}

function Fact({
  label,
  ok,
  children,
}: {
  label: string;
  ok: boolean;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-lg border border-border bg-bg p-2">
      <div className="text-[10px] uppercase tracking-wide text-muted">{label}</div>
      <div className={`mt-1 text-sm font-medium ${ok ? 'text-secured' : 'text-critical'}`}>
        {ok ? '✓ ' : '⚠ '}
        {children}
      </div>
    </div>
  );
}

const BAND_LABEL: Record<PasswordCheckResult['exposureBand'], string> = {
  none: 'Not found',
  low: 'Low',
  medium: 'Medium',
  high: 'High',
  very_high: 'Very high',
};

/** Keep provider-derived sites but refresh their tracked status from storage. */
function mergeStatuses(
  sites: PasswordExposureSite[],
  stored: PasswordExposureSite[],
): PasswordExposureSite[] {
  return sites.map((s) => {
    const hit = stored.find(
      (x) =>
        x.service.toLowerCase() === s.service.toLowerCase() &&
        x.email.toLowerCase() === s.email.toLowerCase(),
    );
    return hit ? { ...s, findingId: hit.findingId, status: hit.status, severity: hit.severity } : s;
  });
}

function PasswordChecker() {
  const [value, setValue] = useState('');
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<PasswordCheckResult | null>(null);
  const [sites, setSites] = useState<PasswordExposureSite[]>([]);
  const [error, setError] = useState<string | null>(null);

  const loadSites = () => api.passwordExposures().then(setSites).catch(() => setSites([]));
  useEffect(() => {
    loadSites();
  }, []);

  async function run(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setResult(null);
    if (!value) return setError('Enter a password to check.');
    setBusy(true);
    try {
      const r = await checkPassword(value);
      setResult(r);
      setValue('');
      await loadSites();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Section title="Password-only check">
      <form onSubmit={run} className="card space-y-3">
        <label className="label" htmlFor="pw-only">
          Password
        </label>
        <div className="flex gap-2">
          <input
            id="pw-only"
            className="input"
            type={show ? 'text' : 'password'}
            autoComplete="off"
            value={value}
            onChange={(e) => setValue(e.target.value)}
          />
          <button type="button" className="btn shrink-0" onClick={() => setShow((s) => !s)}>
            {show ? 'Hide' : 'Show'}
          </button>
        </div>
        <button className="btn btn-primary" disabled={busy}>
          {busy ? 'Checking…' : 'Check password'}
        </button>
      </form>
      {error && <Banner tone="error">{error}</Banner>}
      {result && (
        <div className="card space-y-2">
          <h3 className="text-lg font-semibold">
            {result.compromised ? (
              <span className="text-critical">⚠ COMPROMISED</span>
            ) : (
              <span className="text-secured">✓ Not found in the queried dataset</span>
            )}
          </h3>
          {result.compromised && (
            <p className="text-sm">
              Exposure level: <strong>{BAND_LABEL[result.exposureBand]}</strong>
              {result.occurrences ? ` (~${result.occurrences.toLocaleString()} occurrences)` : ''}
            </p>
          )}
          <p className="text-sm text-muted">{result.note}</p>
          <ul className="list-inside list-disc text-sm">
            {result.recommendedActions.map((a) => (
              <li key={a}>{a}</li>
            ))}
          </ul>
        </div>
      )}

      {sites.length > 0 && (
        <PasswordExposureList
          sites={sites}
          title="Accounts you are monitoring with exposed password data"
          intro={
            result?.compromised
              ? 'If this is the password you use on any of these, change it there first. These are the breaches from your monitored emails that included password data.'
              : 'These monitored accounts had password data exposed in a breach. Change the password on each, regardless of the check above.'
          }
          onChanged={loadSites}
        />
      )}
    </Section>
  );
}
