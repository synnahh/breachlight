import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api';
import type { EmailRecord, Scan, ScanDepth, ScanOptions } from '../../shared/types';
import { isValidEmail } from '../../shared/validation';
import { Banner, Section } from '../components/ui';

const DEPTHS: { id: ScanDepth; title: string; blurb: string }[] = [
  { id: 'quick', title: 'Quick', blurb: 'Fastest single source — email exposure + high-level risk. A quick check before acting.' },
  { id: 'standard', title: 'Standard', blurb: 'All public email sources + catalogue enrichment: breach metadata, exposed data, severity, remediation.' },
  { id: 'deep', title: 'Deep', blurb: 'Everything in Standard + authenticated providers, domain security posture, and cross-breach correlation.' },
  { id: 'maximum', title: 'Maximum', blurb: 'Every configured source, every monitored email, full correlation and the most complete remediation report.' },
];

export default function NewScan() {
  const nav = useNavigate();
  const [emails, setEmails] = useState<EmailRecord[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [input, setInput] = useState('');
  const [label, setLabel] = useState('');
  const [depth, setDepth] = useState<ScanDepth>('standard');
  const [options, setOptions] = useState<ScanOptions>({
    passwordCheck: true,
    crossBreachCorrelation: true,
    domainSecurity: true,
    historicalComparison: true,
  });
  const [error, setError] = useState<string | null>(null);
  const [scan, setScan] = useState<Scan | null>(null);
  const [running, setRunning] = useState(false);
  const poll = useRef<number | null>(null);

  const load = () =>
    api.listEmails().then((e) => {
      setEmails(e);
      setSelected((cur) => {
        if (cur.size > 0) return cur;
        return new Set(e.map((x) => x.id));
      });
    });

  useEffect(() => {
    load();
    return () => {
      if (poll.current) window.clearInterval(poll.current);
    };
  }, []);

  async function addEmail(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!isValidEmail(input.trim())) {
      setError('Enter a valid email address.');
      return;
    }
    try {
      const rec = await api.addEmail(input.trim(), label.trim() || undefined);
      setInput('');
      setLabel('');
      await load();
      setSelected((s) => new Set(s).add(rec.id));
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function removeEmail(id: string) {
    if (!confirm('Remove this email and all its findings?')) return;
    await api.removeEmail(id);
    await load();
    setSelected((s) => {
      const n = new Set(s);
      n.delete(id);
      return n;
    });
  }

  function toggle(id: string) {
    setSelected((s) => {
      const n = new Set(s);
      n.has(id) ? n.delete(id) : n.add(id);
      return n;
    });
  }

  async function start() {
    setError(null);
    const ids = depth === 'maximum' ? emails.map((e) => e.id) : [...selected];
    if (ids.length === 0) {
      setError('Select at least one email to scan.');
      return;
    }
    setRunning(true);
    setScan(null);
    try {
      const { scanId } = await api.startScan(ids, depth, options);
      poll.current = window.setInterval(async () => {
        try {
          const { scan } = await api.getScan(scanId);
          setScan(scan);
          if (scan.status !== 'running') {
            if (poll.current) window.clearInterval(poll.current);
            setRunning(false);
          }
        } catch {
          /* keep polling */
        }
      }, 800);
    } catch (err) {
      setError((err as Error).message);
      setRunning(false);
    }
  }

  return (
    <div className="space-y-6">
      <Section title="Emails">
        <p className="text-sm text-muted">
          Stored only in the local database on this machine. During a scan an address is sent only to
          the configured breach providers.
        </p>
        {error && <Banner tone="error">{error}</Banner>}
        <form onSubmit={addEmail} className="flex flex-wrap gap-2">
          <input
            className="input flex-1"
            type="email"
            placeholder="you@example.com"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            aria-label="Email address"
          />
          <input
            className="input w-32"
            placeholder="Label"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            aria-label="Label (e.g. Primary)"
          />
          <button className="btn btn-primary" type="submit">
            + Add
          </button>
        </form>
        <div className="space-y-2">
          {emails.length === 0 && (
            <div className="card text-sm text-muted">No emails yet. Add one above.</div>
          )}
          {emails.map((e) => (
            <label
              key={e.id}
              className="card flex cursor-pointer items-center justify-between gap-3"
            >
              <span className="flex items-center gap-3">
                <input
                  type="checkbox"
                  checked={selected.has(e.id)}
                  onChange={() => toggle(e.id)}
                  disabled={depth === 'maximum'}
                />
                <span>
                  <span className="font-medium">{e.email}</span>
                  {e.label && (
                    <span className="ml-2 pill border border-border text-muted">{e.label}</span>
                  )}
                </span>
              </span>
              <button
                type="button"
                className="btn btn-danger"
                onClick={(ev) => {
                  ev.preventDefault();
                  removeEmail(e.id);
                }}
              >
                Remove
              </button>
            </label>
          ))}
        </div>
      </Section>

      <Section title="New Security Scan">
        <div className="card space-y-4">
          <div>
            <div className="label">Scan depth</div>
            <div className="grid gap-2 sm:grid-cols-2">
              {DEPTHS.map((dp) => (
                <label
                  key={dp.id}
                  className={`cursor-pointer rounded-lg border p-3 text-sm ${
                    depth === dp.id ? 'border-accent bg-accent/10' : 'border-border'
                  }`}
                >
                  <span className="flex items-center gap-2 font-medium">
                    <input
                      type="radio"
                      name="depth"
                      checked={depth === dp.id}
                      onChange={() => setDepth(dp.id)}
                    />
                    {dp.title}
                  </span>
                  <span className="mt-1 block text-xs text-muted">{dp.blurb}</span>
                </label>
              ))}
            </div>
          </div>

          <div>
            <div className="label">Options</div>
            <div className="grid gap-2 sm:grid-cols-2">
              {(
                [
                  ['passwordCheck', 'Password exposure indicator'],
                  ['crossBreachCorrelation', 'Cross-breach correlation'],
                  ['domainSecurity', 'Domain security checks (Deep+)'],
                  ['historicalComparison', 'Historical comparison'],
                ] as [keyof ScanOptions, string][]
              ).map(([key, txt]) => (
                <label key={key} className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={options[key]}
                    onChange={(e) => setOptions((o) => ({ ...o, [key]: e.target.checked }))}
                  />
                  {txt}
                </label>
              ))}
            </div>
          </div>

          <button className="btn btn-primary" onClick={start} disabled={running}>
            {running ? 'Scanning…' : 'Start scan'}
          </button>
          {depth === 'maximum' && (
            <p className="text-xs text-muted">Maximum depth scans every monitored email.</p>
          )}
        </div>
      </Section>

      {scan && <ScanProgress scan={scan} onDone={() => nav('/findings')} />}
    </div>
  );
}

function ScanProgress({ scan, onDone }: { scan: Scan; onDone: () => void }) {
  const icon = (s: string) =>
    s === 'ok' ? '✓' : s === 'failed' ? '✗' : s === 'running' ? '●' : s === 'skipped' ? '–' : '○';
  return (
    <Section title="Scan progress">
      <div className="card space-y-2">
        {scan.stages.map((s) => (
          <div key={s.key} className="flex items-center gap-2 text-sm">
            <span aria-hidden className={s.status === 'running' ? 'text-accent' : ''}>
              {icon(s.status)}
            </span>
            <span className={s.status === 'failed' ? 'text-critical' : ''}>{s.label}</span>
            {s.detail && <span className="text-xs text-muted">({s.detail})</span>}
          </div>
        ))}
        {scan.status === 'complete' && scan.summary && (
          <div className="space-y-2 border-t border-border pt-3 text-sm">
            <div className="font-semibold">
              Scan complete — {scan.summary.total} finding(s):{' '}
              {scan.summary.counts.critical} critical, {scan.summary.counts.high} high,{' '}
              {scan.summary.counts.medium} medium, {scan.summary.counts.low} low
            </div>
            <div className="text-muted">
              {scan.summary.requireAction} require action ·{' '}
              {scan.summary.passwordExposures} with password exposure ·{' '}
              coverage {scan.coverage.percent}% ({scan.coverage.sourcesAvailable}/
              {scan.coverage.sourcesTotal} sources)
            </div>
            {scan.coverage.percent < 100 && (
              <Banner tone="warn">
                {scan.coverage.note} Unavailable: {scan.coverage.unavailable.join(', ') || 'n/a'}.
              </Banner>
            )}
            {scan.summary.topPriorities.length > 0 && (
              <div>
                <span className="font-medium">Top priorities:</span>{' '}
                {scan.summary.topPriorities.join(' → ')}
              </div>
            )}
            {scan.comparison && (
              <div className="text-muted">
                vs previous scan: {scan.comparison.previousExposures} → {scan.comparison.currentExposures}{' '}
                exposures ({scan.comparison.exposureDelta >= 0 ? '+' : ''}
                {scan.comparison.exposureDelta}).
                {scan.comparison.noLongerReturned.length > 0 &&
                  ` No longer returned by a provider: ${scan.comparison.noLongerReturned.join(', ')} (not the same as "resolved").`}
              </div>
            )}
            <button className="btn btn-primary" onClick={onDone}>
              View findings
            </button>
          </div>
        )}
        {scan.status === 'failed' && <Banner tone="error">{scan.error}</Banner>}
      </div>
    </Section>
  );
}
