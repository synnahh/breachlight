import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api';
import type { DashboardSummary, PasswordExposureSite } from '../../shared/types';
import PasswordExposureList from '../components/PasswordExposureList';
import {
  Banner,
  ProgressBar,
  ScoreRing,
  Section,
  SeverityBadge,
  StatCard,
  formatBreachDate,
  formatDate,
  formatDateTime,
} from '../components/ui';

export default function Dashboard() {
  const [d, setD] = useState<DashboardSummary | null>(null);
  const [passwordSites, setPasswordSites] = useState<PasswordExposureSite[]>([]);
  const [error, setError] = useState<string | null>(null);

  const load = () =>
    api
      .dashboard()
      .then((x) => {
        setD(x);
        setError(null);
      })
      .catch((e) => setError(e.message));

  const loadPasswordSites = () =>
    api
      .passwordExposures()
      .then((s) => setPasswordSites(s.filter((x) => x.status !== 'secured')))
      .catch(() => setPasswordSites([]));

  useEffect(() => {
    load();
    loadPasswordSites();
  }, []);

  if (error) return <Banner tone="error">Could not load dashboard: {error}</Banner>;
  if (!d) return <div className="card text-muted">Loading…</div>;

  const empty = d.findingsTotal === 0 && !d.lastScanAt;

  return (
    <div className="space-y-6">
      <Section
        title="Security Overview"
        actions={
          <Link to="/scan" className="btn btn-primary">
            New Security Scan
          </Link>
        }
      >
        {d.notifications.map((n) => (
          <Banner key={n} tone="warn">
            {n}
          </Banner>
        ))}

        <div className="card flex flex-col items-center gap-5 sm:flex-row">
          <ScoreRing score={d.score.score} band={d.score.band} />
          <div className="min-w-0 flex-1">
            <div className="text-sm uppercase tracking-wide text-muted">Personal Security Score</div>
            <div className="text-xl font-semibold capitalize">{d.score.band}</div>
            {d.score.topRisks.length > 0 && (
              <>
                <div className="mt-2 text-xs font-medium uppercase tracking-wide text-muted">
                  Biggest remaining risks
                </div>
                <ol className="list-inside list-decimal text-sm text-muted">
                  {d.score.topRisks.map((r) => (
                    <li key={r}>{r}</li>
                  ))}
                </ol>
              </>
            )}
            <details className="mt-2 text-xs text-muted">
              <summary className="cursor-pointer">How the score is calculated</summary>
              <ul className="ml-4 mt-1 list-disc">
                {d.score.factors.map((f) => (
                  <li key={f.label}>
                    <span className={f.delta < 0 ? 'text-critical' : 'text-secured'}>
                      {f.delta > 0 ? `+${f.delta}` : f.delta}
                    </span>{' '}
                    {f.label} — {f.detail}
                  </li>
                ))}
                {d.score.factors.length === 0 && <li>No penalties applied — starts at 100.</li>}
              </ul>
            </details>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
          <StatCard label="Emails monitored" value={d.emailsMonitored} tone="accent" />
          <StatCard label="Findings" value={d.findingsTotal} sub={`${d.servicesExposed} services`} />
          <StatCard label="Critical" value={d.counts.critical} tone="critical" />
          <StatCard label="High" value={d.counts.high} tone="high" />
          <StatCard label="Medium" value={d.counts.medium} tone="medium" />
          <StatCard label="Low" value={d.counts.low} tone="low" />
          <Link to="/findings?filter=password" className="block">
            <StatCard
              label="Password exposures"
              value={d.passwordExposures}
              tone={d.passwordExposures > 0 ? 'critical' : undefined}
              sub="view & change"
            />
          </Link>
          <StatCard label="Optional providers" value={d.optionalProvidersConfigured} />
        </div>
      </Section>

      {empty ? (
        <Banner tone="info">
          No scans yet. Add an email on the <Link to="/scan" className="underline">New Scan</Link> page
          and run a Standard scan to get started.
        </Banner>
      ) : (
        <>
          <Section
            title="Urgent actions"
            actions={
              <Link to="/actions" className="btn">
                All security actions
              </Link>
            }
          >
            {d.urgentFindings.length === 0 ? (
              <div className="card text-sm text-muted">Nothing urgent right now.</div>
            ) : (
              <div className="space-y-2">
                {d.urgentFindings.map((u) => (
                  <div
                    key={u.id}
                    className="card flex items-center justify-between gap-3"
                  >
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={u.severity} />
                      <span className="font-medium">{u.service}</span>
                      <span className="text-xs text-muted">{u.headline}</span>
                    </div>
                    <Link to={`/findings/${u.id}`} className="btn btn-primary">
                      Secure
                    </Link>
                  </div>
                ))}
              </div>
            )}
          </Section>

          {passwordSites.length > 0 && (
            <Section title="Passwords to change">
              <PasswordExposureList
                sites={passwordSites.slice(0, 15)}
                intro="These breaches included password data for your monitored addresses. Change the password on each — and anywhere you reused it."
                onChanged={() => {
                  load();
                  loadPasswordSites();
                }}
              />
              {passwordSites.length > 15 && (
                <p className="text-xs text-muted">
                  Showing 15 of {passwordSites.length}.{' '}
                  <Link to="/findings?filter=password" className="underline">
                    See all password exposures
                  </Link>
                  .
                </p>
              )}
            </Section>
          )}

          <Section
            title="Your exposed accounts"
            actions={
              <Link to="/findings" className="btn">
                View all findings
              </Link>
            }
          >
            <div className="card overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs uppercase tracking-wide text-muted">
                    <th className="pb-2 pr-4">Website / Service</th>
                    <th className="pb-2 pr-4">Exposure</th>
                    <th className="pb-2 pr-4">Date</th>
                    <th className="pb-2">Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {d.exposedAccounts.map((a) => (
                    <tr key={a.id} className="border-t border-border">
                      <td className="py-2 pr-4">
                        <Link to={`/findings/${a.id}`} className="text-accent hover:underline">
                          {a.service}
                        </Link>
                      </td>
                      <td className="py-2 pr-4">{a.exposure}</td>
                      <td className="py-2 pr-4 text-muted">{formatBreachDate(a.date)}</td>
                      <td className="py-2">
                        <SeverityBadge severity={a.status === 'secured' ? 'secured' : a.severity} />
                      </td>
                    </tr>
                  ))}
                  {d.exposedAccounts.length === 0 && (
                    <tr>
                      <td colSpan={4} className="py-3 text-center text-muted">
                        No unresolved exposed accounts.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </Section>

          <div className="grid gap-4 md:grid-cols-2">
            <div className="card space-y-2">
              <h3 className="font-semibold">Security progress</h3>
              <ProgressBar percent={d.actionProgressPercent} />
              <p className="text-sm text-muted">
                {d.actionsCompleted} / {d.actionsTotal} actions completed
              </p>
              <Link to="/actions" className="btn">
                Work through actions
              </Link>
            </div>
            <div className="card space-y-2">
              <h3 className="font-semibold">Last scan</h3>
              <p className="text-sm text-muted">{formatDateTime(d.lastScanAt)}</p>
              {d.lastScanId && (
                <Link to={`/history`} className="btn">
                  View scan history
                </Link>
              )}
              <p className="pt-1 text-xs text-muted">
                “No breaches found” means nothing matched the queried sources — not that an account was
                never compromised. A breach result doesn't necessarily mean your current password is
                still in use.
              </p>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
