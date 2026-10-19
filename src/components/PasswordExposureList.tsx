import { Link } from 'react-router-dom';
import type { FindingStatus, PasswordExposureSite } from '../../shared/types';
import { api } from '../api';
import { Banner, SeverityBadge, formatBreachDate } from './ui';

/**
 * "Where do I go and change it" — the actionable list of services whose breach
 * included password data. This is what turns a COMPROMISED result into work the
 * user can actually do.
 */
export default function PasswordExposureList({
  sites,
  title = 'Change your password on these services',
  intro,
  onChanged,
}: {
  sites: PasswordExposureSite[];
  title?: string;
  intro?: string;
  onChanged?: () => void;
}) {
  if (sites.length === 0) return null;

  async function secure(findingId: string, status: FindingStatus) {
    await api.setFindingStatus(findingId, status);
    onChanged?.();
  }

  const outstanding = sites.filter((s) => s.status !== 'secured');

  return (
    <div className="card space-y-3">
      <div>
        <h4 className="font-semibold text-critical">
          🔑 {title} ({outstanding.length} outstanding)
        </h4>
        <p className="mt-1 text-xs text-muted">
          {intro ??
            'These breaches included password data for this address. Change the password on each — and anywhere you reused it. Sites are listed most recent first.'}
        </p>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full min-w-[46rem] text-sm">
          <thead>
            <tr className="text-left text-xs uppercase tracking-wide text-muted">
              <th className="pb-2 pr-4">Service</th>
              <th className="pb-2 pr-4">Account</th>
              <th className="pb-2 pr-4">Website</th>
              <th className="pb-2 pr-4">Breach</th>
              <th className="pb-2 pr-4">Password format</th>
              <th className="pb-2 pr-4">Go here</th>
              <th className="pb-2">Status</th>
            </tr>
          </thead>
          <tbody>
            {sites.map((s) => {
              const best = s.links.find((l) => !l.derived) ?? s.links[0];
              return (
                <tr
                  key={`${s.email}::${s.service}::${s.domain ?? ''}`}
                  className="border-t border-border align-top"
                >
                  <td className="py-2 pr-4">
                    <span className="font-medium">{s.service}</span>
                    {s.severity && (
                      <span className="ml-2">
                        <SeverityBadge severity={s.status === 'secured' ? 'secured' : s.severity} />
                      </span>
                    )}
                  </td>
                  <td className="py-2 pr-4 text-xs text-muted">{s.email}</td>
                  <td className="py-2 pr-4 text-muted">{s.domain ?? 'Unknown'}</td>
                  <td className="py-2 pr-4 text-muted">{formatBreachDate(s.breachDate)}</td>
                  <td className="py-2 pr-4 text-muted">{s.passwordRisk ?? 'unknown'}</td>
                  <td className="whitespace-nowrap py-2 pr-4">
                    {best ? (
                      <a
                        href={best.url}
                        target="_blank"
                        rel="noreferrer noopener"
                        className="text-accent underline"
                        title={
                          best.derived
                            ? `${best.url} — then go to Account → Security → Password`
                            : best.url
                        }
                      >
                        {best.derived ? 'Open site →' : 'Change password →'}
                      </a>
                    ) : (
                      <span className="text-muted">No known URL</span>
                    )}
                  </td>
                  <td className="whitespace-nowrap py-2">
                    {s.findingId ? (
                      s.status === 'secured' ? (
                        <span className="text-secured">✓ secured</span>
                      ) : (
                        <span className="flex gap-1">
                          <button
                            className="btn px-2 py-1 text-xs"
                            onClick={() => secure(s.findingId!, 'secured')}
                          >
                            Secured
                          </button>
                          <Link className="btn px-2 py-1 text-xs" to={`/findings/${s.findingId}`}>
                            Details
                          </Link>
                        </span>
                      )
                    ) : (
                      <span className="text-xs text-muted">not monitored</span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {sites.some((s) => !s.findingId) && (
        <Banner tone="info">
          Some of these services aren't being tracked yet. Add this email on the New Scan page and
          run a scan to track and tick them off.
        </Banner>
      )}
    </div>
  );
}
