import { useEffect, useState } from 'react';
import { api } from '../api';
import type { DomainSecurityInfo, ProviderRuntimeStatus } from '../../shared/types';
import { Banner, Section, formatDateTime } from '../components/ui';

const STATE_STYLE: Record<ProviderRuntimeStatus['state'], string> = {
  available: 'text-secured',
  optional: 'text-medium',
  rate_limited: 'text-medium',
  error: 'text-critical',
  disabled: 'text-muted',
};

export default function DataSources() {
  const [providers, setProviders] = useState<ProviderRuntimeStatus[]>([]);
  const [domains, setDomains] = useState<DomainSecurityInfo[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.dataSources().then(setProviders).catch((e) => setError(e.message));
    api.domainSecurity().then(setDomains).catch(() => {});
  }, []);

  return (
    <div className="space-y-6">
      <Section title="Data Sources">
        {error && <Banner tone="error">{error}</Banner>}
        <p className="text-sm text-muted">
          The scanner combines multiple legitimate sources. HIBP is one optional provider, not a
          single point of failure. Nothing here is hidden — provider limitations are shown.
        </p>
        <div className="space-y-2">
          {providers.map((p) => (
            <div key={p.id} className="card space-y-1">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-medium">
                  {p.state === 'available' ? '●' : '○'} {p.label}
                </span>
                <span className={`pill border border-border ${STATE_STYLE[p.state]}`}>
                  {p.state.replace('_', ' ')}
                </span>
              </div>
              <div className="grid gap-x-6 gap-y-1 text-xs text-muted sm:grid-cols-2">
                <span>Kind: {p.kind}</span>
                <span>
                  Auth: {p.requiresAuth ? (p.authenticated ? 'authenticated' : 'needs key') : 'none required'}
                </span>
                <span>Configured: {p.configured ? 'yes' : 'no'}</span>
                <span>Last success: {formatDateTime(p.lastSuccessAt)}</span>
                {p.rateLimitedUntil && (
                  <span className="text-medium">
                    Rate limited until {formatDateTime(p.rateLimitedUntil)}
                  </span>
                )}
                {p.lastError && <span className="text-critical">Last error: {p.lastError}</span>}
              </div>
              <p className="text-xs text-muted">{p.note}</p>
              {p.isDemoData && (
                <p className="text-xs text-low">This source produces synthetic data only.</p>
              )}
            </div>
          ))}
        </div>
      </Section>

      {domains.length > 0 && (
        <Section title="Domain security posture">
          <p className="text-sm text-muted">
            Passive checks on the domains of breached services (Deep/Maximum scans). No probing of
            paths or private infrastructure.
          </p>
          <div className="card overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs uppercase tracking-wide text-muted">
                  <th className="pb-2 pr-4">Domain</th>
                  <th className="pb-2 pr-4">Grade</th>
                  <th className="pb-2 pr-4">HTTPS</th>
                  <th className="pb-2 pr-4">HSTS</th>
                  <th className="pb-2">Notes</th>
                </tr>
              </thead>
              <tbody>
                {domains.map((d) => (
                  <tr key={d.domain} className="border-t border-border align-top">
                    <td className="py-2 pr-4">{d.domain}</td>
                    <td className="py-2 pr-4 font-semibold">{d.grade}</td>
                    <td className="py-2 pr-4">{d.https ? '✓' : '—'}</td>
                    <td className="py-2 pr-4">{d.hsts ? '✓' : '—'}</td>
                    <td className="py-2 text-xs text-muted">{d.notes.join('; ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Section>
      )}
    </div>
  );
}
