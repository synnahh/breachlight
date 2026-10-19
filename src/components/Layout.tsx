import { NavLink, Outlet } from 'react-router-dom';
import { useEffect, useState } from 'react';
import { api, type StatusResponse } from '../api';

const NAV = [
  { to: '/', label: 'Dashboard', end: true },
  { to: '/scan', label: 'New Scan' },
  { to: '/findings', label: 'Findings' },
  { to: '/timeline', label: 'Timeline' },
  { to: '/actions', label: 'Security Actions' },
  { to: '/tools', label: 'Password Tools' },
  { to: '/history', label: 'Scan History' },
  { to: '/sources', label: 'Data Sources' },
  { to: '/settings', label: 'Settings' },
];

export default function Layout() {
  const [status, setStatus] = useState<StatusResponse | null>(null);

  useEffect(() => {
    api.status().then(setStatus).catch(() => setStatus(null));
  }, []);

  return (
    <div className="mx-auto flex min-h-screen max-w-6xl flex-col gap-6 px-4 py-6 md:flex-row md:px-6">
      <aside className="md:w-56 md:shrink-0">
        <div className="mb-6 flex items-center gap-2">
          <span aria-hidden className="text-xl">🛡️</span>
          <span className="font-semibold">Security Scanner</span>
        </div>
        <nav className="flex flex-wrap gap-1 md:flex-col">
          {NAV.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              end={n.end}
              className={({ isActive }) =>
                `rounded-lg px-3 py-2 text-sm ${
                  isActive
                    ? 'bg-surface-2 font-medium text-text'
                    : 'text-muted hover:bg-surface hover:text-text'
                }`
              }
            >
              {n.label}
            </NavLink>
          ))}
        </nav>
        {status && (
          <div className="mt-6 hidden rounded-lg border border-border bg-surface p-3 text-xs text-muted md:block">
            <div>
              Baseline:{' '}
              <span className={status.baselineReady ? 'text-secured' : 'text-medium'}>
                {status.baselineReady ? 'ready' : 'limited'}
              </span>
            </div>
            <div>
              Optional providers: {status.optionalProvidersConfigured}
              {status.hibpConfigured ? '' : ' · HIBP not set'}
            </div>
            {status.demoProviderEnabled && <div className="text-low">Demo provider ON</div>}
          </div>
        )}
      </aside>

      <main className="min-w-0 flex-1 space-y-6">
        {status && !status.baselineReady && (
          <div className="rounded-lg border border-medium/30 bg-medium/10 px-4 py-2 text-xs text-medium">
            Baseline sources are limited — check Data Sources. Scans still run with whatever is available.
          </div>
        )}
        {status?.demoProviderEnabled && (
          <div className="rounded-lg border border-low/30 bg-low/10 px-4 py-2 text-xs font-semibold uppercase tracking-wide text-low">
            Demo provider enabled — some results may be synthetic (each is marked DEMO)
          </div>
        )}
        <Outlet />
      </main>
    </div>
  );
}
