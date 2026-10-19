import { useEffect, useState } from 'react';
import { api } from '../api';
import type { Scan, ScanHistoryEntry } from '../../shared/types';
import { Banner, Section, formatDateTime } from '../components/ui';

export default function ScanHistory() {
  const [history, setHistory] = useState<ScanHistoryEntry[]>([]);
  const [all, setAll] = useState<Scan[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.scanHistory().then(setHistory).catch((e) => setError(e.message));
    api.allScans().then(setAll).catch(() => {});
  }, []);

  const latest = all.find((s) => s.status === 'complete');

  return (
    <div className="space-y-6">
      <Section title="Scan History">
        {error && <Banner tone="error">{error}</Banner>}
        {latest && (
          <div className="card flex flex-wrap items-center gap-3 text-sm">
            <span className="font-medium">Export latest report:</span>
            <a className="btn" href={api.exportUrl(latest.id, 'json')} download>
              JSON
            </a>
            <a className="btn" href={api.exportUrl(latest.id, 'csv')} download>
              CSV
            </a>
            <span className="text-xs text-muted">
              Reports contain breach metadata + remediation status only — never passwords.
            </span>
          </div>
        )}

        {history.length === 0 ? (
          <div className="card text-sm text-muted">No completed scans yet.</div>
        ) : (
          <div className="space-y-2">
            {history.map((h, i) => {
              const prev = history[i + 1];
              return (
                <div key={h.id} className="card space-y-1">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-medium">{formatDateTime(h.date)}</span>
                    <span className="pill border border-border text-muted">{h.depth}</span>
                  </div>
                  <div className="text-sm text-muted">
                    {h.exposures} exposure(s) · {h.unresolved} unresolved · coverage {h.coverage}% ·{' '}
                    {h.emailAddresses.join(', ')}
                  </div>
                  {prev && (
                    <div className="text-xs text-muted">
                      vs previous: {prev.exposures} → {h.exposures} exposures (
                      {h.exposures - prev.exposures >= 0 ? '+' : ''}
                      {h.exposures - prev.exposures}), {prev.unresolved - h.unresolved} more resolved.
                    </div>
                  )}
                  <div className="flex gap-2 pt-1">
                    <a className="btn" href={api.exportUrl(h.id, 'json')} download>
                      Export JSON
                    </a>
                    <a className="btn" href={api.exportUrl(h.id, 'csv')} download>
                      Export CSV
                    </a>
                  </div>
                </div>
              );
            })}
          </div>
        )}
        <p className="text-xs text-muted">
          “No longer returned by a provider” is not the same as “confirmed resolved”. A breach can
          drop out of a provider's results without your exposure changing.
        </p>
      </Section>
    </div>
  );
}
