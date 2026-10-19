import { useEffect, useState } from 'react';
import { api } from '../api';
import type { CorrelationReport } from '../../shared/types';
import { Banner, Section, SeverityBadge } from '../components/ui';

export default function Timeline() {
  const [c, setC] = useState<CorrelationReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.correlation().then(setC).catch((e) => setError(e.message));
  }, []);

  if (error) return <Banner tone="error">{error}</Banner>;
  if (!c) return <div className="card text-muted">Loading…</div>;

  const years = [...new Set(c.timeline.map((t) => t.year))].sort();

  return (
    <div className="space-y-6">
      <Section title="Exposure timeline">
        {c.timeline.length === 0 ? (
          <div className="card text-sm text-muted">
            No dated exposures yet. Run a Standard or Deep scan.
          </div>
        ) : (
          <div className="card space-y-3">
            {years.map((y) => (
              <div key={y} className="flex gap-4">
                <div className="w-14 shrink-0 font-mono text-sm text-muted">{y}</div>
                <div className="flex flex-1 flex-wrap gap-2">
                  {c.timeline
                    .filter((t) => t.year === y)
                    .map((t, i) => (
                      <span
                        key={t.service + i}
                        className="inline-flex items-center gap-1 rounded-lg border border-border bg-bg px-2 py-1 text-xs"
                      >
                        {t.service}
                        {t.passwordInvolved && <span className="text-critical">· pw</span>}
                        <SeverityBadge severity={t.severity} />
                      </span>
                    ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </Section>

      <Section title="Cross-breach correlation">
        <div className="card space-y-2 text-sm">
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            <Stat label="Breaches" value={c.breachCount} />
            <Stat label="With passwords" value={c.passwordBreachCount} />
            <Stat label="After first pw breach" value={c.passwordBreachesAfterFirst} />
            <Stat label="Span" value={`${yr(c.earliestBreach)}–${yr(c.latestBreach)}`} />
          </div>
          <ul className="ml-4 list-disc space-y-1 text-muted">
            {c.patterns.map((p) => (
              <li key={p}>{p}</li>
            ))}
          </ul>
          <p className="text-xs text-muted">
            Correlation uses cautious language — it never asserts a password was actually reused, only
            that the pattern of exposures raises risk.
          </p>
        </div>
      </Section>

      {c.perEmail.length > 1 && (
        <Section title="Cross-email findings">
          <div className="card space-y-3 text-sm">
            {c.perEmail.map((e) => (
              <div key={e.email}>
                <div className="font-medium">{e.email}</div>
                <div className="text-xs text-muted">{e.services.join(', ') || 'none'}</div>
              </div>
            ))}
          </div>
        </Section>
      )}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-border bg-bg p-2">
      <div className="text-[10px] uppercase tracking-wide text-muted">{label}</div>
      <div className="text-lg font-semibold">{value}</div>
    </div>
  );
}
function yr(s: string | null) {
  return s ? new Date(s).getUTCFullYear() : '—';
}
