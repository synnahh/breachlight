import type { ReactNode } from 'react';
import type { Confidence, Severity } from '../../shared/types';

const SEV_CLASS: Record<Severity | 'secured', string> = {
  critical: 'bg-critical/15 text-critical border border-critical/30',
  high: 'bg-high/15 text-high border border-high/30',
  medium: 'bg-medium/15 text-medium border border-medium/30',
  low: 'bg-low/15 text-low border border-low/30',
  secured: 'bg-secured/15 text-secured border border-secured/30',
};

export function SeverityBadge({ severity }: { severity: Severity | 'secured' }) {
  return <span className={`pill ${SEV_CLASS[severity]}`}>{severity}</span>;
}

export function ConfidenceBadge({ confidence }: { confidence: Confidence }) {
  const cls =
    confidence === 'high'
      ? 'border-secured/30 text-secured'
      : confidence === 'medium'
        ? 'border-medium/30 text-medium'
        : 'border-border text-muted';
  return <span className={`pill border ${cls}`}>confidence: {confidence}</span>;
}

export function StatCard({
  label,
  value,
  tone,
  sub,
}: {
  label: string;
  value: ReactNode;
  tone?: Severity | 'accent' | 'secured';
  sub?: ReactNode;
}) {
  const toneClass =
    tone === 'critical'
      ? 'text-critical'
      : tone === 'high'
        ? 'text-high'
        : tone === 'medium'
          ? 'text-medium'
          : tone === 'low'
            ? 'text-low'
            : tone === 'secured'
              ? 'text-secured'
              : tone === 'accent'
                ? 'text-accent'
                : 'text-text';
  return (
    <div className="card">
      <div className="text-xs font-medium uppercase tracking-wide text-muted">{label}</div>
      <div className={`mt-2 text-3xl font-semibold ${toneClass}`}>{value}</div>
      {sub && <div className="mt-1 text-xs text-muted">{sub}</div>}
    </div>
  );
}

const BAND_COLOR: Record<string, string> = {
  critical: '#ef4444',
  poor: '#f97316',
  fair: '#eab308',
  good: '#22c55e',
  strong: '#22c55e',
};

export function ScoreRing({ score, band }: { score: number; band: string }) {
  const color = BAND_COLOR[band] ?? '#38bdf8';
  const circumference = 2 * Math.PI * 42;
  const offset = circumference * (1 - score / 100);
  return (
    <div className="relative h-32 w-32 shrink-0">
      <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90">
        <circle cx="50" cy="50" r="42" fill="none" stroke="#243040" strokeWidth="10" />
        <circle
          cx="50"
          cy="50"
          r="42"
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-2xl font-bold" style={{ color }}>
          {score}
        </span>
        <span className="text-[10px] uppercase tracking-wide text-muted">/ 100</span>
      </div>
    </div>
  );
}

export function ProgressBar({ percent }: { percent: number }) {
  const p = Math.max(0, Math.min(100, percent));
  return (
    <div className="h-2.5 w-full overflow-hidden rounded-full bg-surface-2">
      <div
        className="h-full rounded-full bg-secured transition-all"
        style={{ width: `${p}%` }}
        role="progressbar"
        aria-valuenow={p}
        aria-valuemin={0}
        aria-valuemax={100}
      />
    </div>
  );
}

export function Section({
  title,
  actions,
  children,
}: {
  title: string;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-lg font-semibold">{title}</h2>
        {actions}
      </div>
      {children}
    </section>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="card text-center text-sm text-muted">{children}</div>;
}

export function Banner({
  tone = 'info',
  children,
}: {
  tone?: 'info' | 'warn' | 'error' | 'demo' | 'success';
  children: ReactNode;
}) {
  const cls = {
    info: 'border-accent/30 bg-accent/10 text-accent',
    warn: 'border-medium/30 bg-medium/10 text-medium',
    error: 'border-critical/30 bg-critical/10 text-critical',
    demo: 'border-low/30 bg-low/10 text-low',
    success: 'border-secured/30 bg-secured/10 text-secured',
  }[tone];
  return (
    <div className={`rounded-lg border px-4 py-3 text-sm ${cls}`} role="status">
      {children}
    </div>
  );
}

export function formatDate(value: string | null | undefined): string {
  if (!value) return 'Unknown / Not provided';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' });
}

/**
 * Breach dates from some sources are year-precision only (stored as YYYY-01-01).
 * Show just the year in that case rather than a misleading exact day.
 */
export function formatBreachDate(value: string | null | undefined): string {
  if (!value) return 'Unknown / Not provided';
  if (/^\d{4}-01-01(T00:00:00)?/.test(value)) return value.slice(0, 4);
  return formatDate(value);
}
export function formatDateTime(value: string | null | undefined): string {
  if (!value) return 'Never';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString();
}
export function yearOf(value: string | null | undefined): string {
  if (!value) return '—';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? '—' : String(d.getUTCFullYear());
}
