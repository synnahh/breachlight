import { useState } from 'react';
import type { BreachFinding, FindingStatus } from '../../shared/types';
import { ConfidenceBadge, SeverityBadge, formatBreachDate, formatDate } from './ui';
import RemediationWizard from './RemediationWizard';

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex justify-between gap-4 py-1 text-sm">
      <span className="text-muted">{label}</span>
      <span className="text-right">{value}</span>
    </div>
  );
}
const yn = (v: boolean) => (v ? 'Yes' : 'No');

export default function FindingDetail({
  finding,
  onStatus,
  onRefreshNeeded,
}: {
  finding: BreachFinding;
  onStatus: (id: string, s: FindingStatus) => void;
  onRefreshNeeded: () => void;
}) {
  const [wizard, setWizard] = useState(false);
  const f = finding;

  return (
    <div className="grid gap-4 border-t border-border pt-4 md:grid-cols-2">
      <div>
        <div className="mb-2 flex flex-wrap items-center gap-2">
          <SeverityBadge severity={f.status === 'secured' ? 'secured' : f.severity} />
          <ConfidenceBadge confidence={f.confidence} />
          <span className="pill border border-border text-muted">
            {f.associationType === 'confirmed'
              ? 'Confirmed breach exposure'
              : 'Possible service association'}
          </span>
          {f.isDemoData && (
            <span className="pill border border-low/30 bg-low/10 text-low">demo</span>
          )}
        </div>

        <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">
          Breach details
        </h4>
        <Row label="Service" value={f.service} />
        <Row label="Website" value={f.domain || 'Unknown / Not provided'} />
        <Row label="Email" value={f.email} />
        <Row label="Breach name" value={f.breachName} />
        <Row label="Breach date" value={formatBreachDate(f.breachDate)} />
        <Row label="Disclosed" value={formatDate(f.disclosureDate)} />
        <Row label="First observed" value={formatDate(f.firstSeenDate)} />
        <Row label="Accounts affected" value={f.pwnCount ? f.pwnCount.toLocaleString() : 'Unknown'} />
        <Row label="Industry" value={f.industry || 'Unknown'} />
        <Row label="Source" value={f.source} />
        <Row label="Current status" value={f.status} />

        <h4 className="mb-1 mt-3 text-xs font-semibold uppercase tracking-wide text-muted">
          Data exposed
        </h4>
        {f.dataClasses.length ? (
          <ul className="flex flex-wrap gap-1">
            {f.dataClasses.map((c) => (
              <li key={c} className="pill border border-border text-muted">
                {c}
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-muted">Unknown / Not provided</p>
        )}
        <div className="mt-2">
          <Row label="Password data involved" value={yn(f.passwordExposed)} />
          {f.passwordRisk && <Row label="Password format" value={f.passwordRisk} />}
          <Row label="Username involved" value={yn(f.usernameExposed)} />
          <Row label="Phone involved" value={yn(f.phoneExposed)} />
          <Row label="IP address involved" value={yn(f.ipExposed)} />
          <Row label="Location involved" value={yn(f.locationExposed)} />
        </div>
      </div>

      <div>
        <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">
          Why this matters
        </h4>
        <p className="text-sm text-muted">{f.whyItMatters}</p>
        <details className="mt-2 text-xs text-muted">
          <summary className="cursor-pointer">How this risk level was decided</summary>
          <ul className="ml-4 mt-1 list-disc">
            {f.severityReasons.map((r) => (
              <li key={r}>{r}</li>
            ))}
            <li>Confidence: {f.confidenceReason}</li>
          </ul>
        </details>

        <h4 className="mb-1 mt-3 text-xs font-semibold uppercase tracking-wide text-muted">
          What to do
        </h4>
        <ol className="list-inside list-decimal space-y-1 text-sm">
          {f.recommendations.map((r) => (
            <li key={r.code}>
              {r.label}
              <span className="block pl-4 text-xs text-muted">{r.detail}</span>
            </li>
          ))}
        </ol>

        {f.links.length > 0 && (
          <>
            <h4 className="mb-1 mt-3 text-xs font-semibold uppercase tracking-wide text-muted">
              Where to go
            </h4>
            <ul className="space-y-1 text-sm">
              {f.links.map((l) => (
                <li key={l.url}>
                  <a
                    href={l.url}
                    target="_blank"
                    rel="noreferrer noopener"
                    className="text-accent underline"
                  >
                    {l.label}
                  </a>
                  {l.derived && <span className="text-xs text-muted"> (derived link)</span>}
                </li>
              ))}
            </ul>
          </>
        )}

        {f.description && <p className="mt-3 text-xs text-muted">{f.description}</p>}

        <div className="mt-4 flex flex-wrap gap-2">
          <button className="btn btn-primary" onClick={() => setWizard(true)}>
            Start remediation
          </button>
          {(['open', 'in_progress', 'secured'] as FindingStatus[]).map((s) => (
            <button
              key={s}
              className={`btn ${f.status === s ? 'btn-primary' : ''}`}
              onClick={() => onStatus(f.id, s)}
            >
              {s === 'in_progress'
                ? 'In progress'
                : s === 'secured'
                  ? 'Mark secured'
                  : 'Needs action'}
            </button>
          ))}
        </div>
      </div>

      {wizard && (
        <RemediationWizard
          finding={f}
          onClose={() => setWizard(false)}
          onSecured={() => {
            setWizard(false);
            onRefreshNeeded();
          }}
        />
      )}
    </div>
  );
}
