import { useState } from 'react';
import type { BreachFinding } from '../../shared/types';
import { api } from '../api';
import { Banner } from './ui';

export default function RemediationWizard({
  finding,
  onClose,
  onSecured,
}: {
  finding: BreachFinding;
  onClose: () => void;
  onSecured: () => void;
}) {
  const [done, setDone] = useState<Record<string, boolean>>({});
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const steps = finding.wizardSteps;
  const allDone = steps.every((s) => done[s.key]);

  async function complete() {
    setSaving(true);
    setError(null);
    try {
      await api.setFindingStatus(finding.id, 'secured');
      onSecured();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4"
      role="dialog"
      aria-modal="true"
      aria-label={`Securing ${finding.service}`}
      onClick={onClose}
    >
      <div
        className="my-8 w-full max-w-lg rounded-xl border border-border bg-surface p-5"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-lg font-semibold">Securing {finding.service}</h3>
          <button className="btn" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </div>

        <ol className="space-y-3">
          {steps.map((s, i) => (
            <li key={s.key} className="rounded-lg border border-border bg-bg p-3">
              <label className="flex items-start gap-3">
                <input
                  type="checkbox"
                  className="mt-1"
                  checked={!!done[s.key]}
                  onChange={(e) => setDone((d) => ({ ...d, [s.key]: e.target.checked }))}
                />
                <span>
                  <span className="text-sm font-medium">
                    Step {i + 1}: {s.title}
                  </span>
                  <span className="mt-0.5 block text-xs text-muted">{s.detail}</span>
                  {s.link && (
                    <a
                      href={s.link.url}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="mt-1 inline-block text-xs text-accent underline"
                    >
                      Open {s.link.label}
                      {s.link.derived ? ' (derived link)' : ''}
                    </a>
                  )}
                </span>
              </label>
            </li>
          ))}
        </ol>

        {error && (
          <div className="mt-3">
            <Banner tone="error">{error}</Banner>
          </div>
        )}

        <div className="mt-4 flex items-center justify-between gap-2">
          <span className="text-xs text-muted">
            {Object.values(done).filter(Boolean).length}/{steps.length} steps checked
          </span>
          <button className="btn btn-primary" onClick={complete} disabled={saving || !allDone}>
            {saving ? 'Saving…' : 'Complete security review'}
          </button>
        </div>
        <p className="mt-2 text-[11px] text-muted">
          Only your progress is stored — never any password or credential.
        </p>
      </div>
    </div>
  );
}
