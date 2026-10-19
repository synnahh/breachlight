import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import type { ActionStatus, SecurityAction } from '../../shared/types';
import { Banner, ProgressBar, Section } from '../components/ui';

const CYCLE: Record<ActionStatus, ActionStatus> = {
  not_started: 'in_progress',
  in_progress: 'completed',
  completed: 'not_started',
  not_applicable: 'not_started',
};
const LABEL: Record<ActionStatus, string> = {
  not_started: 'Not started',
  in_progress: 'In progress',
  completed: 'Completed',
  not_applicable: 'N/A',
};

export default function SecurityActions() {
  const [actions, setActions] = useState<SecurityAction[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [title, setTitle] = useState('');
  const [hideDone, setHideDone] = useState(false);

  const load = () => api.listActions().then(setActions).catch((e) => setError(e.message));
  useEffect(() => {
    load();
  }, []);

  const applicable = actions.filter((a) => a.status !== 'not_applicable');
  const completed = applicable.filter((a) => a.status === 'completed').length;
  const percent = applicable.length ? Math.round((completed / applicable.length) * 100) : 100;

  const groups = useMemo(() => {
    const list = hideDone ? actions.filter((a) => a.status !== 'completed') : actions;
    return {
      urgent: list.filter((a) => a.priority === 'urgent'),
      recommended: list.filter((a) => a.priority === 'recommended'),
    };
  }, [actions, hideDone]);

  async function set(a: SecurityAction, status: ActionStatus) {
    await api.setActionStatus(a.id, status);
    await load();
  }
  async function addCustom(e: React.FormEvent) {
    e.preventDefault();
    if (!title.trim()) return;
    await api.addAction(title.trim());
    setTitle('');
    await load();
  }

  return (
    <Section
      title="Security Actions"
      actions={
        <label className="flex items-center gap-2 text-sm text-muted">
          <input type="checkbox" checked={hideDone} onChange={(e) => setHideDone(e.target.checked)} />
          Hide completed
        </label>
      }
    >
      {error && <Banner tone="error">{error}</Banner>}

      <div className="card space-y-2">
        <div className="flex items-center justify-between text-sm">
          <span className="font-medium">Security progress</span>
          <span className="text-muted">
            {completed} / {applicable.length} complete
          </span>
        </div>
        <ProgressBar percent={percent} />
      </div>

      <p className="text-sm text-muted">
        Tasks are generated automatically from findings that need action. Click a task's status to
        move it Not started → In progress → Completed. Mark irrelevant tasks as N/A.
      </p>

      <form onSubmit={addCustom} className="flex gap-2">
        <input
          className="input"
          placeholder="Add your own task…"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
        />
        <button className="btn shrink-0" type="submit">
          Add
        </button>
      </form>

      <Group title="Urgent" items={groups.urgent} onSet={set} />
      <Group title="Recommended" items={groups.recommended} onSet={set} />
      {actions.length === 0 && (
        <div className="card text-sm text-muted">No actions yet — run a scan.</div>
      )}
    </Section>
  );

  function Group({
    title,
    items,
    onSet,
  }: {
    title: string;
    items: SecurityAction[];
    onSet: (a: SecurityAction, s: ActionStatus) => void;
  }) {
    if (items.length === 0) return null;
    return (
      <div className="space-y-2">
        <h3 className={`font-semibold ${title === 'Urgent' ? 'text-critical' : ''}`}>{title}</h3>
        {items.map((a) => (
          <div key={a.id} className="card flex items-start gap-3">
            <button
              className={`mt-0.5 h-5 w-5 shrink-0 rounded border text-xs ${
                a.status === 'completed'
                  ? 'border-secured bg-secured/30 text-secured'
                  : a.status === 'in_progress'
                    ? 'border-medium bg-medium/20 text-medium'
                    : a.status === 'not_applicable'
                      ? 'border-border text-muted'
                      : 'border-border'
              }`}
              onClick={() => onSet(a, CYCLE[a.status])}
              aria-label={`Advance status for ${a.title}`}
              title={LABEL[a.status]}
            >
              {a.status === 'completed' ? '✓' : a.status === 'in_progress' ? '…' : ''}
            </button>
            <div className={`flex-1 ${a.status === 'completed' ? 'opacity-60' : ''}`}>
              <div className="text-sm font-medium">{a.title}</div>
              {a.description && <div className="text-xs text-muted">{a.description}</div>}
              <div className="mt-1 flex items-center gap-2 text-[11px] uppercase tracking-wide text-muted">
                <span>{LABEL[a.status]}</span>
                {a.status !== 'not_applicable' ? (
                  <button className="underline" onClick={() => onSet(a, 'not_applicable')}>
                    mark N/A
                  </button>
                ) : (
                  <button className="underline" onClick={() => onSet(a, 'not_started')}>
                    reactivate
                  </button>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>
    );
  }
}
