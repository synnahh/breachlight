import { useEffect, useMemo, useState } from 'react';
import { useParams, useSearchParams } from 'react-router-dom';
import { api } from '../api';
import type { BreachFinding, FindingStatus, Severity } from '../../shared/types';
import { Banner, Section, SeverityBadge, formatBreachDate, formatDate } from '../components/ui';
import FindingDetail from '../components/FindingDetail';

type Filter =
  | 'all'
  | Severity
  | 'needs_action'
  | 'in_progress'
  | 'secured'
  | 'password'
  | 'email'
  | 'sensitive';

const FILTERS: Filter[] = [
  'all',
  'critical',
  'high',
  'medium',
  'low',
  'needs_action',
  'in_progress',
  'secured',
  'password',
  'email',
  'sensitive',
];

export default function Findings() {
  const { id } = useParams();
  const [params] = useSearchParams();
  const initialFilter = params.get('filter');
  const [findings, setFindings] = useState<BreachFinding[]>([]);
  const [filter, setFilter] = useState<Filter>(
    FILTERS.includes(initialFilter as Filter) ? (initialFilter as Filter) : 'all',
  );
  const [query, setQuery] = useState('');
  const [openId, setOpenId] = useState<string | null>(id ?? null);
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [view, setView] = useState<'cards' | 'table'>('cards');
  const [error, setError] = useState<string | null>(null);

  const load = () => api.listFindings().then(setFindings).catch((e) => setError(e.message));
  useEffect(() => {
    load();
  }, []);
  useEffect(() => {
    if (id) setOpenId(id);
  }, [id]);

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return findings.filter((f) => {
      if (filter === 'needs_action' && f.status !== 'open') return false;
      if (filter === 'in_progress' && f.status !== 'in_progress') return false;
      if (filter === 'secured' && f.status !== 'secured') return false;
      if (['critical', 'high', 'medium', 'low'].includes(filter) && f.severity !== filter)
        return false;
      if (filter === 'password' && !f.passwordExposed) return false;
      if (filter === 'email' && !f.emailExposed) return false;
      if (
        filter === 'sensitive' &&
        !(f.financialExposed || f.governmentIdExposed || f.sensitivePersonalExposed || f.securityQuestionsExposed)
      )
        return false;
      if (!q) return true;
      return [f.service, f.email, f.breachName, f.domain, f.breachDate, f.disclosureDate]
        .filter(Boolean)
        .some((v) => String(v).toLowerCase().includes(q));
    });
  }, [findings, filter, query]);

  async function setStatus(fid: string, status: FindingStatus) {
    await api.setFindingStatus(fid, status);
    await load();
  }
  async function bulk(status: FindingStatus) {
    if (checked.size === 0) return;
    await api.bulkFindingStatus([...checked], status);
    setChecked(new Set());
    await load();
  }
  function toggleCheck(fid: string) {
    setChecked((s) => {
      const n = new Set(s);
      n.has(fid) ? n.delete(fid) : n.add(fid);
      return n;
    });
  }

  const counts = { needsAction: findings.filter((f) => f.status !== 'secured').length };

  return (
    <Section
      title={`Security Findings — ${findings.length} service(s), ${counts.needsAction} need action`}
      actions={
        <div className="flex gap-2">
          <button
            className="btn"
            onClick={() => setView(view === 'cards' ? 'table' : 'cards')}
          >
            {view === 'cards' ? 'Table view' : 'Card view'}
          </button>
        </div>
      }
    >
      {error && <Banner tone="error">{error}</Banner>}

      <div className="flex flex-wrap items-center gap-2">
        {FILTERS.map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`pill border ${
              filter === f ? 'border-accent bg-accent/15 text-accent' : 'border-border text-muted'
            }`}
          >
            {f.replace('_', ' ')}
          </button>
        ))}
        <input
          className="input ml-auto max-w-xs"
          placeholder="Search service, email, breach, date…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label="Search findings"
        />
      </div>

      {checked.size > 0 && (
        <div className="card flex flex-wrap items-center gap-2 text-sm">
          <span>{checked.size} selected</span>
          <button className="btn" onClick={() => bulk('in_progress')}>
            Mark reviewed (in progress)
          </button>
          <button className="btn btn-primary" onClick={() => bulk('secured')}>
            Mark secured
          </button>
          <button className="btn" onClick={() => setChecked(new Set())}>
            Clear
          </button>
        </div>
      )}

      {visible.length === 0 ? (
        <div className="card text-sm text-muted">
          No findings match. Run a scan from the New Scan page.
        </div>
      ) : view === 'table' ? (
        <div className="card overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase tracking-wide text-muted">
                <th className="pb-2 pr-2"></th>
                <th className="pb-2 pr-4">Service</th>
                <th className="pb-2 pr-4">Exposure</th>
                <th className="pb-2 pr-4">Date</th>
                <th className="pb-2 pr-4">Risk</th>
                <th className="pb-2">Status</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((f) => (
                <tr
                  key={f.id}
                  className="cursor-pointer border-t border-border hover:bg-surface-2"
                  onClick={() => setOpenId(openId === f.id ? null : f.id)}
                >
                  <td className="py-2 pr-2" onClick={(e) => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={checked.has(f.id)}
                      onChange={() => toggleCheck(f.id)}
                    />
                  </td>
                  <td className="py-2 pr-4">{f.service}</td>
                  <td className="py-2 pr-4">
                    {f.passwordExposed ? 'Password' : f.emailExposed ? 'Email' : 'Metadata'}
                  </td>
                  <td className="py-2 pr-4 text-muted">{formatBreachDate(f.breachDate)}</td>
                  <td className="py-2 pr-4">
                    <SeverityBadge severity={f.status === 'secured' ? 'secured' : f.severity} />
                  </td>
                  <td className="py-2 text-muted">{f.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {openId && findings.find((f) => f.id === openId) && (
            <div className="mt-4">
              <FindingDetail
                finding={findings.find((f) => f.id === openId)!}
                onStatus={setStatus}
                onRefreshNeeded={load}
              />
            </div>
          )}
        </div>
      ) : (
        <div className="space-y-3">
          {visible.map((f) => (
            <div key={f.id} className="card">
              <div className="flex items-start gap-3">
                <input
                  type="checkbox"
                  className="mt-1"
                  checked={checked.has(f.id)}
                  onChange={() => toggleCheck(f.id)}
                  aria-label={`Select ${f.service}`}
                />
                <button
                  className="flex w-full items-center justify-between gap-3 text-left"
                  onClick={() => setOpenId(openId === f.id ? null : f.id)}
                  aria-expanded={openId === f.id}
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="truncate font-semibold">{f.service}</span>
                      {f.passwordExposed && (
                        <span className="pill border border-critical/30 bg-critical/10 text-critical">
                          password
                        </span>
                      )}
                      {f.isDemoData && (
                        <span className="pill border border-low/30 bg-low/10 text-low">demo</span>
                      )}
                    </div>
                    <div className="truncate text-xs text-muted">
                      {f.email} · {f.domain || 'domain unknown'} · {formatBreachDate(f.breachDate)}
                    </div>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    <SeverityBadge severity={f.status === 'secured' ? 'secured' : f.severity} />
                    <span aria-hidden className="text-muted">
                      {openId === f.id ? '▲' : '▼'}
                    </span>
                  </div>
                </button>
              </div>
              {openId === f.id && (
                <FindingDetail finding={f} onStatus={setStatus} onRefreshNeeded={load} />
              )}
            </div>
          ))}
        </div>
      )}

      <p className="text-xs text-muted">
        Export a full report from the <a className="underline" href="/history">Scan History</a> page.
      </p>
    </Section>
  );
}
