import type {
  BreachFinding,
  ComboResponse,
  CorrelationReport,
  DashboardSummary,
  DomainSecurityInfo,
  EmailRecord,
  PasswordExposureSite,
  PrivacyReport,
  ProviderRuntimeStatus,
  Scan,
  ScanDepth,
  ScanHistoryEntry,
  ScanOptions,
  SecurityAction,
} from '../shared/types';

const BASE = '/api';

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(BASE + path, {
    headers: { 'Content-Type': 'application/json' },
    ...init,
  });
  const text = await res.text();
  let payload: any = null;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    /* non-JSON */
  }
  if (!res.ok || (payload && payload.ok === false)) {
    throw new Error(payload?.error || `Request failed (${res.status})`);
  }
  return (payload?.data ?? payload) as T;
}

export interface StatusResponse {
  baselineReady: boolean;
  optionalProvidersConfigured: number;
  passwordCheckEnabled: boolean;
  hibpConfigured: boolean;
  demoProviderEnabled: boolean;
}

export const api = {
  status: () => request<StatusResponse>('/status'),
  dataSources: () => request<ProviderRuntimeStatus[]>('/data-sources'),
  dashboard: () => request<DashboardSummary>('/dashboard'),
  privacy: () => request<PrivacyReport>('/privacy'),
  settings: () =>
    request<{ values: Record<string, string>; config: Record<string, unknown> }>('/settings'),
  saveSetting: (key: string, value: string) =>
    request(`/settings/${key}`, { method: 'PUT', body: JSON.stringify({ value }) }),

  listEmails: () => request<EmailRecord[]>('/emails'),
  addEmail: (email: string, label?: string) =>
    request<EmailRecord>('/emails', { method: 'POST', body: JSON.stringify({ email, label }) }),
  setEmailLabel: (id: string, label: string | null) =>
    request<EmailRecord>(`/emails/${id}`, { method: 'PATCH', body: JSON.stringify({ label }) }),
  removeEmail: (id: string) => request(`/emails/${id}`, { method: 'DELETE' }),

  startScan: (emailIds: string[], depth: ScanDepth, options?: Partial<ScanOptions>) =>
    request<{ scanId: string }>('/scans', {
      method: 'POST',
      body: JSON.stringify({ emailIds, depth, options }),
    }),
  getScan: (id: string) => request<{ scan: Scan; findings: BreachFinding[] }>(`/scans/${id}`),
  scanHistory: () => request<ScanHistoryEntry[]>('/scans'),
  allScans: () => request<Scan[]>('/scans/all'),
  exportUrl: (scanId: string, format: 'json' | 'csv') =>
    `${BASE}/scans/${scanId}/export?format=${format}`,

  listFindings: () => request<BreachFinding[]>('/findings'),
  getFinding: (id: string) => request<BreachFinding>(`/findings/${id}`),
  correlation: () => request<CorrelationReport>('/findings/correlation'),
  setFindingStatus: (id: string, status: BreachFinding['status']) =>
    request<BreachFinding>(`/findings/${id}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    }),
  bulkFindingStatus: (ids: string[], status: BreachFinding['status']) =>
    request<{ updated: number }>('/findings/bulk-status', {
      method: 'POST',
      body: JSON.stringify({ ids, status }),
    }),

  listActions: () => request<SecurityAction[]>('/actions'),
  addAction: (title: string, description?: string) =>
    request('/actions', { method: 'POST', body: JSON.stringify({ title, description }) }),
  setActionStatus: (id: string, status: SecurityAction['status']) =>
    request<SecurityAction>(`/actions/${id}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    }),

  domainSecurity: () => request<DomainSecurityInfo[]>('/domain-security'),

  passwordRange: async (prefix: string): Promise<string> => {
    const res = await fetch(`${BASE}/password/range/${prefix}`);
    if (!res.ok) {
      let msg = `Password service error (${res.status})`;
      try {
        msg = (await res.json()).error || msg;
      } catch {
        /* ignore */
      }
      throw new Error(msg);
    }
    return res.text();
  },

  combo: (email: string, prefix: string, suffix: string) =>
    request<ComboResponse>('/combo', {
      method: 'POST',
      body: JSON.stringify({ email, prefix, suffix }),
    }),

  passwordExposures: () => request<PasswordExposureSite[]>('/password-exposures'),

  wipe: () => request('/wipe', { method: 'POST' }),
};
