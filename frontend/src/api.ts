import {
  DashboardStats, AIMetrics, ThreatFeed, ThreatDistribution, CountryShare,
  ThreatActor, ThreatDetail, ThreatListResponse, ThreatCreateRequest,
  Agency, ShareCreate, ShareOut, AIAnalysis, AttackMapEntry, TopAttacker,
  GeoRiskEntry, EconomicIndicator, PlatformMetrics, AutoResponse,
  GraphData, SIEMLog, DarkwebEntry, BreachEntry,
} from './types';

const BASE_URL = process.env.REACT_APP_API_URL || '/api';

function getAuthHeaders(): Record<string, string> {
  try {
    const stored = localStorage.getItem('ictip_auth');
    if (stored) {
      const { access_token } = JSON.parse(stored);
      if (access_token) return { Authorization: `Bearer ${access_token}` };
    }
  } catch {}
  return {};
}

async function fetchJSON<T>(path: string, options?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    ...getAuthHeaders(),
    ...(options?.headers as Record<string, string> || {}),
  };
  const res = await fetch(`${BASE_URL}${path}`, { ...options, headers });
  if (res.status === 401) {
    localStorage.removeItem('ictip_auth');
    window.location.href = '/login';
    return undefined as unknown as T;
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `API error: ${res.status}`);
  }
  if (res.status === 204) return undefined as unknown as T;
  return res.json();
}

export const api = {
  // Dashboard
  getDashboardStats: () => fetchJSON<DashboardStats>('/dashboard/stats'),
  getAIMetrics: () => fetchJSON<AIMetrics>('/dashboard/ai-metrics'),
  getThreatFeed: (limit = 20) => fetchJSON<ThreatFeed[]>(`/threats/feed?limit=${limit}`),
  getThreatDistribution: () => fetchJSON<ThreatDistribution[]>('/threats/distribution'),
  getCountryShares: () => fetchJSON<CountryShare[]>('/countries/shares'),
  getThreatActors: () => fetchJSON<ThreatActor[]>('/threats/actors'),
  getAttackMap: () => fetchJSON<AttackMapEntry[]>('/dashboard/attack-map'),
  getTopAttackers: () => fetchJSON<TopAttacker[]>('/dashboard/top-attackers'),
  getGeoRisk: () => fetchJSON<GeoRiskEntry[]>('/dashboard/geo-risk'),
  getEconomicIndicators: () => fetchJSON<EconomicIndicator[]>('/dashboard/economic-indicators'),
  getPlatformMetrics: () => fetchJSON<PlatformMetrics>('/dashboard/platform-metrics'),

  // Threat CRUD
  createThreat: (body: ThreatCreateRequest) =>
    fetchJSON<ThreatDetail>('/threats', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  listThreats: (params: { page?: number; page_size?: number; severity?: string; threat_type?: string; search?: string }) => {
    const q = new URLSearchParams();
    if (params.page) q.set('page', String(params.page));
    if (params.page_size) q.set('page_size', String(params.page_size));
    if (params.severity) q.set('severity', params.severity);
    if (params.threat_type) q.set('threat_type', params.threat_type);
    if (params.search) q.set('search', params.search);
    return fetchJSON<ThreatListResponse>(`/threats?${q}`);
  },
  listFeeds: (params: { page?: number; page_size?: number; severity?: string; threat_type?: string; source?: string; search?: string }) => {
    const q = new URLSearchParams();
    if (params.page) q.set('page', String(params.page));
    if (params.page_size) q.set('page_size', String(params.page_size));
    if (params.severity) q.set('severity', params.severity);
    if (params.threat_type) q.set('threat_type', params.threat_type);
    if (params.source) q.set('source', params.source);
    if (params.search) q.set('search', params.search);
    return fetchJSON<ThreatListResponse>(`/feeds?${q}`);
  },
  getThreat: (id: number) => fetchJSON<ThreatDetail>(`/threats/${id}`),
  updateThreat: (id: number, body: Partial<ThreatCreateRequest>) =>
    fetchJSON<ThreatDetail>(`/threats/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  deleteThreat: (id: number) => fetchJSON<void>(`/threats/${id}`, { method: 'DELETE' }),

  // Agencies
  getAgencies: () => fetchJSON<Agency[]>('/agencies'),

  // Sharing
  shareThreat: (threatId: number, body: ShareCreate) =>
    fetchJSON<ShareOut[]>(`/threats/${threatId}/share`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  getThreatShares: (threatId: number) => fetchJSON<ShareOut[]>(`/threats/${threatId}/shares`),

  // AI Analysis
  analyzeThreat: (threatId: number) =>
    fetchJSON<AIAnalysis>(`/threats/${threatId}/analyze`, { method: 'POST' }),
  getThreatAnalysis: (threatId: number) => fetchJSON<AIAnalysis>(`/threats/${threatId}/analysis`),

  // Auto Response
  getAutoResponses: (threatId: number) =>
    fetchJSON<AutoResponse[]>(`/threats/${threatId}/auto-responses`),

  // Sharing - confirm
  confirmShare: (shareId: number) =>
    fetchJSON<ShareOut>(`/shares/${shareId}/confirm`, { method: 'PATCH' }),
  getSharingStats: () => fetchJSON<any>('/sharing/stats'),

  // STIX/TAXII
  getSTIXBundle: (threatId?: number) =>
    fetchJSON<any>(`/stix/bundle${threatId ? `?threat_id=${threatId}` : ''}`),
  getTAXIIInbound: () => fetchJSON<any[]>('/taxii/inbound/'),

  // PDF Reports
  downloadThreatReport: async (threatId: number): Promise<void> => {
    const headers = { ...getAuthHeaders() };
    const res = await fetch(`${BASE_URL}/reports/threat/${threatId}`, { headers });
    if (!res.ok) throw new Error(`Report error: ${res.status}`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `threat_report_${threatId}.pdf`;
    a.click();
    URL.revokeObjectURL(url);
  },
  downloadDailyReport: async (): Promise<void> => {
    const headers = { ...getAuthHeaders() };
    const res = await fetch(`${BASE_URL}/reports/daily`, { headers });
    if (!res.ok) throw new Error(`Report error: ${res.status}`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `daily_report.pdf`;
    a.click();
    URL.revokeObjectURL(url);
  },

  // YARA / Sigma Rules
  getYARARule: (threatId: number) =>
    fetchJSON<string>(`/rules/yara/${threatId}`),
  getSigmaRule: (threatId: number) =>
    fetchJSON<string>(`/rules/sigma/${threatId}`),
  getAllRules: (threatId: number) =>
    fetchJSON<{ threat_id: number; yara: string; sigma: string; generated_at: string }>(`/rules/all/${threatId}`),

  // IOC Relationship Graph
  getIOCGraph: (threatId: number) =>
    fetchJSON<GraphData>(`/graph/ioc/${threatId}`),
  getActorGraph: (actorName: string) =>
    fetchJSON<GraphData>(`/graph/actor/${encodeURIComponent(actorName)}`),
  getOverviewGraph: () =>
    fetchJSON<GraphData>('/graph/overview'),

  // Threat Trend Prediction
  getTrendData: () => fetchJSON<any>('/prediction/trend'),
  getForecast: () => fetchJSON<any>('/prediction/forecast'),
  getHotspot: () => fetchJSON<any>('/prediction/hotspot'),
  getActorActivity: () => fetchJSON<any>('/prediction/actor-activity'),

  // SIEM Webhook
  testSIEMWebhook: (url: string, format = 'json') =>
    fetchJSON<any>('/siem/webhook/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, format }),
    }),
  sendToSIEM: (threatId: number, url: string, format = 'json') =>
    fetchJSON<any>(`/siem/webhook/send/${threatId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, format }),
    }),
  getSIEMLogs: () => fetchJSON<SIEMLog[]>('/siem/webhook/logs'),

  // Dark Web Monitoring
  getDarkwebMonitor: () => fetchJSON<any>('/darkweb/monitor'),
  getDarkwebBreaches: () => fetchJSON<any>('/darkweb/breaches'),
  searchDarkweb: (q: string) =>
    fetchJSON<{ query: string; total: number; results: DarkwebEntry[] }>(`/darkweb/search?q=${encodeURIComponent(q)}`),
};
