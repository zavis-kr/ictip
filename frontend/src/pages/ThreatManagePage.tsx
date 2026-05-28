import React, { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api';
import { ThreatDetail, ThreatFeed } from '../types';
import { useLanguage } from '../LanguageContext';
import { SEVERITY_OPTIONS, THREAT_TYPE_OPTIONS } from '../i18n/valueI18n';
import './pages.css';

const SEVERITY_COLOR: Record<string, string> = {
  '긴급': '#dc2626', '높음': '#ea580c', '중간': '#ca8a04', '낮음': '#16a34a',
};
const SEVERITY_BG: Record<string, string> = {
  '긴급': '#fee2e2', '높음': '#ffedd5', '중간': '#fef9c3', '낮음': '#dcfce7',
};

// 소스 → 표시 이름 매핑
const SOURCE_LABELS: Record<string, string> = {
  malwarebazaar:  'MalwareBazaar',
  urlhaus:        'URLhaus',
  nvd_cve:        'NVD CVE',
  threatfox:      'ThreatFox',
  cisa_kev:       'CISA KEV',
  kisa_malware:   'CISA ICS',
  kisa_vuln:      'CISA Advisory',
  kisa_notice:    'JPCERT/CC',
  otx_alienvault: 'OTX AlienVault',
  feodo_tracker:  'Feodo Tracker',
  internal:       null, // t('internalSource')로 처리
};
const SOURCE_COLOR: Record<string, string> = {
  malwarebazaar:  '#7c3aed', urlhaus:        '#0891b2',
  nvd_cve:        '#dc2626', threatfox:      '#ea580c',
  cisa_kev:       '#1d4ed8', kisa_malware:   '#0f766e',
  kisa_vuln:      '#0369a1', kisa_notice:    '#9333ea',
  otx_alienvault: '#b45309', feodo_tracker:  '#be185d',
  internal:       '#374151',
};

const PAGE_SIZE = 15;
type TabMode = 'db' | 'feeds';

export default function ThreatManagePage() {
  const navigate = useNavigate();
  const { t } = useLanguage();
  const [tab, setTab] = useState<TabMode>('feeds');

  // DB tab state
  const [threats, setThreats] = useState<ThreatDetail[]>([]);
  const [dbTotal, setDbTotal] = useState(0);
  const [dbPage, setDbPage] = useState(1);
  const [deleting, setDeleting] = useState<number | null>(null);

  // Feed tab state
  const [feeds, setFeeds] = useState<ThreatFeed[]>([]);
  const [feedTotal, setFeedTotal] = useState(0);
  const [feedPage, setFeedPage] = useState(1);
  const [filterSource, setFilterSource] = useState('');

  // Shared filter state
  const [search, setSearch] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('');
  const [filterType, setFilterType] = useState('');
  const [loading, setLoading] = useState(false);

  const loadDb = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.listThreats({
        page: dbPage, page_size: PAGE_SIZE,
        severity: filterSeverity || undefined,
        threat_type: filterType || undefined,
        search: search || undefined,
      });
      setThreats(res.items as unknown as ThreatDetail[]);
      setDbTotal(res.total);
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  }, [dbPage, search, filterSeverity, filterType]);

  const loadFeeds = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.listFeeds({
        page: feedPage, page_size: PAGE_SIZE,
        severity: filterSeverity || undefined,
        threat_type: filterType || undefined,
        source: filterSource || undefined,
        search: search || undefined,
      });
      setFeeds(res.items as unknown as ThreatFeed[]);
      setFeedTotal(res.total);
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  }, [feedPage, search, filterSeverity, filterType, filterSource]);

  useEffect(() => { if (tab === 'db') loadDb(); else loadFeeds(); }, [tab, loadDb, loadFeeds]);

  const handleDelete = async (id: number) => {
    if (!window.confirm(t('deleteConfirm'))) return;
    setDeleting(id);
    try { await api.deleteThreat(id); await loadDb(); }
    catch (e: any) { alert(e.message || t('deleteError')); }
    finally { setDeleting(null); }
  };

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (tab === 'db') { setDbPage(1); loadDb(); }
    else { setFeedPage(1); loadFeeds(); }
  };

  const totalPages = Math.ceil((tab === 'db' ? dbTotal : feedTotal) / PAGE_SIZE);
  const currentPage = tab === 'db' ? dbPage : feedPage;
  const setCurrentPage = tab === 'db' ? setDbPage : setFeedPage;

  return (
    <div className="page-container">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h2 className="page-title">{t('threatMgmtTitle')}</h2>
          <p className="page-desc">{t('threatMgmtDesc')}</p>
        </div>
        {tab === 'db' && (
          <button className="btn btn-primary" onClick={() => navigate('/submit')}>
            {t('btnNew')}
          </button>
        )}
      </div>

      {/* 탭 */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 16 }}>
        {([['feeds', `${t('tabFeeds')} (${feedTotal.toLocaleString()}${t('recordsUnit')})`], ['db', `${t('tabThreatDB')} (${dbTotal}${t('recordsUnit')})`]] as [TabMode, string][]).map(([key, label]) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            style={{
              padding: '8px 18px', borderRadius: 8, border: 'none', cursor: 'pointer', fontWeight: 600, fontSize: 13,
              background: tab === key ? '#2563eb' : '#f1f5f9',
              color: tab === key ? '#fff' : '#475569',
              transition: 'all .15s',
            }}
          >{label}</button>
        ))}
      </div>

      {/* 필터 */}
      <div className="filter-bar">
        <form onSubmit={handleSearch} style={{ display: 'flex', gap: 8, flex: 1, flexWrap: 'wrap' }}>
          <input
            className="form-input" type="text"
            placeholder={t('searchPlaceholder')}
            value={search} onChange={(e) => setSearch(e.target.value)}
            style={{ flex: 1, minWidth: 160 }}
          />
          <select className="form-select" value={filterSeverity} onChange={(e) => { setFilterSeverity(e.target.value); setCurrentPage(1); }}>
            <option value="">{t('filterAll')} {t('filterSeverity')}</option>
            {SEVERITY_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>{t(o.labelKey)}</option>
            ))}
          </select>
          <select className="form-select" value={filterType} onChange={(e) => { setFilterType(e.target.value); setCurrentPage(1); }}>
            <option value="">{t('filterAll')} {t('filterType')}</option>
            {THREAT_TYPE_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>{t(o.labelKey)}</option>
            ))}
          </select>
          {tab === 'feeds' && (
            <select className="form-select" value={filterSource} onChange={(e) => { setFilterSource(e.target.value); setFeedPage(1); }}>
              <option value="">{t('allSources')}</option>
              {Object.entries(SOURCE_LABELS).map(([key, label]) => (
                <option key={key} value={key}>{label ?? t('internalSource')}</option>
              ))}
            </select>
          )}
          <button type="submit" className="btn btn-secondary">{t('btnSearch')}</button>
        </form>
      </div>

      <div className="table-card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
          <span style={{ fontSize: 13, color: '#64748b' }}>
            총 <strong>{(tab === 'db' ? dbTotal : feedTotal).toLocaleString()}</strong>{t('totalCount')}
          </span>
          {loading && <span style={{ fontSize: 12, color: '#94a3b8' }}>{t('loading')}</span>}
        </div>

        <div className="table-scroll">
          {tab === 'db' ? (
            /* 위협 DB 테이블 */
            <table className="threat-table">
              <thead>
                <tr>
                  <th style={{ width: 48 }}>ID</th>
                  <th>{t('colTitle')}</th>
                  <th style={{ width: 72 }}>{t('filterSeverity')}</th>
                  <th style={{ width: 120 }}>{t('colType')}</th>
                  <th style={{ width: 80 }}>IOC</th>
                  <th style={{ width: 90 }}>{t('fieldActor')}</th>
                  <th style={{ width: 100 }}>{t('colDetected')}</th>
                  <th style={{ width: 100 }}>{t('colActions')}</th>
                </tr>
              </thead>
              <tbody>
                {threats.length === 0 && !loading && (
                  <tr><td colSpan={8} style={{ textAlign: 'center', padding: '32px', color: '#94a3b8' }}>{t('noData')}</td></tr>
                )}
                {threats.map((th) => (
                  <tr key={th.id} className="table-row" onClick={() => navigate(`/threats/${th.id}`)}>
                    <td style={{ color: '#94a3b8', fontSize: 12 }}>{th.id}</td>
                    <td>
                      <span className="threat-title">{th.title}</span>
                      {th.ioc_value && <span className="ioc-badge">{th.ioc_value.slice(0, 28)}{th.ioc_value.length > 28 ? '…' : ''}</span>}
                    </td>
                    <td>
                      <span className="severity-badge" style={{ background: SEVERITY_BG[th.severity] || '#f1f5f9', color: SEVERITY_COLOR[th.severity] || '#475569' }}>{th.severity}</span>
                    </td>
                    <td style={{ fontSize: 12, color: '#475569' }}>{th.threat_type}</td>
                    <td style={{ fontSize: 12, color: '#64748b', textAlign: 'center' }}>{th.ioc_count}</td>
                    <td style={{ fontSize: 12, color: '#64748b' }}>{th.actor_tag || '—'}</td>
                    <td style={{ fontSize: 12, color: '#64748b' }}>{new Date(th.detected_at).toLocaleDateString()}</td>
                    <td onClick={(e) => e.stopPropagation()}>
                      <div style={{ display: 'flex', gap: 4 }}>
                        <button className="btn-icon" onClick={() => navigate(`/threats/${th.id}`)}>{t('btnDetail')}</button>
                        <button className="btn-icon btn-icon-danger" onClick={() => handleDelete(th.id)} disabled={deleting === th.id}>
                          {deleting === th.id ? '…' : t('btnDelete')}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            /* 수집 피드 테이블 */
            <table className="threat-table">
              <thead>
                <tr>
                  <th style={{ width: 48 }}>ID</th>
                  <th style={{ width: 110 }}>{t('colSource')}</th>
                  <th>{t('colTitle')}</th>
                  <th style={{ width: 72 }}>{t('filterSeverity')}</th>
                  <th style={{ width: 130 }}>{t('colType')}</th>
                  <th style={{ width: 80 }}>{t('iocType')}</th>
                  <th style={{ width: 100 }}>{t('colDetected')}</th>
                </tr>
              </thead>
              <tbody>
                {feeds.length === 0 && !loading && (
                  <tr><td colSpan={7} style={{ textAlign: 'center', padding: '32px', color: '#94a3b8' }}>{t('noData')}</td></tr>
                )}
                {feeds.map((f) => (
                  <tr key={f.id} className="table-row">
                    <td style={{ color: '#94a3b8', fontSize: 12 }}>{f.id}</td>
                    <td>
                      <span style={{
                        fontSize: 11, fontWeight: 600, padding: '2px 7px', borderRadius: 4,
                        background: (SOURCE_COLOR[f.source] || '#374151') + '18',
                        color: SOURCE_COLOR[f.source] || '#374151',
                        border: `1px solid ${SOURCE_COLOR[f.source] || '#374151'}33`,
                      }}>
                        {SOURCE_LABELS[f.source] ?? (f.source === 'internal' ? t('internalSource') : f.source)}
                      </span>
                    </td>
                    <td>
                      <span className="threat-title" style={{ fontSize: 12 }}>{f.title}</span>
                      {f.ioc_value && (
                        <span className="ioc-badge" style={{ fontSize: 10 }}>
                          {f.ioc_value.slice(0, 24)}{f.ioc_value.length > 24 ? '…' : ''}
                        </span>
                      )}
                    </td>
                    <td>
                      <span className="severity-badge" style={{ background: SEVERITY_BG[f.severity] || '#f1f5f9', color: SEVERITY_COLOR[f.severity] || '#475569' }}>{f.severity}</span>
                    </td>
                    <td style={{ fontSize: 11, color: '#475569' }}>{f.threat_type}</td>
                    <td style={{ fontSize: 11, color: '#64748b' }}>{f.ioc_type || '—'}</td>
                    <td style={{ fontSize: 11, color: '#64748b' }}>
                      {f.detected_at ? new Date(f.detected_at).toLocaleDateString() : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {totalPages > 1 && (
          <div className="pagination">
            <button className="btn btn-secondary" disabled={currentPage === 1} onClick={() => setCurrentPage(currentPage - 1)}>{t('btnPrev')}</button>
            <span style={{ fontSize: 13, color: '#64748b' }}>{currentPage} {t('of')} {totalPages}</span>
            <button className="btn btn-secondary" disabled={currentPage === totalPages} onClick={() => setCurrentPage(currentPage + 1)}>{t('btnNext')}</button>
          </div>
        )}
      </div>
    </div>
  );
}
