import React, { useEffect, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { api } from '../api';
import { Agency, ThreatDetail, ShareOut } from '../types';
import { useLanguage } from '../LanguageContext';
import { SEVERITY_KEY, THREAT_TYPE_KEY } from '../i18n/valueI18n';
import './pages.css';

const AGENCY_TYPE_KEY: Record<string, string> = {
  CERT: 'agencyCERT', GOV: 'agencyGOV', MIL: 'agencyMIL', ISP: 'agencyISP', INT: 'agencyINT',
};

const TLP_OPTION_VALUES = [
  { value: 'WHITE', label: 'TLP:WHITE', descKey: 'tlpWhiteDesc', color: '#e2e8f0' },
  { value: 'GREEN', label: 'TLP:GREEN', descKey: 'tlpGreenDesc', color: '#22c55e' },
  { value: 'AMBER', label: 'TLP:AMBER', descKey: 'tlpAmberDesc', color: '#f59e0b' },
  { value: 'RED',   label: 'TLP:RED',   descKey: 'tlpRedDesc',   color: '#ef4444' },
] as const;

export default function SharePage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { t } = useLanguage();
  const preselectedThreatId = searchParams.get('threat');

  const [agencies, setAgencies] = useState<Agency[]>([]);
  const [threats, setThreats] = useState<ThreatDetail[]>([]);
  const [selectedAgencies, setSelectedAgencies] = useState<number[]>([]);
  const [selectedThreatId, setSelectedThreatId] = useState<number | null>(
    preselectedThreatId ? Number(preselectedThreatId) : null
  );
  const [note, setNote] = useState('');
  const [fromAgency, setFromAgency] = useState('KISA (한국인터넷진흥원)');
  const [tlpLevel, setTlpLevel] = useState('WHITE');
  const [sharing, setSharing] = useState(false);
  const [result, setResult] = useState<ShareOut[] | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      try {
        const [a, t] = await Promise.all([
          api.getAgencies(),
          api.listThreats({ page: 1, page_size: 50 }),
        ]);
        setAgencies(a);
        setThreats(t.items);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  const toggleAgency = (id: number) => {
    setSelectedAgencies((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]
    );
  };

  const selectAll = () => setSelectedAgencies(agencies.map((a) => a.id));
  const clearAll = () => setSelectedAgencies([]);

  const handleShare = async () => {
    if (!selectedThreatId) { setError(t('shareErrorNoThreat')); return; }
    if (selectedAgencies.length === 0) { setError(t('shareErrorNoAgency')); return; }
    setSharing(true);
    setError('');
    setResult(null);
    try {
      const shares = await api.shareThreat(selectedThreatId, {
        agency_ids: selectedAgencies,
        note: note || undefined,
        from_agency: fromAgency,
        tlp_level: tlpLevel,
      });
      setResult(shares);
      setSelectedAgencies([]);
      setNote('');
    } catch (e: any) {
      setError(e.message || t('shareError'));
    } finally {
      setSharing(false);
    }
  };

  const selectedThreat = threats.find((t) => t.id === selectedThreatId);

  if (loading) return <div className="page-container"><p style={{ color: '#94a3b8' }}>{t('loading')}</p></div>;

  return (
    <div className="page-container share-page">
      <div className="page-header">
        <h2 className="page-title">{t('shareTitle')}</h2>
        <p className="page-desc">{t('shareDesc')}</p>
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      {result && (
        <div className="alert alert-success">
          <strong>{result.length}{t('shareAgenciesCount')}</strong>
          <ul style={{ margin: '8px 0 0', paddingLeft: 20 }}>
            {result.map((s) => (
              <li key={s.id} style={{ fontSize: 13 }}>{s.to_agency_name} — <span style={{ color: '#16a34a' }}>{s.status}</span></li>
            ))}
          </ul>
          <button className="btn-link" style={{ marginTop: 8 }} onClick={() => navigate(`/threats/${selectedThreatId}`)}>
            {t('btnDetail')} →
          </button>
        </div>
      )}

      <div className="share-layout">
        <div className="share-left">
          <div className="form-card">
            <h3 className="form-section-title">{t('shareThreatSelect')}</h3>
            <select
              className="form-select"
              style={{ width: '100%', marginBottom: 16 }}
              value={selectedThreatId || ''}
              onChange={(e) => setSelectedThreatId(e.target.value ? Number(e.target.value) : null)}
            >
              <option value="">{t('shareThreatPH')}</option>
              {threats.map((th) => (
                <option key={th.id} value={th.id}>#{th.id} [{t(SEVERITY_KEY[th.severity] ?? th.severity)}] {th.title.slice(0, 40)}{th.title.length > 40 ? '…' : ''}</option>
              ))}
            </select>

            {selectedThreat && (
              <div className="threat-preview">
                <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 8 }}>
                  <span style={{ fontSize: 14, fontWeight: 700, color: '#dc2626' }}>{t(SEVERITY_KEY[selectedThreat.severity] ?? selectedThreat.severity)}</span>
                  <span style={{ fontSize: 13, color: '#475569' }}>{t(THREAT_TYPE_KEY[selectedThreat.threat_type] ?? selectedThreat.threat_type)}</span>
                </div>
                <p style={{ margin: 0, fontSize: 14, fontWeight: 600, color: '#e2e8f0' }}>{selectedThreat.title}</p>
                {selectedThreat.actor_tag && (
                  <p style={{ margin: '6px 0 0', fontSize: 13, color: '#7c3aed' }}>{t('fieldActor')}: {selectedThreat.actor_tag}</p>
                )}
              </div>
            )}

            {/* TLP 등급 선택 */}
            <div className="form-row" style={{ marginTop: 16 }}>
              <label className="form-label">{t('tlpLevelLabel')}</label>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                {TLP_OPTION_VALUES.map(o => (
                  <button
                    key={o.value}
                    type="button"
                    onClick={() => setTlpLevel(o.value)}
                    title={t(o.descKey as any)}
                    style={{
                      padding: '5px 10px', borderRadius: 6, fontSize: 12, fontWeight: 700,
                      border: `1px solid ${tlpLevel === o.value ? o.color : 'rgba(255,255,255,0.15)'}`,
                      background: tlpLevel === o.value ? `${o.color}20` : 'rgba(255,255,255,0.05)',
                      color: tlpLevel === o.value ? o.color : 'rgba(255,255,255,0.5)',
                      cursor: 'pointer',
                    }}
                  >
                    {o.label}
                  </button>
                ))}
              </div>
              <p style={{ fontSize: 11, color: '#64748b', margin: '4px 0 0' }}>
                {t((TLP_OPTION_VALUES.find(o => o.value === tlpLevel)?.descKey ?? 'tlpWhiteDesc') as any)}
              </p>
            </div>

            <div className="form-row" style={{ marginTop: 12 }}>
              <label className="form-label">{t('shareFrom')}</label>
              <input
                className="form-input"
                type="text"
                value={fromAgency}
                onChange={(e) => setFromAgency(e.target.value)}
              />
            </div>

            <div className="form-row" style={{ marginTop: 12 }}>
              <label className="form-label">{t('shareNote')}</label>
              <textarea
                className="form-textarea"
                rows={3}
                value={note}
                onChange={(e) => setNote(e.target.value)}
              />
            </div>

            <button
              className="btn btn-primary"
              style={{ width: '100%', marginTop: 16 }}
              onClick={handleShare}
              disabled={sharing || !selectedThreatId || selectedAgencies.length === 0}
            >
              {sharing ? t('shareSending') : `${selectedAgencies.length} ${t('shareBtn')}`}
            </button>
          </div>
        </div>

        <div className="share-right">
          <div className="form-card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <h3 className="form-section-title" style={{ margin: 0 }}>
                {t('shareAgencySelect')} <span style={{ fontWeight: 400, color: '#94a3b8' }}>({selectedAgencies.length}/{agencies.length})</span>
              </h3>
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="btn-link" onClick={selectAll}>{t('shareSelectAll')}</button>
                <button className="btn-link" onClick={clearAll}>{t('shareClearAll')}</button>
              </div>
            </div>

            <div className="agency-grid">
              {agencies.map((agency) => {
                const checked = selectedAgencies.includes(agency.id);
                return (
                  <div
                    key={agency.id}
                    className={`agency-card ${checked ? 'selected' : ''}`}
                    onClick={() => toggleAgency(agency.id)}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 8 }}>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: 14, fontWeight: 700, color: '#f1f5f9', lineHeight: 1.45, wordBreak: 'keep-all' }}>{agency.name}</div>
                        <div style={{ fontSize: 12, color: '#94a3b8', marginTop: 3 }}>{agency.country}</div>
                      </div>
                      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4, flexShrink: 0 }}>
                        <span className="agency-type-badge">{t(AGENCY_TYPE_KEY[agency.agency_type] ?? agency.agency_type)}</span>
                        <span className="country-code-badge">{agency.country_code}</span>
                      </div>
                    </div>
                    {checked && (
                      <div style={{ marginTop: 6, color: '#60a5fa', fontSize: 11, fontWeight: 600 }}>{t('agencySelected')}</div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
