import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { api } from '../api';
import { ThreatDetail, AIAnalysis, ShareOut, AutoResponse } from '../types';
import { useLanguage } from '../LanguageContext';
import { SEVERITY_KEY, RISK_KEY, THREAT_TYPE_KEY } from '../i18n/valueI18n';
import './pages.css';

// desc는 t()로 처리하므로 제거
const TLP_CONFIG: Record<string, { bg: string; text: string; border: string; descKey: string }> = {
  'WHITE': { bg: 'rgba(255,255,255,0.1)', text: '#e2e8f0', border: 'rgba(255,255,255,0.3)', descKey: 'tlpWhiteDesc' },
  'GREEN': { bg: 'rgba(34,197,94,0.15)', text: '#22c55e', border: 'rgba(34,197,94,0.4)', descKey: 'tlpGreenDesc' },
  'AMBER': { bg: 'rgba(245,158,11,0.15)', text: '#f59e0b', border: 'rgba(245,158,11,0.4)', descKey: 'tlpAmberDesc' },
  'RED':   { bg: 'rgba(220,38,38,0.15)', text: '#ef4444', border: 'rgba(220,38,38,0.4)', descKey: 'tlpRedDesc' },
};

const AUTO_RESPONSE_ICON: Record<string, string> = {
  'AUTO_ANALYZE': '🤖',
  'IOC_BLOCK_RULE': '🚫',
  'ESCALATE': '🚨',
  'AUTO_SHARE_RECOMMEND': '📤',
};

const SEVERITY_COLOR: Record<string, string> = {
  '긴급': '#dc2626', '높음': '#ea580c', '중간': '#ca8a04', '낮음': '#16a34a',
};
const RISK_COLOR: Record<string, { bg: string; text: string; border: string }> = {
  '위험': { bg: '#fef2f2', text: '#dc2626', border: '#fecaca' },
  '경고': { bg: '#fff7ed', text: '#ea580c', border: '#fed7aa' },
  '주의': { bg: '#fefce8', text: '#ca8a04', border: '#fef08a' },
  '정보': { bg: '#eff6ff', text: '#2563eb', border: '#bfdbfe' },
};

export default function ThreatDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { t } = useLanguage();
  const threatId = Number(id);

  const [threat, setThreat] = useState<ThreatDetail | null>(null);
  const [analysis, setAnalysis] = useState<AIAnalysis | null>(null);
  const [shares, setShares] = useState<ShareOut[]>([]);
  const [autoResponses, setAutoResponses] = useState<AutoResponse[]>([]);
  const [loadingThreat, setLoadingThreat] = useState(true);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    const load = async () => {
      setLoadingThreat(true);
      try {
        const [tRes, sRes] = await Promise.allSettled([
          api.getThreat(threatId),
          api.getThreatShares(threatId),
        ]);
        if (tRes.status === 'fulfilled') setThreat(tRes.value);
        if (sRes.status === 'fulfilled') setShares(sRes.value);

        // Load analysis + auto-responses
        try {
          const a = await api.getThreatAnalysis(threatId);
          setAnalysis(a);
        } catch {
          // no analysis yet
        }
        try {
          const ar = await api.getAutoResponses(threatId);
          setAutoResponses(ar);
        } catch {
          // no auto responses
        }
      } catch {
        setError('cannotLoadThreat');
      } finally {
        setLoadingThreat(false);
      }
    };
    load();
  }, [threatId]);

  const runAnalysis = async () => {
    setAnalyzing(true);
    try {
      const a = await api.analyzeThreat(threatId);
      setAnalysis(a);
    } catch (e: any) {
      alert(e.message || t('aiAnalysisError'));
    } finally {
      setAnalyzing(false);
    }
  };

  if (loadingThreat) return <div className="page-container"><p style={{ color: '#94a3b8' }}>{t('loading')}</p></div>;
  if (error || !threat) return <div className="page-container"><p style={{ color: '#dc2626' }}>{error ? t(error as any) : t('noData')}</p></div>;

  const riskStyle = analysis ? RISK_COLOR[analysis.risk_level] || RISK_COLOR['정보'] : null;

  return (
    <div className="page-container">
      {/* Breadcrumb */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
        <button className="btn-link" style={{ fontSize: 52 }} onClick={() => navigate('/threats')}>{t('threatMgmtTitle')}</button>
        <span style={{ fontSize: 52, color: '#cbd5e1' }}>/</span>
        <span style={{ fontSize: 52, color: '#64748b' }}>#{threat.id}</span>
      </div>

      {/* Threat Header */}
      <div className="detail-header">
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12, flex: 1 }}>
          <span className="severity-badge large" style={{ color: SEVERITY_COLOR[threat.severity] || '#475569' }}>
            {t(SEVERITY_KEY[threat.severity] ?? 'sevMedium')}
          </span>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <h2 style={{ margin: 0, fontSize: 20, fontWeight: 700, color: '#0f172a', lineHeight: 1.4 }}>{threat.title}</h2>
              {/* TLP 배지 */}
              {(() => {
                const tlp = threat.tlp_level || 'WHITE';
                const cfg = TLP_CONFIG[tlp] || TLP_CONFIG['WHITE'];
                return (
                  <span title={t(cfg.descKey as any)} style={{
                    display: 'inline-flex', alignItems: 'center', gap: 4,
                    padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 800,
                    background: cfg.bg, color: cfg.text, border: `1px solid ${cfg.border}`,
                    letterSpacing: 0.5, cursor: 'help', flexShrink: 0,
                  }}>
                    🚦 TLP:{tlp}
                  </span>
                );
              })()}
            </div>
            <div style={{ display: 'flex', gap: 12, marginTop: 4, flexWrap: 'wrap' }}>
              <span style={{ fontSize: 13, color: '#64748b' }}>{t('fieldTypeLbl')}: <strong>{t(THREAT_TYPE_KEY[threat.threat_type] ?? 'ttOther')}</strong></span>
              <span style={{ fontSize: 13, color: '#64748b' }}>{t('fieldSourceLbl')}: <strong>{threat.source}</strong></span>
              {threat.actor_tag && <span style={{ fontSize: 13, color: '#64748b' }}>{t('fieldActor')}: <strong style={{ color: '#7c3aed' }}>{threat.actor_tag}</strong></span>}
              {threat.country_code && <span style={{ fontSize: 13, color: '#64748b' }}>{t('fieldCountryLbl')}: <strong>{threat.country_code}</strong></span>}
              <span style={{ fontSize: 13, color: '#64748b' }}>{t('fieldDetected')}: {new Date(threat.detected_at).toLocaleString()}</span>
              {threat.mitre_tactic_id && (
                <span style={{ fontSize: 12, color: '#6366f1', background: 'rgba(99,102,241,0.1)', padding: '1px 6px', borderRadius: 4, border: '1px solid rgba(99,102,241,0.3)' }}>
                  MITRE {threat.mitre_tactic_id} · {threat.mitre_technique_id}
                </span>
              )}
            </div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
          <button className="btn btn-secondary" onClick={() => navigate(`/share?threat=${threat.id}`)}>
            {t('navShare')}
          </button>
          <button className="btn btn-primary" onClick={runAnalysis} disabled={analyzing}>
            {analyzing ? t('btnAIRunning') : analysis ? t('btnAIReanalyze') : t('btnAIAnalyze')}
          </button>
        </div>
      </div>

      <div className="detail-grid">
        {/* 위협 상세 */}
        <div className="detail-card">
          <h3 className="detail-card-title">{t('threatDetail')}</h3>
          <div className="detail-field-list">
            {threat.ioc_value && (
              <div className="detail-field">
                <span className="detail-field-label">{t('fieldIOCVal')}</span>
                <code className="detail-field-code">{threat.ioc_value}</code>
              </div>
            )}
            {threat.ioc_type && (
              <div className="detail-field">
                <span className="detail-field-label">{t('fieldIOCTypeLbl')}</span>
                <span className="detail-field-value">{threat.ioc_type}</span>
              </div>
            )}
            <div className="detail-field">
              <span className="detail-field-label">{t('fieldIOCCnt')}</span>
              <span className="detail-field-value">{threat.ioc_count.toLocaleString()}</span>
            </div>
            {threat.description && (
              <div className="detail-field full">
                <span className="detail-field-label">{t('fieldDescLbl')}</span>
                <p className="detail-field-text">{threat.description}</p>
              </div>
            )}
          </div>
        </div>

        {/* 공유 기록 */}
        <div className="detail-card">
          <h3 className="detail-card-title">{t('shareHistory')} ({shares.length})</h3>
          {shares.length === 0 ? (
            <p style={{ color: '#94a3b8', fontSize: 13, margin: 0 }}>{t('noShareHistory')}</p>
          ) : (
            <div className="share-list">
              {shares.map((s) => {
                const tlpCfg = TLP_CONFIG[s.tlp_level] || TLP_CONFIG['WHITE'];
                const statusColor = s.status === '확인됨' ? '#22c55e' : s.status === '전송완료' ? '#3b82f6' : s.status === '대기중' ? '#f59e0b' : '#ef4444';
                return (
                  <div key={s.id} className="share-item">
                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <span style={{ fontSize: 13, fontWeight: 600, color: '#0f172a' }}>{s.to_agency_name}</span>
                        <span style={{ fontSize: 10, fontWeight: 700, padding: '1px 5px', borderRadius: 3, background: tlpCfg.bg, color: tlpCfg.text, border: `1px solid ${tlpCfg.border}` }}>
                          TLP:{s.tlp_level}
                        </span>
                      </div>
                      {s.note && <p style={{ fontSize: 11, color: '#64748b', margin: '2px 0 0' }}>{s.note}</p>}
                    </div>
                    <div style={{ textAlign: 'right' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4, justifyContent: 'flex-end', marginBottom: 2 }}>
                        <span style={{ width: 6, height: 6, borderRadius: '50%', background: statusColor, display: 'inline-block' }} />
                        <span style={{ fontSize: 11, fontWeight: 700, color: statusColor }}>{s.status}</span>
                      </div>
                      <div style={{ fontSize: 11, color: '#94a3b8' }}>
                        {new Date(s.shared_at).toLocaleString()}
                      </div>
                      {s.confirmed_at && (
                        <div style={{ fontSize: 10, color: '#22c55e' }}>
                          {t('confirmedAt')}: {new Date(s.confirmed_at).toLocaleString()}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* 자동 대응 이력 */}
      {autoResponses.length > 0 && (
        <div className="detail-card" style={{ marginTop: 16 }}>
          <h3 className="detail-card-title">🤖 {t('autoResponseHistory')} ({autoResponses.length})</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 8 }}>
            {autoResponses.map((ar) => {
              const icon = AUTO_RESPONSE_ICON[ar.action_type] || '⚙️';
              const labelMap: Record<string, string> = {
                'AUTO_ANALYZE': t('autoAnalyze'),
                'IOC_BLOCK_RULE': t('iocBlockRule'),
                'ESCALATE': t('escalate'),
                'AUTO_SHARE_RECOMMEND': t('autoShareRecommend'),
              };
              return (
                <div key={ar.id} style={{
                  background: '#0d1b2e', border: '1px solid #1e293b', borderRadius: 8,
                  padding: '10px 14px', display: 'flex', gap: 12, alignItems: 'flex-start',
                }}>
                  <span style={{ fontSize: 20, flexShrink: 0 }}>{icon}</span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                      <span style={{ fontSize: 13, fontWeight: 700, color: '#e2e8f0' }}>
                        {labelMap[ar.action_type] || ar.action_type}
                      </span>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <span style={{
                          fontSize: 11, fontWeight: 700,
                          color: ar.status === '완료' ? '#22c55e' : '#ef4444',
                          background: ar.status === '완료' ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)',
                          padding: '1px 6px', borderRadius: 3,
                        }}>{ar.status === '완료' ? t('statusDone') : ar.status === '실패' ? t('statusFail') : ar.status}</span>
                        <span style={{ fontSize: 11, color: '#64748b' }}>{new Date(ar.executed_at).toLocaleString()}</span>
                      </div>
                    </div>
                    {ar.action_detail && (
                      <pre style={{
                        margin: 0, fontSize: 11, color: '#94a3b8', fontFamily: 'monospace',
                        whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                        background: 'rgba(0,0,0,0.2)', padding: '6px 8px', borderRadius: 4,
                        maxHeight: 120, overflow: 'auto',
                      }}>{ar.action_detail}</pre>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* AI 분석 결과 */}
      {analysis && riskStyle && (
        <div className="ai-analysis-card" style={{ borderLeft: `4px solid ${riskStyle.text}` }}>
          <div className="ai-analysis-header">
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
              {analysis.is_fallback ? (
                <span style={{
                  display: 'inline-flex', alignItems: 'center', gap: 5,
                  padding: '4px 12px', borderRadius: 6, fontSize: 12, fontWeight: 700,
                  background: 'rgba(245,158,11,0.15)', color: '#f59e0b',
                  border: '1px solid rgba(245,158,11,0.4)',
                }}>
                  ⚠️ {t('aiFallback')}
                </span>
              ) : (
                <span style={{
                  display: 'inline-flex', alignItems: 'center', gap: 5,
                  padding: '4px 12px', borderRadius: 6, fontSize: 12, fontWeight: 700,
                  background: 'rgba(34,197,94,0.15)', color: '#22c55e',
                  border: '1px solid rgba(34,197,94,0.4)',
                }}>
                  ✅ {t('aiReal')}
                </span>
              )}
              <span className="ai-badge">{t('aiBadge')}</span>
              <span className="risk-badge" style={{ background: riskStyle.bg, color: riskStyle.text, border: `1px solid ${riskStyle.border}` }}>
                {t(RISK_KEY[analysis.risk_level] ?? 'riskInfo')}
              </span>
              <span style={{ fontSize: 13, color: '#64748b' }}>{t('aiRiskScore')}: <strong>{analysis.risk_score}</strong>/100</span>
              <span style={{ fontSize: 13, color: '#64748b' }}>{t('aiConfidence')}: <strong>{analysis.confidence_score}%</strong></span>
            </div>
            <span style={{ fontSize: 12, color: '#94a3b8' }}>
              {t('aiAnalyzedAt')}: {new Date(analysis.analyzed_at).toLocaleString()}
            </span>
          </div>

          {/* Risk Score Bar */}
          <div className="risk-bar-container">
            <div className="risk-bar-track">
              <div className="risk-bar-fill" style={{
                width: `${analysis.risk_score}%`,
                background: riskStyle.text,
              }} />
            </div>
          </div>

          <div className="ai-sections">
            <div className="ai-section">
              <h4 className="ai-section-title">{t('aiSummary')}</h4>
              <p className="ai-section-text">{analysis.summary}</p>
            </div>
            <div className="ai-section-grid">
              {analysis.attack_vector && (
                <div className="ai-section">
                  <h4 className="ai-section-title">{t('aiAttackVector')}</h4>
                  <p className="ai-section-text">{analysis.attack_vector}</p>
                </div>
              )}
              {analysis.target_sectors && (
                <div className="ai-section">
                  <h4 className="ai-section-title">{t('aiTargets')}</h4>
                  <p className="ai-section-text">{analysis.target_sectors}</p>
                </div>
              )}
            </div>
            {analysis.ioc_analysis && (
              <div className="ai-section">
                <h4 className="ai-section-title">{t('aiIOCAnalysis')}</h4>
                <p className="ai-section-text">{analysis.ioc_analysis}</p>
              </div>
            )}
            {analysis.attribution && (
              <div className="ai-section">
                <h4 className="ai-section-title">{t('aiAttribution')}</h4>
                <p className="ai-section-text">{analysis.attribution}</p>
              </div>
            )}
            {analysis.recommendations && (
              <div className="ai-section">
                <h4 className="ai-section-title">{t('aiRecommend')}</h4>
                <pre className="ai-recommendations">{analysis.recommendations}</pre>
              </div>
            )}
          </div>
        </div>
      )}

      {!analysis && (
        <div className="ai-placeholder">
          <div style={{ fontSize: 96, marginBottom: 8 }}>🤖</div>
          <p style={{ margin: 0, fontWeight: 600, color: '#475569' }}>{t('aiNotRun')}</p>
          <p style={{ margin: '4px 0 16px', fontSize: 13, color: '#94a3b8' }}>
            {t('aiRunHint')}
          </p>
          <button className="btn btn-primary" onClick={runAnalysis} disabled={analyzing}>
            {analyzing ? t('btnAIRunning') : t('btnAIAnalyze')}
          </button>
        </div>
      )}
    </div>
  );
}
