import React from 'react';
import { TopAttacker } from '../types';
import { useLanguage } from '../LanguageContext';
import { SEVERITY_KEY, THREAT_TYPE_KEY } from '../i18n/valueI18n';
import './TopAttackersPanel.css';

const SEV_COLOR: Record<string, string> = {
  '긴급': '#dc2626', '높음': '#f97316', '중간': '#eab308', '낮음': '#22c55e',
};
const SEV_BG: Record<string, string> = {
  '긴급': 'rgba(220,38,38,0.12)', '높음': 'rgba(249,115,22,0.12)',
  '중간': 'rgba(234,179,8,0.12)', '낮음': 'rgba(34,197,94,0.12)',
};

interface Props {
  data: TopAttacker[];
}

export default function TopAttackersPanel({ data }: Props) {
  const { t } = useLanguage();
  const maxCount = Math.max(...data.map(d => d.count), 1);

  function parseIp(raw: string): string {
    const match = raw.match(/^(\d{1,3}(?:\.\d{1,3}){3})/);
    return match ? match[1] : raw;
  }

  return (
    <div className="top-attackers-panel">
      <div className="tap-header">
        <div className="tap-title-row">
          <span className="tap-icon">🎯</span>
          <span className="tap-title">{t('topAttackersTitle')} {data.length}</span>
        </div>
        <span className="tap-subtitle">{t('topAttackersSubtitle')}</span>
      </div>

      <div className="tap-list">
        {data.map((a, i) => (
          <div key={a.ip} className="tap-row">
            <span className={`tap-rank ${i < 3 ? 'top3' : ''}`}>#{i + 1}</span>

            <div className="tap-info">
              <div className="tap-row-top">
                <span className="tap-ip">{parseIp(a.ip)}</span>
                <div className="tap-badges">
                  {a.country_code && (
                    <span className="tap-badge tap-cc">{a.country_code}</span>
                  )}
                  {a.severity && (
                    <span
                      className="tap-badge tap-sev"
                      style={{
                        color: SEV_COLOR[a.severity] ?? '#94a3b8',
                        background: SEV_BG[a.severity] ?? 'rgba(148,163,184,0.1)',
                        borderColor: SEV_COLOR[a.severity] ?? '#475569',
                      }}
                    >
                      {t(SEVERITY_KEY[a.severity] ?? a.severity ?? '')}
                    </span>
                  )}
                  {a.threat_type && (
                    <span className="tap-badge tap-type">{t(THREAT_TYPE_KEY[a.threat_type] ?? a.threat_type)}</span>
                  )}
                </div>
              </div>
              <div className="tap-bar-wrap">
                <div
                  className="tap-bar"
                  style={{
                    width: `${(a.count / maxCount) * 100}%`,
                    background: i < 3 ? '#ef4444' : '#3b82f6',
                  }}
                />
              </div>
            </div>

            <span className="tap-count">
              {a.count.toLocaleString()}
              <span className="tap-unit">{t('attackUnit')}</span>
            </span>
          </div>
        ))}

        {data.length === 0 && (
          <div className="tap-empty">{t('topAttackersEmpty')}</div>
        )}
      </div>
    </div>
  );
}
