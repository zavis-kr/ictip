import React from 'react';
import { GeoRiskEntry } from '../types';
import { useLanguage } from '../LanguageContext';
import { SEVERITY_KEY, TREND_KEY } from '../i18n/valueI18n';
import './GeoPoliticalPanel.css';

const LEVEL_COLOR: Record<string, string> = {
  '긴급': '#dc2626', '높음': '#f97316', '중간': '#eab308', '낮음': '#22c55e',
};
const LEVEL_BG: Record<string, string> = {
  '긴급': 'rgba(220,38,38,0.12)', '높음': 'rgba(249,115,22,0.12)',
  '중간': 'rgba(234,179,8,0.12)', '낮음': 'rgba(34,197,94,0.12)',
};
const TREND_ICON: Record<string, string> = { '상승': '▲', '하락': '▼', '안정': '─' };
const TREND_COLOR: Record<string, string> = { '상승': '#ef4444', '하락': '#22c55e', '안정': '#64748b' };

interface Props {
  data: GeoRiskEntry[];
}

export default function GeoPoliticalPanel({ data }: Props) {
  const { t } = useLanguage();
  const top = data.slice(0, 8);

  return (
    <div className="geo-panel">
      <div className="geo-header">
        <div className="geo-title-row">
          <span className="geo-icon">🗺</span>
          <span className="geo-title">{t('geoPanelTitle')}</span>
        </div>
        <span className="geo-subtitle">{t('geoPanelSubtitle')}</span>
      </div>

      <div className="geo-list">
        {top.map((item, i) => (
          <div key={item.country_code} className="geo-row">
            <div className="geo-row-top">
              <span className="geo-rank">#{i + 1}</span>
              <span className="geo-cc">{item.country_code}</span>
              <span className="geo-name">{item.country_name}</span>
              <span
                className="geo-level-badge"
                style={{
                  color: LEVEL_COLOR[item.level] ?? '#94a3b8',
                  background: LEVEL_BG[item.level] ?? 'rgba(148,163,184,0.1)',
                }}
              >
                {t(SEVERITY_KEY[item.level] ?? 'sevMedium')}
              </span>
              <span
                className="geo-trend"
                style={{ color: TREND_COLOR[item.trend] ?? '#64748b' }}
              >
                {TREND_ICON[item.trend] ?? '─'} {t(TREND_KEY[item.trend] ?? 'trendStable')}
              </span>
              <span className="geo-score">{item.score}</span>
            </div>

            <div className="geo-bar-wrap">
              <div
                className="geo-bar"
                style={{
                  width: `${item.score}%`,
                  background: LEVEL_COLOR[item.level] ?? '#475569',
                  opacity: 0.7,
                }}
              />
            </div>

            <div className="geo-factors">
              {item.factors.slice(0, 3).map(f => (
                <span key={f} className="geo-factor">{f}</span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
