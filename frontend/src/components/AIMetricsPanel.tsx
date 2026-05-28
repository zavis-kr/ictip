import React from 'react';
import { PlatformMetrics, ThreatActor } from '../types';
import { useLanguage } from '../LanguageContext';
import './AIMetricsPanel.css';

interface Props {
  metrics?: PlatformMetrics;
  actors: ThreatActor[];
}

export default function AIMetricsPanel({ metrics, actors }: Props) {
  const { t, locale } = useLanguage();

  const updatedText = metrics ? (() => {
    const d = new Date(metrics.updated_at);
    const h = String(d.getHours()).padStart(2, '0');
    const m = String(d.getMinutes()).padStart(2, '0');
    return `${h}:${m} ${t('aggregatedAt')} · ${t('hourlyRefresh')}`;
  })() : '';

  return (
    <div className="panel">
      <div className="panel-header">
        <h2 className="panel-title">{t('platformMetricsTitle')}</h2>
        {metrics && (
          <span style={{ fontSize: 11, color: '#475569' }}>{updatedText}</span>
        )}
      </div>

      <div className="metrics-grid">
        <div className="metric-box">
          <div className="metric-value green">
            {metrics ? metrics.total_threats.toLocaleString(locale) : '—'}
          </div>
          <div className="metric-label">{t('totalThreats')}</div>
        </div>
        <div className="metric-box">
          <div className="metric-value amber">
            {metrics ? `${metrics.high_risk_rate}%` : '—'}
          </div>
          <div className="metric-label">{t('highRiskRate')}</div>
        </div>
        <div className="metric-box">
          <div className="metric-value blue">
            {metrics ? `${metrics.attribution_rate}%` : '—'}
          </div>
          <div className="metric-label">{t('actorAttribution')}</div>
        </div>
        <div className="metric-box">
          <div className="metric-value purple">
            {metrics ? `${metrics.active_sources}${t('sourceUnit')}` : '—'}
          </div>
          <div className="metric-label">{t('activeSources')}</div>
        </div>
      </div>

      <div className="metrics-sub-row">
        <div className="metric-sub-box">
          <span className="metric-sub-label">{t('todayNewIOC')}</span>
          <span className="metric-sub-value">
            {metrics ? `${metrics.today_ioc_sum.toLocaleString(locale)}${t('countUnit')}` : '—'}
          </span>
        </div>
        <div className="metric-sub-box">
          <span className="metric-sub-label">{t('avgDetectLag')}</span>
          <span className="metric-sub-value">
            {metrics
              ? metrics.avg_detection_lag_hours >= 1
                ? `${metrics.avg_detection_lag_hours}${t('hour')}`
                : `${Math.round(metrics.avg_detection_lag_hours * 60)}${t('min')}`
              : '—'}
          </span>
        </div>
      </div>

      <div className="actors-section">
        <div className="actors-label">{t('activeActorTags')}</div>
        <div className="actors-tags">
          {actors.map((actor) => (
            <span key={actor.name} className="actor-tag">{actor.name}</span>
          ))}
          {actors.length === 0 && (
            <span style={{ fontSize: 12, color: '#475569' }}>{t('collectingData')}</span>
          )}
        </div>
      </div>
    </div>
  );
}
