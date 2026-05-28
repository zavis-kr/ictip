import React, { useEffect, useState, useCallback, useRef } from 'react';
import { api } from '../api';
import { useLanguage } from '../LanguageContext';
import {
  DashboardStats, AIMetrics, ThreatFeed,
  ThreatDistribution, CountryShare, ThreatActor, WSMessage,
  AttackMapEntry, TopAttacker, GeoRiskEntry, EconomicIndicator, PlatformMetrics,
} from '../types';
import StatCard from '../components/StatCard';
import ThreatFeedPanel from '../components/ThreatFeedPanel';
import ThreatDistributionPanel from '../components/ThreatDistributionPanel';
import CountrySharePanel from '../components/CountrySharePanel';
import AIMetricsPanel from '../components/AIMetricsPanel';
import AttackMapPanel from '../components/AttackMapPanel';
import TopAttackersPanel from '../components/TopAttackersPanel';
import GeoPoliticalPanel from '../components/GeoPoliticalPanel';
import EconomicPanel from '../components/EconomicPanel';
import CorrelationPanel from '../components/CorrelationPanel';
import './DashboardPage.css';

const REFRESH_INTERVAL = 30; // seconds
const WS_URL = `ws://${window.location.host}/ws`;

function useLiveClock() {
  const [now, setNow] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  return now;
}

export default function DashboardPage() {
  const { t, locale } = useLanguage();
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [metrics, setMetrics] = useState<AIMetrics | null>(null);
  const [platformMetrics, setPlatformMetrics] = useState<PlatformMetrics | null>(null);
  const [feeds, setFeeds] = useState<ThreatFeed[]>([]);
  const [distribution, setDistribution] = useState<ThreatDistribution[]>([]);
  const [countryShares, setCountryShares] = useState<CountryShare[]>([]);
  const [actors, setActors] = useState<ThreatActor[]>([]);
  const [attackMap, setAttackMap] = useState<AttackMapEntry[]>([]);
  const [topAttackers, setTopAttackers] = useState<TopAttacker[]>([]);
  const [geoRisk, setGeoRisk] = useState<GeoRiskEntry[]>([]);
  const [economicData, setEconomicData] = useState<EconomicIndicator[]>([]);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [wsConnected, setWsConnected] = useState(false);
  const [countdown, setCountdown] = useState(REFRESH_INTERVAL);
  const [loading, setLoading] = useState(true);
  const wsRef = useRef<WebSocket | null>(null);
  const now = useLiveClock();

  const loadData = useCallback(async () => {
    try {
      const [s, m, f, d, c, a, am, ta, gr, ei, pm] = await Promise.allSettled([
        api.getDashboardStats(),
        api.getAIMetrics(),
        api.getThreatFeed(15),
        api.getThreatDistribution(),
        api.getCountryShares(),
        api.getThreatActors(),
        api.getAttackMap(),
        api.getTopAttackers(),
        api.getGeoRisk(),
        api.getEconomicIndicators(),
        api.getPlatformMetrics(),
      ]);
      if (s.status === 'fulfilled') setStats(s.value);
      if (m.status === 'fulfilled') setMetrics(m.value);
      if (f.status === 'fulfilled') setFeeds(f.value);
      if (d.status === 'fulfilled') setDistribution(d.value);
      if (c.status === 'fulfilled') setCountryShares(c.value);
      if (a.status === 'fulfilled') setActors(a.value);
      if (am.status === 'fulfilled') setAttackMap(am.value);
      if (ta.status === 'fulfilled') setTopAttackers(ta.value);
      if (gr.status === 'fulfilled') setGeoRisk(gr.value);
      if (ei.status === 'fulfilled') setEconomicData(ei.value);
      if (pm.status === 'fulfilled') setPlatformMetrics(pm.value);
      setLastUpdated(new Date());
      setCountdown(REFRESH_INTERVAL);
    } catch (e) {
      console.error('Failed to load data', e);
    } finally {
      setLoading(false);
    }
  }, []);

  // 1시간마다 플랫폼 지표 + 공유 현황 갱신
  useEffect(() => {
    const refreshHourly = async () => {
      try {
        const [pm, cs] = await Promise.allSettled([
          api.getPlatformMetrics(),
          api.getCountryShares(),
        ]);
        if (pm.status === 'fulfilled') setPlatformMetrics(pm.value);
        if (cs.status === 'fulfilled') setCountryShares(cs.value);
      } catch {}
    };
    const t = setInterval(refreshHourly, 60 * 60 * 1000); // 1시간
    return () => clearInterval(t);
  }, []);

  // WebSocket
  useEffect(() => {
    let retryTimer: ReturnType<typeof setTimeout>;
    function connect() {
      try {
        const ws = new WebSocket(WS_URL);
        wsRef.current = ws;
        ws.onopen = () => setWsConnected(true);
        ws.onclose = () => {
          setWsConnected(false);
          retryTimer = setTimeout(connect, 5000);
        };
        ws.onerror = () => ws.close();
        ws.onmessage = (event) => {
          try {
            const msg: WSMessage = JSON.parse(event.data);
            if (msg.type === 'new_threat') {
              setFeeds(prev => [msg.data as ThreatFeed, ...prev].slice(0, 15));
              setLastUpdated(new Date());
            } else if (msg.type === 'stats_update') {
              setStats(prev => prev ? { ...prev, ...msg.data } : prev);
            }
          } catch {}
        };
      } catch {
        retryTimer = setTimeout(connect, 5000);
      }
    }
    connect();
    return () => {
      clearTimeout(retryTimer);
      wsRef.current?.close();
    };
  }, []);

  // 30초 자동 갱신
  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, REFRESH_INTERVAL * 1000);
    return () => clearInterval(interval);
  }, [loadData]);

  // 카운트다운
  useEffect(() => {
    const t = setInterval(() => {
      setCountdown(prev => (prev <= 1 ? REFRESH_INTERVAL : prev - 1));
    }, 1000);
    return () => clearInterval(t);
  }, []);

  const lastUpdatedText = lastUpdated
    ? `${Math.floor((now.getTime() - lastUpdated.getTime()) / 1000)}${t('secAgo')}`
    : t('dataLoading');

  const clockStr = now.toLocaleTimeString(locale, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const dateStr  = now.toLocaleDateString(locale, { year: 'numeric', month: 'long', day: 'numeric', weekday: 'short' });

  return (
    <div className="dashboard">
      {/* ── 헤더 ── */}
      <div className="dashboard-header">
        <div className="header-left">
          <div className="header-title">{t('dashboardHeaderTitle')}</div>
          <div className="header-date">{dateStr}</div>
        </div>
        <div className="header-right">
          <div className="live-clock">{clockStr}</div>
          <div className="header-meta">
            <span className={`live-badge ${wsConnected ? 'connected' : 'disconnected'}`}>
              <span className="live-dot" />
              {wsConnected ? t('wsConnected') : t('wsReconnecting')}
            </span>
            <span className="last-update">{lastUpdatedText}</span>
            <div className="refresh-bar-wrap" title={`${countdown}${t('secRefresh')}`}>
              <div
                className="refresh-bar"
                style={{ width: `${(countdown / REFRESH_INTERVAL) * 100}%` }}
              />
            </div>
          </div>
        </div>
      </div>

      {/* ── KPI 카드 ── */}
      {loading ? (
        <div className="kpi-row">
          {[0,1,2,3].map(i => <div key={i} className="stat-skeleton" />)}
        </div>
      ) : (
        <div className="kpi-row">
          <StatCard
            icon="🛡"
            label={t('kpiThreats')}
            value={stats ? stats.threats_detected.toLocaleString(locale) : '—'}
            change={stats ? `${stats.threats_change_pct > 0 ? '+' : ''}${stats.threats_change_pct}% ${t('kpiVsYesterday')}` : undefined}
            changePositive={false}
            accent="red"
          />
          <StatCard
            icon="🌐"
            label={t('kpiCountries')}
            value={stats ? `${stats.participating_countries}${t('nation')}` : '—'}
            change={stats ? `${t('kpiNewCountries')} +${stats.new_countries}${t('nation')}` : undefined}
            changePositive={true}
            accent="blue"
          />
          <StatCard
            icon="🤖"
            label={t('kpiAttribution')}
            value={stats ? `${stats.ai_response_rate}%` : '—'}
            change={stats ? `${stats.ai_response_change > 0 ? '+' : ''}${stats.ai_response_change}%p` : undefined}
            changePositive={stats ? stats.ai_response_change >= 0 : true}
            accent="green"
          />
          <StatCard
            icon="⚡"
            label={t('kpiDetectTime')}
            value={stats ? (stats.avg_share_time_minutes >= 60
              ? `${(stats.avg_share_time_minutes / 60).toFixed(1)}${t('hour')}`
              : `${stats.avg_share_time_minutes}${t('min')}`) : '—'}
            change={stats ? (Math.abs(stats.share_time_change) >= 60
              ? `${(Math.abs(stats.share_time_change) / 60).toFixed(1)}${t('hour')} ${stats.share_time_change > 0 ? t('kpiIncrease') : t('kpiDecrease')}`
              : `${Math.abs(stats.share_time_change)}${t('min')} ${stats.share_time_change > 0 ? t('kpiIncrease') : t('kpiDecrease')}`) : undefined}
            changePositive={stats ? stats.share_time_change < 0 : false}
            accent="orange"
          />
        </div>
      )}

      {/* ── 중단 : 위협피드 | 분포 | 경제지표 ── */}
      <div className="mid-row">
        <div className="mid-left">
          <ThreatFeedPanel feeds={feeds} />
        </div>
        <div className="mid-right">
          <ThreatDistributionPanel data={distribution} />
        </div>
        <div className="mid-econ">
          <EconomicPanel data={economicData} />
        </div>
      </div>

      {/* ── 하단 ── */}
      <div className="bottom-row">
        <div><CountrySharePanel data={countryShares} /></div>
        <div><AIMetricsPanel metrics={platformMetrics ?? undefined} actors={actors} /></div>
      </div>

      {/* ── 공격 지도 + 위험 공격자 ── */}
      <div className="attack-row">
        <div className="attack-map-col">
          <AttackMapPanel data={attackMap} geoRisk={geoRisk} partnerCodes={countryShares.map(c => c.country_code)} />
        </div>
        <div className="attack-list-col">
          <TopAttackersPanel data={topAttackers} />
        </div>
      </div>

      {/* ── 지정학적 리스크 ── */}
      <div className="intel-row">
        <GeoPoliticalPanel data={geoRisk} />
      </div>

      {/* ── 경제지표 ↔ 공격 상관관계 ── */}
      <div className="intel-row">
        <CorrelationPanel />
      </div>
    </div>
  );
}
