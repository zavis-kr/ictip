import React, { useEffect, useState } from 'react';
import {
  ComposedChart, Bar, Line, XAxis, YAxis, CartesianGrid,
  Tooltip, Legend, ResponsiveContainer,
} from 'recharts';
import { useLanguage } from '../LanguageContext';

interface CorrelationPoint {
  date: string;
  attacks: number;
  btc_usd: number | null;
  usd_krw: number | null;
}

interface CorrelationData {
  data: CorrelationPoint[];
  btc_corr: number;
  krw_corr: number;
  period_days: number;
  interpretation: string;
}

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

function corrColor(r: number): string {
  const abs = Math.abs(r);
  if (abs >= 0.6) return r > 0 ? '#ef4444' : '#3b82f6';
  if (abs >= 0.3) return r > 0 ? '#f97316' : '#60a5fa';
  return '#64748b';
}

// 상관계수 배지 텍스트 생성
function makeCorrLabel(r: number, t: (k: string) => string): string {
  const abs = Math.abs(r);
  if (abs >= 0.6) return `${r > 0 ? t('corrPositiveStrong') : t('corrNegativeStrong')} ${r.toFixed(2)}`;
  if (abs >= 0.3) return `${r > 0 ? t('corrPositiveWeak') : t('corrNegativeWeak')} ${r.toFixed(2)}`;
  return `${t('corrNone')} ${r.toFixed(2)}`;
}

// 상관관계 해석 텍스트 생성 (프론트엔드에서 다국어 처리)
function makeInterpretation(btcCorr: number, krwCorr: number, t: (k: string) => string): string {
  const strongest = Math.max(Math.abs(btcCorr), Math.abs(krwCorr));
  const indicator = Math.abs(btcCorr) >= Math.abs(krwCorr) ? 'BTC' : 'USD/KRW';
  const actualCorr = indicator === 'BTC' ? btcCorr : krwCorr;
  const dir = actualCorr > 0 ? t('corrDirPositive') : t('corrDirNegative');
  const r = strongest.toFixed(2);
  if (strongest >= 0.6) {
    return t('corrInterpStrong')
      .replace('{indicator}', indicator).replace('{dir}', dir).replace('{r}', r);
  }
  if (strongest >= 0.3) {
    return t('corrInterpWeak')
      .replace('{indicator}', indicator).replace('{dir}', dir).replace('{r}', r);
  }
  return t('corrInterpNone').replace('{r}', r);
}

const CustomTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{
      background: '#0f1e38', border: '1px solid #1e3a5f', borderRadius: 8,
      padding: '10px 14px', fontSize: 12,
    }}>
      <div style={{ color: '#94a3b8', marginBottom: 6, fontWeight: 600 }}>{label}</div>
      {payload.map((p: any) => (
        <div key={p.name} style={{ color: p.color, marginBottom: 2 }}>
          {p.name}: <strong>{typeof p.value === 'number' ? p.value.toLocaleString() : '-'}</strong>
        </div>
      ))}
    </div>
  );
};

const THREAT_TYPE_KEYS = [
  { value: '', labelKey: 'corrAllAttacks' },
  { value: '악성코드/랜섬웨어', labelKey: 'corrRansomware' },
  { value: 'APT/국가지원',      labelKey: 'corrAPT' },
  { value: '취약점/익스플로잇',  labelKey: 'corrVuln' },
  { value: '피싱/소셜엔지니어링', labelKey: 'corrPhishing' },
  { value: 'C2/봇넷',           labelKey: 'corrC2' },
  { value: '공급망공격',         labelKey: 'corrSupplyChain' },
] as const;

export default function CorrelationPanel() {
  const { t } = useLanguage();
  const [data, setData] = useState<CorrelationData | null>(null);
  const [view, setView] = useState<'btc' | 'krw'>('btc');
  const [threatType, setThreatType] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    const params = new URLSearchParams({ days: '30' });
    if (threatType) params.set('threat_type', threatType);
    fetch(`${BASE_URL}/dashboard/correlation?${params}`, { headers: getAuthHeaders() })
      .then(r => r.ok ? r.json() : null)
      .then(d => { setData(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, [threatType]);

  if (loading) {
    return (
      <div style={{ background: '#0a1628', borderRadius: 12, padding: '20px 24px', border: '1px solid #1e3a5f', minHeight: 280, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <span style={{ color: '#475569', fontSize: 13 }}>{t('corrAnalyzing')}</span>
      </div>
    );
  }

  if (!data) return null;

  const points = data.data;
  const showBtc = view === 'btc';
  const corrValue = showBtc ? data.btc_corr : data.krw_corr;
  const lineKey = showBtc ? 'btc_usd' : 'usd_krw';
  const lineLabel = showBtc ? 'BTC (USD)' : 'USD/KRW';
  const lineColor = showBtc ? '#f59e0b' : '#a78bfa';

  // Y2 도메인 계산
  const vals = points.map(p => showBtc ? (p.btc_usd ?? 0) : (p.usd_krw ?? 0)).filter(v => v > 0);
  const minV = Math.min(...vals);
  const maxV = Math.max(...vals);
  const pad = (maxV - minV) * 0.1 || 1;

  const tickFormatter = showBtc
    ? (v: number) => `$${(v / 1000).toFixed(0)}k`
    : (v: number) => `₩${v.toFixed(0)}`;

  return (
    <div style={{ background: '#080f1e', borderRadius: 14, padding: '20px 24px', border: '1px solid #1e3a5f' }}>
      {/* 헤더 */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16, flexWrap: 'wrap', gap: 10 }}>
        <div>
          <div style={{ fontSize: 14, fontWeight: 700, color: '#e2e8f0', marginBottom: 4 }}>
            {t('corrTitle')}
          </div>
          <div style={{ fontSize: 11, color: '#475569' }}>{t('corrSubtitle').replace('{days}', String(data.period_days))}</div>
        </div>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
          {/* 유형 필터 */}
          <select
            value={threatType}
            onChange={e => setThreatType(e.target.value)}
            style={{
              padding: '4px 10px', borderRadius: 6, border: '1px solid #1e3a5f',
              background: '#0d1b2e', color: '#93c5fd', fontSize: 12, cursor: 'pointer',
            }}
          >
            {THREAT_TYPE_KEYS.map(item => (
              <option key={item.value} value={item.value}>{t(item.labelKey as any)}</option>
            ))}
          </select>
          {/* 지표 전환 버튼 */}
          {(['btc', 'krw'] as const).map(v => (
            <button
              key={v}
              onClick={() => setView(v)}
              style={{
                padding: '5px 12px', borderRadius: 6, border: 'none', cursor: 'pointer', fontSize: 12, fontWeight: 600,
                background: view === v ? '#1e3a5f' : 'transparent',
                color: view === v ? '#93c5fd' : '#475569',
                transition: 'all .15s',
              }}
            >{v === 'btc' ? '🪙 BTC' : `💱 ${t('corrExchangeRate')}`}</button>
          ))}
        </div>
      </div>

      {/* 상관계수 배지 */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 14, flexWrap: 'wrap' }}>
        {[
          { label: t('corrBTC'), val: data.btc_corr },
          { label: t('corrKRW'), val: data.krw_corr },
        ].map(({ label, val }) => (
          <div key={label} style={{
            display: 'flex', alignItems: 'center', gap: 8,
            background: '#0d1b2e', border: `1px solid ${corrColor(val)}44`,
            borderRadius: 8, padding: '6px 12px',
          }}>
            <span style={{ fontSize: 11, color: '#64748b' }}>{label}</span>
            <span style={{ fontSize: 14, fontWeight: 800, color: corrColor(val) }}>
              r = {makeCorrLabel(val, t)}
            </span>
          </div>
        ))}
      </div>

      {/* 차트 */}
      <ResponsiveContainer width="100%" height={220}>
        <ComposedChart data={points} margin={{ top: 4, right: 16, left: 0, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e3a5f55" vertical={false} />
          <XAxis
            dataKey="date"
            tick={{ fontSize: 10, fill: '#475569' }}
            axisLine={false} tickLine={false}
            interval={Math.floor(points.length / 7)}
          />
          {/* 왼쪽: 공격 건수 */}
          <YAxis
            yAxisId="attacks"
            orientation="left"
            tick={{ fontSize: 10, fill: '#60a5fa' }}
            axisLine={false} tickLine={false}
            width={36}
          />
          {/* 오른쪽: 경제 지표 */}
          <YAxis
            yAxisId="econ"
            orientation="right"
            domain={[minV - pad, maxV + pad]}
            tickFormatter={tickFormatter}
            tick={{ fontSize: 10, fill: lineColor }}
            axisLine={false} tickLine={false}
            width={52}
          />
          <Tooltip content={<CustomTooltip />} />
          <Legend
            iconType="circle"
            iconSize={8}
            wrapperStyle={{ fontSize: 11, color: '#64748b', paddingTop: 8 }}
          />
          <Bar
            yAxisId="attacks"
            dataKey="attacks"
            name={t('corrAttackCount')}
            fill="#3b82f6"
            fillOpacity={0.7}
            radius={[2, 2, 0, 0]}
            maxBarSize={14}
          />
          <Line
            yAxisId="econ"
            dataKey={lineKey}
            name={lineLabel}
            stroke={lineColor}
            strokeWidth={2}
            dot={false}
            connectNulls
          />
        </ComposedChart>
      </ResponsiveContainer>

      {/* 해석 */}
      <div style={{
        marginTop: 12, padding: '10px 14px',
        background: '#0d1b2e', borderRadius: 8,
        borderLeft: `3px solid ${corrColor(corrValue)}`,
        fontSize: 12, color: '#94a3b8', lineHeight: 1.6,
      }}>
        🔍 {makeInterpretation(data.btc_corr, data.krw_corr, t)}
      </div>
    </div>
  );
}
