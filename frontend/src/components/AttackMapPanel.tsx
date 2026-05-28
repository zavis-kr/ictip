import React, { useState } from 'react';
import { ComposableMap, Geographies, Geography } from 'react-simple-maps';
import { AttackMapEntry, GeoRiskEntry } from '../types';
import { useLanguage } from '../LanguageContext';
import { SEVERITY_KEY, TREND_KEY } from '../i18n/valueI18n';
import './AttackMapPanel.css';

const GEO_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json';

const A2_NUM: Record<string, number> = {
  AF:4,AL:8,DZ:12,AR:32,AM:51,AU:36,AT:40,AZ:31,BD:50,BY:112,BE:56,
  BR:76,BG:100,KH:116,CA:124,CL:152,CN:156,CO:170,HR:191,CU:192,
  CZ:203,DK:208,EG:818,EE:233,ET:231,FI:246,FR:250,GE:268,DE:276,
  GH:288,GR:300,HU:348,IN:356,ID:360,IR:364,IQ:368,IE:372,IL:376,
  IT:380,JP:392,JO:400,KZ:398,KE:404,KP:408,KR:410,KW:414,KG:417,
  LV:428,LB:422,LT:440,MY:458,MX:484,MD:498,MN:496,MA:504,MM:104,
  NL:528,NZ:554,NG:566,NO:578,PK:586,PE:604,PH:608,PL:616,PT:620,
  RO:642,RU:643,SA:682,RS:688,ZA:710,ES:724,LK:144,SE:752,CH:756,
  SY:760,TW:158,TH:764,TN:788,TR:792,UA:804,AE:784,GB:826,US:840,
  UZ:860,VE:862,VN:704,YE:887,SN:686,CM:120,GT:320,BO:68,PY:600,
  UY:858,EC:218,PA:591,CR:188,HN:340,NI:558,DO:214,
};

// 숫자 id → 알파2 코드 역매핑
const NUM_A2: Record<number, string> = Object.fromEntries(
  Object.entries(A2_NUM).map(([a2, num]) => [num, a2])
);

const RISK_LABEL_COLOR: Record<string, string> = {
  '긴급': '#dc2626', '높음': '#f97316', '중간': '#eab308', '낮음': '#22c55e',
};

interface TooltipData {
  countryName: string;
  attackCount: number;
  risk: GeoRiskEntry | null;
  isPartner: boolean;
  x: number;
  y: number;
}

interface Props {
  data: AttackMapEntry[];
  geoRisk: GeoRiskEntry[];
  partnerCodes?: string[];   // 우리 플랫폼 참여 국가
}

export default function AttackMapPanel({ data, geoRisk, partnerCodes = [] }: Props) {
  const { t } = useLanguage();
  const [tooltip, setTooltip] = useState<TooltipData | null>(null);

  // 파트너 국가 Set
  const partnerSet = new Set(partnerCodes.map(c => c.toUpperCase()));

  // 공격 데이터: numId → entry
  const countMap: Record<number, AttackMapEntry> = {};
  let maxCount = 1;
  for (const entry of data) {
    const num = A2_NUM[entry.country_code.toUpperCase()];
    if (num) {
      countMap[num] = entry;
      if (entry.count > maxCount) maxCount = entry.count;
    }
  }

  // 지정학적 리스크: cc → entry
  const riskMap: Record<string, GeoRiskEntry> = {};
  for (const r of geoRisk) riskMap[r.country_code.toUpperCase()] = r;

  /**
   * 색상 결정 우선순위:
   * 1. 지정학적 위험 국가 (리스크 점수 기반 빨강 계열)
   * 2. 파트너 국가 (파란색 계열)
   * 3. 공격 데이터만 있는 국가 (오렌지 계열)
   * 4. 기본 배경
   */
  function getColor(numId: number): string {
    const cc = NUM_A2[numId];
    if (!cc) return '#1a2744';

    const ccUp = cc.toUpperCase();
    const risk = riskMap[ccUp];
    const isPartner = partnerSet.has(ccUp);
    const attackEntry = countMap[numId];

    // 1) 고위험 국가: 리스크 점수 70+ → 빨강 계열
    if (risk && risk.score >= 70) {
      if (risk.score >= 90) return '#b91c1c';  // 극위험 (러시아, 북한)
      if (risk.score >= 80) return '#dc2626';  // 긴급 (중국, 대만)
      return '#c2410c';                         // 높음 (이란 등)
    }

    // 2) 파트너 국가 → 파란색 계열
    if (isPartner) {
      // 파트너지만 중간 리스크 존재 시 약간 다른 파란색
      if (risk && risk.score >= 50) return '#1d4ed8';
      return '#2563eb';
    }

    // 3) 중간 리스크 국가 (50-69) → 오렌지 계열
    if (risk && risk.score >= 50) {
      return '#d97706';
    }

    // 4) 공격 데이터만 있는 국가 → 연한 오렌지
    if (attackEntry) {
      const t = attackEntry.count / maxCount;
      if (t > 0.5) return '#92400e';
      return '#78350f';
    }

    return '#1a2744';
  }

  function getStrokeColor(numId: number): string {
    const cc = NUM_A2[numId];
    if (!cc) return '#0d1b2e';
    const ccUp = cc.toUpperCase();
    if (partnerSet.has(ccUp) && !(riskMap[ccUp]?.score >= 70)) return '#3b82f6';
    return '#0d1b2e';
  }

  const totalAttacks = data.reduce((s, d) => s + d.count, 0);
  const topCountries = [...data].sort((a, b) => b.count - a.count).slice(0, 5);

  return (
    <div className="attack-map-panel">
      <div className="amp-header">
        <div className="amp-title-row">
          <span className="amp-icon">🌐</span>
          <span className="amp-title">{t('ampTitle')}</span>
        </div>
        <span className="amp-total">{totalAttacks.toLocaleString()} {t('ampTotal')}</span>
      </div>

      <div className="amp-map-wrap">
        <ComposableMap
          projection="geoNaturalEarth1"
          projectionConfig={{ scale: 155, center: [10, 10] }}
          style={{ width: '100%', height: '100%' }}
        >
          <Geographies geography={GEO_URL}>
            {({ geographies }) =>
              geographies.map(geo => {
                const numId = Number(geo.id);
                const cc = NUM_A2[numId]?.toUpperCase();
                const attackEntry = countMap[numId];
                const risk = cc ? riskMap[cc] : null;
                const isPartner = cc ? partnerSet.has(cc) : false;
                const hasData = !!attackEntry || !!risk || isPartner;

                return (
                  <Geography
                    key={geo.rsmKey}
                    geography={geo}
                    fill={getColor(numId)}
                    stroke={getStrokeColor(numId)}
                    strokeWidth={isPartner && !risk?.score ? 0.8 : 0.4}
                    style={{
                      default: { outline: 'none' },
                      hover: {
                        fill: hasData ? '#60a5fa' : '#263354',
                        outline: 'none',
                        cursor: hasData ? 'pointer' : 'default',
                      },
                      pressed: { outline: 'none' },
                    }}
                    onMouseEnter={(e: React.MouseEvent) => {
                      if (hasData) {
                        setTooltip({
                          countryName: attackEntry?.country_name ?? risk?.country_name ?? cc ?? '',
                          attackCount: attackEntry?.count ?? 0,
                          risk: risk ?? null,
                          isPartner,
                          x: e.clientX,
                          y: e.clientY,
                        });
                      }
                    }}
                    onMouseMove={(e: React.MouseEvent) => {
                      if (tooltip) setTooltip(t => t ? { ...t, x: e.clientX, y: e.clientY } : null);
                    }}
                    onMouseLeave={() => setTooltip(null)}
                  />
                );
              })
            }
          </Geographies>
        </ComposableMap>

        {tooltip && (
          <div className="amp-tooltip" style={{ left: tooltip.x + 14, top: tooltip.y - 10 }}>
            <div className="amp-tt-country">{tooltip.countryName}</div>
            {tooltip.isPartner && (
              <div className="amp-tt-partner">🤝 {t('ampPartner')}</div>
            )}
            {tooltip.attackCount > 0 && (
              <div className="amp-tt-attacks">⚡ {t('ampAttack')} {tooltip.attackCount.toLocaleString()}</div>
            )}
            {tooltip.risk && (
              <>
                <div className="amp-tt-divider" />
                <div className="amp-tt-risk-row">
                  <span
                    className="amp-tt-level"
                    style={{ color: RISK_LABEL_COLOR[tooltip.risk.level] ?? '#94a3b8' }}
                  >
                    ● {t(SEVERITY_KEY[tooltip.risk.level] ?? 'sevMedium')}
                  </span>
                  <span className="amp-tt-score">{t('ampRisk')} {tooltip.risk.score}/100</span>
                  <span className="amp-tt-trend">
                    {tooltip.risk.trend === '상승' ? '▲' : tooltip.risk.trend === '하락' ? '▼' : '─'} {t(TREND_KEY[tooltip.risk.trend] ?? 'trendStable')}
                  </span>
                </div>
                <div className="amp-tt-factors">
                  {tooltip.risk.factors.slice(0, 3).map(f => (
                    <span key={f} className="amp-tt-factor">{f}</span>
                  ))}
                </div>
              </>
            )}
          </div>
        )}
      </div>

      {/* 범례 + 상위 공격국 */}
      <div className="amp-bottom">
        <div className="amp-legend">
          <div className="amp-legend-items">
            <div className="amp-legend-item">
              <span className="amp-legend-dot" style={{ background: '#b91c1c' }} />
              <span>{t('ampLegendVeryHigh')}</span>
            </div>
            <div className="amp-legend-item">
              <span className="amp-legend-dot" style={{ background: '#dc2626' }} />
              <span>{t('ampLegendHigh')}</span>
            </div>
            <div className="amp-legend-item">
              <span className="amp-legend-dot" style={{ background: '#c2410c' }} />
              <span>{t('ampLegendMedium')}</span>
            </div>
            <div className="amp-legend-item">
              <span className="amp-legend-dot" style={{ background: '#2563eb' }} />
              <span>{t('ampLegendPartner')}</span>
            </div>
          </div>
        </div>
        <div className="amp-top-list">
          {topCountries.map((c, i) => {
            const risk = riskMap[c.country_code.toUpperCase()];
            return (
              <div key={c.country_code} className="amp-top-item">
                <span className="amp-rank">#{i + 1}</span>
                <span className="amp-cc">{c.country_code}</span>
                <span className="amp-cname">{c.country_name}</span>
                {risk && (
                  <span
                    className="amp-risk-badge"
                    style={{ color: RISK_LABEL_COLOR[risk.level] ?? '#94a3b8' }}
                  >
                    {risk.level}
                  </span>
                )}
                <span className="amp-cnt">{c.count.toLocaleString()}</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
