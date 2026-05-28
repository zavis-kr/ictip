import React from 'react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell
} from 'recharts';
import { CountryShare } from '../types';
import { useLanguage } from '../LanguageContext';
import { COUNTRY_KEY } from '../i18n/valueI18n';
import './CountrySharePanel.css';

interface Props {
  data: CountryShare[];
}

const BAR_COLOR = '#3b82f6';
const BAR_HOVER = '#2563eb';

function formatK(val: number): string {
  if (val >= 1000) return `${(val / 1000).toFixed(1)}K`;
  return `${val}`;
}

export default function CountrySharePanel({ data }: Props) {
  const { t } = useLanguage();
  const top5 = data.slice(0, 5);

  // 번역된 국가명 또는 country_code로 표시용 데이터 변환
  const chartData = top5.map(item => ({
    ...item,
    displayName: COUNTRY_KEY[item.country_code]
      ? t(COUNTRY_KEY[item.country_code]!)
      : item.country_code, // 번역 없으면 2자리 코드 표시
  }));

  return (
    <div className="panel country-share-panel">
      <h2 className="panel-title">{t('countryShareTitle')}</h2>
      <div className="country-chart-wrap">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={chartData} margin={{ top: 20, right: 10, left: -20, bottom: 5 }}>
            <XAxis dataKey="displayName" tick={{ fontSize: 12, fill: '#cbd5e1' }} axisLine={false} tickLine={false} />
            <YAxis tick={{ fontSize: 12, fill: '#64748b' }} axisLine={false} tickLine={false} tickFormatter={formatK} />
            <Tooltip
              formatter={(value: number) => [`${formatK(value)}${t('countUnit')}`, t('countryChartTooltip')]}
              labelFormatter={(label) => label}
              contentStyle={{ borderRadius: 8, border: '1px solid #334155', background: '#1e293b', fontSize: 13 }}
            />
            <Bar dataKey="ioc_shared" radius={[4, 4, 0, 0]} label={{ position: 'top', fontSize: 12, fill: '#94a3b8', formatter: formatK }}>
              {chartData.map((_, i) => (
                <Cell key={i} fill={i < 2 ? BAR_HOVER : BAR_COLOR} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
      <p className="chart-footnote">{t('countryChartFootnote')}</p>
    </div>
  );
}
