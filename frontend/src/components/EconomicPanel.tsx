import React from 'react';
import { EconomicIndicator } from '../types';
import { useLanguage } from '../LanguageContext';
import './EconomicPanel.css';

function formatUSD(value: number): string {
  return `$${value.toLocaleString('en-US', { minimumFractionDigits: 0, maximumFractionDigits: 0 })}`;
}

function formatKRW(value: number): string {
  if (value >= 100_000_000) {
    return `₩${(value / 100_000_000).toLocaleString('ko-KR', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}억`;
  }
  if (value >= 10_000) {
    return `₩${(value / 10_000).toLocaleString('ko-KR', { minimumFractionDigits: 0, maximumFractionDigits: 0 })}만`;
  }
  return `₩${value.toLocaleString('ko-KR', { maximumFractionDigits: 0 })}`;
}

function formatValue(indicator: EconomicIndicator): string {
  if (indicator.category === '암호화폐') {
    if (indicator.unit === 'KRW') return formatKRW(indicator.value);
    return formatUSD(indicator.value);
  }
  if (indicator.unit === 'KRW') return indicator.value.toLocaleString('ko-KR', { maximumFractionDigits: 1 });
  if (indicator.unit === 'JPY') return indicator.value.toLocaleString('ja-JP', { maximumFractionDigits: 2 });
  return indicator.value.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 4 });
}

function ChangeChip({ change }: { change: number }) {
  const up = change > 0;
  const zero = Math.abs(change) < 0.005;
  if (zero) return <span className="econ-change neutral">─ 0.00%</span>;
  return (
    <span className={`econ-change ${up ? 'up' : 'down'}`}>
      {up ? '▲' : '▼'} {Math.abs(change).toFixed(2)}%
    </span>
  );
}

interface CryptoPair {
  symbol: string;
  usd: EconomicIndicator | null;
  krw: EconomicIndicator | null;
}

interface Props {
  data: EconomicIndicator[];
}

export default function EconomicPanel({ data }: Props) {
  const { t } = useLanguage();
  const forex = data.filter(d => d.category === '환율');
  const cryptoAll = data.filter(d => d.category === '암호화폐');

  // BTC/USD + BTC/KRW를 하나의 쌍으로 묶기
  const symbols = Array.from(new Set(cryptoAll.map(c => c.name.split('/')[0])));
  const cryptoPairs: CryptoPair[] = symbols.map(sym => ({
    symbol: sym,
    usd: cryptoAll.find(c => c.name === `${sym}/USD`) ?? null,
    krw: cryptoAll.find(c => c.name === `${sym}/KRW`) ?? null,
  }));

  return (
    <div className="econ-panel">
      <div className="econ-header">
        <div className="econ-title-row">
          <span className="econ-icon">📈</span>
          <span className="econ-title">{t('panelEconomic')}</span>
        </div>
        <span className="econ-subtitle">{t('econSubtitle')}</span>
      </div>

      {forex.length > 0 && (
        <div className="econ-section">
          <div className="econ-section-label">💱 {t('forexRate')}</div>
          <div className="econ-grid">
            {forex.map(item => (
              <div key={item.name} className="econ-card">
                <div className="econ-card-name">{item.name}</div>
                <div className="econ-card-value">{formatValue(item)}</div>
                <ChangeChip change={item.change} />
              </div>
            ))}
          </div>
        </div>
      )}

      {cryptoPairs.length > 0 && (
        <div className="econ-section">
          <div className="econ-section-label">🪙 {t('crypto')}</div>
          <div className="econ-grid">
            {cryptoPairs.map(pair => {
              const change = pair.usd?.change ?? pair.krw?.change ?? 0;
              const isPos = change >= 0;
              return (
                <div key={pair.symbol} className={`econ-card econ-crypto ${isPos ? 'pos' : 'neg'}`}>
                  <div className="econ-card-name">{pair.symbol}</div>
                  {pair.usd && (
                    <div className="econ-crypto-row">
                      <span className="econ-crypto-currency">USD</span>
                      <span className="econ-card-value">{formatUSD(pair.usd.value)}</span>
                    </div>
                  )}
                  {pair.krw && (
                    <div className="econ-crypto-row">
                      <span className="econ-crypto-currency">KRW</span>
                      <span className="econ-card-value krw">{formatKRW(pair.krw.value)}</span>
                    </div>
                  )}
                  <ChangeChip change={change} />
                </div>
              );
            })}
          </div>
        </div>
      )}

      <div className="econ-note">{t('rateSource')}</div>
    </div>
  );
}
