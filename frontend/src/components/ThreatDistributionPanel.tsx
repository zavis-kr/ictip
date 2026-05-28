import React from 'react';
import { ThreatDistribution } from '../types';
import { useLanguage } from '../LanguageContext';
import { THREAT_TYPE_KEY } from '../i18n/valueI18n';
import './ThreatDistributionPanel.css';

interface Props {
  data: ThreatDistribution[];
}

export default function ThreatDistributionPanel({ data }: Props) {
  const { t } = useLanguage();
  return (
    <div className="panel">
      <h2 className="panel-title">{t('distTitle')}</h2>
      <div className="dist-list">
        {data.map((item) => (
          <div key={item.type} className="dist-item">
            <div className="dist-header">
              <span className="dist-type">{t(THREAT_TYPE_KEY[item.type] ?? item.type)}</span>
              <span className="dist-pct">{item.percentage}%</span>
            </div>
            <div className="dist-bar-bg">
              <div
                className="dist-bar-fill"
                style={{ width: `${item.percentage}%`, backgroundColor: item.color }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
