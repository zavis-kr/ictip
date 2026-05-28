import React, { useEffect, useRef, useState } from 'react';
import './StatCard.css';

interface StatCardProps {
  label: string;
  value: string;
  subValue?: string;
  change?: string;
  changePositive?: boolean;
  changeNeutral?: boolean;
  icon?: string;
  accent?: 'red' | 'green' | 'blue' | 'orange';
}

export default function StatCard({ label, value, subValue, change, changePositive, changeNeutral, icon, accent = 'blue' }: StatCardProps) {
  const [flash, setFlash] = useState(false);
  const prevValue = useRef(value);

  useEffect(() => {
    if (prevValue.current !== value && prevValue.current !== '') {
      setFlash(true);
      const t = setTimeout(() => setFlash(false), 800);
      prevValue.current = value;
      return () => clearTimeout(t);
    }
    prevValue.current = value;
  }, [value]);

  const changeClass = changeNeutral ? 'change neutral' : changePositive ? 'change positive' : 'change negative';
  const arrow = changeNeutral ? '' : changePositive ? '▲' : '▼';

  return (
    <div className={`stat-card accent-${accent} ${flash ? 'flash' : ''}`}>
      <div className="stat-header">
        {icon && <span className="stat-icon">{icon}</span>}
        <div className="stat-label">{label}</div>
      </div>
      <div className="stat-value">{value}</div>
      {subValue && <div className="stat-sub">{subValue}</div>}
      {change && (
        <div className={changeClass}>
          {arrow} {change}
        </div>
      )}
    </div>
  );
}
