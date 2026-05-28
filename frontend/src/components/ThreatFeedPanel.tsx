import React, { useEffect, useRef, useState } from 'react';
import { ThreatFeed } from '../types';
import { useLanguage } from '../LanguageContext';
import './ThreatFeedPanel.css';

interface Props {
  feeds: ThreatFeed[];
}

function formatTime(detected_at: string | null, created_at: string): string {
  const dateStr = detected_at || created_at;
  const d = new Date(dateStr);
  if (isNaN(d.getTime())) return '-';
  const now = new Date();
  const isToday =
    d.getFullYear() === now.getFullYear() &&
    d.getMonth() === now.getMonth() &&
    d.getDate() === now.getDate();
  const hh = String(d.getHours()).padStart(2, '0');
  const mm = String(d.getMinutes()).padStart(2, '0');
  const ss = String(d.getSeconds()).padStart(2, '0');
  if (isToday) return `${hh}:${mm}:${ss}`;
  const mon = String(d.getMonth() + 1).padStart(2, '0');
  const dd = String(d.getDate()).padStart(2, '0');
  return `${mon}/${dd} ${hh}:${mm}`;
}

export default function ThreatFeedPanel({ feeds }: Props) {
  const { t } = useLanguage();
  const [newIds, setNewIds] = useState<Set<number>>(new Set());
  const prevFeedIds = useRef<number[]>([]);

  useEffect(() => {
    const prevIds = new Set(prevFeedIds.current);
    const added = feeds.filter(f => !prevIds.has(f.id)).map(f => f.id);
    if (added.length > 0) {
      setNewIds(new Set(added));
      const timer = setTimeout(() => setNewIds(new Set()), 1500);
      prevFeedIds.current = feeds.map(f => f.id);
      return () => clearTimeout(timer);
    }
    prevFeedIds.current = feeds.map(f => f.id);
  }, [feeds]);

  return (
    <div className="panel">
      <div className="panel-header">
        <h2 className="panel-title">{t('feedTitle')}</h2>
        <span className="feed-count">{feeds.length}{t('feedCount')}</span>
      </div>
      <div className="feed-list">
        {feeds.map((feed) => {
          const isNew = newIds.has(feed.id);
          const sevClass =
            feed.severity === '긴급' || feed.severity === 'CRITICAL' ? 'badge critical' :
            feed.severity === '높음'  || feed.severity === 'HIGH'     ? 'badge high' :
            feed.severity === '중간'  || feed.severity === 'MEDIUM'   ? 'badge medium' : 'badge low';
          const sevLabel =
            feed.severity === '긴급' || feed.severity === 'CRITICAL' ? t('sevCritical') :
            feed.severity === '높음'  || feed.severity === 'HIGH'     ? t('sevHigh') :
            feed.severity === '중간'  || feed.severity === 'MEDIUM'   ? t('sevMedium') : t('sevLow');
          return (
            <div key={feed.id} className={`feed-item ${isNew ? 'slide-in' : ''}`}>
              <span className={sevClass}>{sevLabel}</span>
              <span className="feed-title">{feed.title}</span>
              <span className="feed-time">{formatTime(feed.detected_at ?? null, feed.created_at)}</span>
            </div>
          );
        })}
        {feeds.length === 0 && (
          <div className="feed-empty">
            <div className="spinner" />
            {t('feedCollecting')}
          </div>
        )}
      </div>
    </div>
  );
}
