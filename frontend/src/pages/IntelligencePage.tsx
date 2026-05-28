import React, { useEffect, useState, useCallback, useRef } from 'react';
import { api } from '../api';
import { useLanguage } from '../LanguageContext';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Legend, Area, AreaChart, BarChart, Bar, Cell
} from 'recharts';
import './pages.css';
import './IntelligencePage.css';

type Tab = 'trend' | 'graph' | 'rules' | 'report' | 'siem' | 'darkweb';

const TAB_IDS: Tab[] = ['trend', 'graph', 'rules', 'report', 'siem', 'darkweb'];
const TAB_ICONS: Record<Tab, string> = {
  trend: '📈', graph: '🕸', rules: '📋', report: '📄', siem: '🔗', darkweb: '🕵',
};
const TAB_LABEL_KEYS: Record<Tab, string> = {
  trend: 'tabTrend', graph: 'tabGraph', rules: 'tabRules',
  report: 'tabReport', siem: 'tabSIEM', darkweb: 'tabDarkweb',
};

// ─── 위협 트렌드 예측 ─────────────────────────────────────────────────────────
function TrendTab() {
  const { t } = useLanguage();
  const [trend, setTrend] = useState<any>(null);
  const [forecast, setForecast] = useState<any>(null);
  const [hotspot, setHotspot] = useState<any>(null);
  const [actorActivity, setActorActivity] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.allSettled([
      api.getTrendData(),
      api.getForecast(),
      api.getHotspot(),
      api.getActorActivity(),
    ]).then(([t, f, h, a]) => {
      if (t.status === 'fulfilled') setTrend(t.value);
      if (f.status === 'fulfilled') setForecast(f.value);
      if (h.status === 'fulfilled') setHotspot(h.value);
      if (a.status === 'fulfilled') setActorActivity(a.value);
      setLoading(false);
    });
  }, []);

  if (loading) return <div className="intel-loading">{t('trendAnalyzing')}</div>;

  // 트렌드 + 예측 합치기
  const historicalData = (trend?.data || []).map((d: any) => ({
    date: d.date?.slice(5), count: d.count, type: 'actual'
  }));
  const forecastData = (forecast?.forecast || []).map((d: any) => ({
    date: d.date?.slice(5), predicted: d.predicted_count,
    lower: d.lower_bound, upper: d.upper_bound, type: 'forecast'
  }));

  const hotspotTypes = (hotspot?.top_threat_types || []).slice(0, 6);
  const COLORS = ['#dc2626','#f97316','#eab308','#22c55e','#3b82f6','#8b5cf6'];

  return (
    <div className="intel-section">
      <div className="intel-grid-2">
        {/* 트렌드 차트 */}
        <div className="intel-card">
          <h3 className="intel-card-title">{t('trendTitle30d')}</h3>
          {trend && (
            <div style={{ marginBottom: 12, display: 'flex', gap: 16, flexWrap: 'wrap' }}>
              <div className="intel-stat"><span>{t('trendTotalThreats')}</span><strong>{(trend.total || 0).toLocaleString()}</strong></div>
              <div className="intel-stat"><span>{t('trendPeriod')}</span><strong>{trend.period_days}{t('trendDayUnit')}</strong></div>
              <div className="intel-stat"><span>{t('trendDailyAvg')}</span><strong>{trend.total ? (trend.total / trend.period_days).toFixed(1) : '0'}</strong></div>
            </div>
          )}
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={historicalData}>
              <defs>
                <linearGradient id="tg" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b"/>
              <XAxis dataKey="date" tick={{ fontSize: 11, fill: '#64748b' }} axisLine={false}/>
              <YAxis tick={{ fontSize: 11, fill: '#64748b' }} axisLine={false}/>
              <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', fontSize: 12 }}/>
              <Area type="monotone" dataKey="count" stroke="#3b82f6" fill="url(#tg)" strokeWidth={2} dot={false}/>
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* 예측 차트 */}
        <div className="intel-card">
          <h3 className="intel-card-title">{t('forecastTitle')}</h3>
          {forecast && (
            <div style={{ marginBottom: 12, display: 'flex', gap: 16 }}>
              <div className="intel-stat"><span>{t('forecastBaseAvg')}</span><strong>{forecast.base_avg?.toFixed(1)}</strong></div>
              <div className="intel-stat"><span>{t('forecastMethod')}</span><strong style={{ fontSize: 11 }}>{t('forecastMethodName')}</strong></div>
            </div>
          )}
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={forecastData}>
              <defs>
                <linearGradient id="fg" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#a855f7" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="#a855f7" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b"/>
              <XAxis dataKey="date" tick={{ fontSize: 11, fill: '#64748b' }} axisLine={false}/>
              <YAxis tick={{ fontSize: 11, fill: '#64748b' }} axisLine={false}/>
              <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', fontSize: 12 }}/>
              <Area type="monotone" dataKey="upper" stroke="none" fill="url(#fg)" strokeWidth={0}/>
              <Line type="monotone" dataKey="predicted" stroke="#a855f7" strokeWidth={2} dot={{ r: 3 }}/>
              <Line type="monotone" dataKey="lower" stroke="#64748b" strokeWidth={1} strokeDasharray="4 2" dot={false}/>
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* 핫스팟: 위협 유형 */}
        <div className="intel-card">
          <h3 className="intel-card-title">{t('hotspotTitle')}</h3>
          {hotspotTypes.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={hotspotTypes} layout="vertical" margin={{ left: 80 }}>
                <XAxis type="number" tick={{ fontSize: 11, fill: '#64748b' }} axisLine={false}/>
                <YAxis type="category" dataKey="threat_type" tick={{ fontSize: 11, fill: '#cbd5e1' }} axisLine={false} width={80}/>
                <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', fontSize: 12 }}/>
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {hotspotTypes.map((_: any, i: number) => (
                    <Cell key={i} fill={COLORS[i % COLORS.length]}/>
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <p style={{ color: '#64748b', textAlign: 'center', padding: '40px 0' }}>{t('hotspotNoData')}</p>
          )}
        </div>

        {/* 요일별 패턴 */}
        <div className="intel-card">
          <h3 className="intel-card-title">{t('weeklyPatternTitle')}</h3>
          {(actorActivity?.weekly_activity_pattern?.length > 0) ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={actorActivity.weekly_activity_pattern}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b"/>
                <XAxis dataKey="day" tick={{ fontSize: 11, fill: '#64748b' }} axisLine={false}/>
                <YAxis tick={{ fontSize: 11, fill: '#64748b' }} axisLine={false}/>
                <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', fontSize: 12 }}/>
                <Bar dataKey="count" fill="#6366f1" radius={[4, 4, 0, 0]}/>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <p style={{ color: '#64748b', textAlign: 'center', padding: '40px 0', fontSize: 13 }}>{t('weeklyPatternNoData')}</p>
          )}
        </div>

        {/* 행위자 활동 */}
        <div className="intel-card">
          <h3 className="intel-card-title">{t('actorActivityTitle')}</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 8 }}>
            {(actorActivity?.actor_profiles || []).slice(0, 8).map((a: any, i: number) => (
              <div key={a.actor_tag} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontSize: 11, color: '#475569', width: 20, textAlign: 'right' }}>#{i+1}</span>
                <span style={{ fontSize: 13, color: '#7c3aed', fontWeight: 600, minWidth: 120 }}>{a.actor_tag}</span>
                <div style={{ flex: 1, background: '#1e293b', borderRadius: 4, height: 8, overflow: 'hidden' }}>
                  <div style={{
                    height: '100%', background: '#7c3aed', borderRadius: 4,
                    width: `${(a.count / (actorActivity?.actor_profiles?.[0]?.count || 1)) * 100}%`
                  }}/>
                </div>
                <span style={{ fontSize: 12, color: '#64748b', minWidth: 30, textAlign: 'right' }}>{a.count}</span>
              </div>
            ))}
            {(!actorActivity?.actor_profiles?.length) && (
              <p style={{ color: '#64748b', fontSize: 13 }}>{t('actorActivityNoData')}</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── IOC 관계 그래프 ──────────────────────────────────────────────────────────
// ─── 노드 타입별 설정 ────────────────────────────────────────────────────────
const NODE_CONFIG_BASE: Record<string, { fill: string; stroke: string; glow: string; labelKey: string; icon: string }> = {
  threat:   { fill: '#0f2d6b', stroke: '#3b82f6', glow: '#3b82f640', labelKey: 'nodeTypeThreat',   icon: '⚠' },
  actor:    { fill: '#3f0a0a', stroke: '#ef4444', glow: '#ef444440', labelKey: 'nodeTypeActor',    icon: '👤' },
  ioc:      { fill: '#3b1a00', stroke: '#f59e0b', glow: '#f59e0b40', labelKey: 'iocCount',         icon: '🔗' },
  campaign: { fill: '#1e0a3f', stroke: '#a855f7', glow: '#a855f740', labelKey: 'nodeTypeCampaign', icon: '🎯' },
};

interface FNode {
  id: string; label: string; type: string; size: number;
  x: number; y: number; vx: number; vy: number;
}
interface FEdge { source: string; target: string; label?: string; }

function runForceSimulation(nodes: FNode[], edges: FEdge[], W: number, H: number, steps = 200) {
  const nodeMap: Record<string, FNode> = {};
  nodes.forEach(n => nodeMap[n.id] = n);

  for (let step = 0; step < steps; step++) {
    const cool = 1 - step / steps;
    // 반발력
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i], b = nodes[j];
        const dx = b.x - a.x || 0.1, dy = b.y - a.y || 0.1;
        const d2 = dx * dx + dy * dy;
        const d  = Math.sqrt(d2) || 1;
        const f  = 5000 / d2;
        a.vx -= dx / d * f; a.vy -= dy / d * f;
        b.vx += dx / d * f; b.vy += dy / d * f;
      }
    }
    // 스프링 인력
    for (const e of edges) {
      const s = nodeMap[e.source], t = nodeMap[e.target];
      if (!s || !t) continue;
      const dx = t.x - s.x, dy = t.y - s.y;
      const d = Math.sqrt(dx * dx + dy * dy) || 1;
      const f = 0.05 * (d - 130);
      s.vx += dx / d * f; s.vy += dy / d * f;
      t.vx -= dx / d * f; t.vy -= dy / d * f;
    }
    // 중심 중력 + 감쇠
    for (const n of nodes) {
      n.vx += (W / 2 - n.x) * 0.008;
      n.vy += (H / 2 - n.y) * 0.008;
      n.vx *= 0.78; n.vy *= 0.78;
      n.x = Math.max(70, Math.min(W - 70, n.x + n.vx * cool));
      n.y = Math.max(70, Math.min(H - 70, n.y + n.vy * cool));
    }
  }
}

function GraphTab() {
  const { t } = useLanguage();
  const svgRef = useRef<SVGSVGElement>(null);
  const [nodes, setNodes] = useState<FNode[]>([]);
  const [edges, setEdges] = useState<FEdge[]>([]);
  const [graphData, setGraphData] = useState<any>(null);
  const [threatId, setThreatId] = useState('');
  const [actorName, setActorName] = useState('');
  const [loading, setLoading] = useState(false);
  const [mode, setMode] = useState<'overview' | 'threat' | 'actor'>('overview');
  const [hoverId, setHoverId] = useState<string | null>(null);

  const NODE_CONFIG = Object.fromEntries(
    Object.entries(NODE_CONFIG_BASE).map(([k, v]) => [k, { ...v, label: t(v.labelKey as any) }])
  );
  // pan & zoom
  const [vb, setVb] = useState({ x: 0, y: 0, w: 900, h: 520 });
  const dragRef = useRef<{ active: boolean; sx: number; sy: number; ox: number; oy: number } | null>(null);

  const W = 900, H = 520;

  // 그래프 계산
  useEffect(() => {
    if (!graphData) return;
    const rawNodes: any[] = graphData.nodes || [];
    const rawEdges: any[] = graphData.edges || [];
    const fnodes: FNode[] = rawNodes.map((n) => {
      let bx = W / 2, by = H / 2;
      if (n.type === 'actor')    { bx = W * 0.78; by = H * 0.5; }
      else if (n.type === 'ioc') { bx = W * 0.25; by = H * 0.5; }
      else if (n.type === 'threat') { bx = W * 0.5; by = H * 0.32; }
      return {
        id: n.id, label: n.label || n.id, type: n.type || 'ioc',
        size: n.size || 12,
        x: bx + (Math.random() - 0.5) * 200,
        y: by + (Math.random() - 0.5) * 160,
        vx: 0, vy: 0,
      };
    });
    const fedges: FEdge[] = rawEdges.map((e: any) => ({ source: e.source, target: e.target }));
    runForceSimulation(fnodes, fedges, W, H);
    setNodes([...fnodes]);
    setEdges(fedges);
    setVb({ x: 0, y: 0, w: W, h: H });
  }, [graphData]);

  // 데이터 로드
  const loadOverview = useCallback(async () => {
    setLoading(true);
    try { const d = await api.getOverviewGraph(); setGraphData(d); }
    catch (e) { console.error(e); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { loadOverview(); }, [loadOverview]);

  const handleSearch = async () => {
    setLoading(true);
    try {
      let d;
      if (mode === 'threat' && threatId) d = await api.getIOCGraph(Number(threatId));
      else if (mode === 'actor' && actorName) d = await api.getActorGraph(actorName);
      else d = await api.getOverviewGraph();
      setGraphData(d);
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  };

  // pan
  const onSvgMouseDown = (e: React.MouseEvent<SVGSVGElement>) => {
    if ((e.target as Element).closest('.graph-node')) return;
    dragRef.current = { active: true, sx: e.clientX, sy: e.clientY, ox: vb.x, oy: vb.y };
  };
  const onSvgMouseMove = (e: React.MouseEvent<SVGSVGElement>) => {
    if (!dragRef.current?.active) return;
    const dx = (e.clientX - dragRef.current.sx) * (vb.w / (svgRef.current?.clientWidth || W));
    const dy = (e.clientY - dragRef.current.sy) * (vb.h / (svgRef.current?.clientHeight || H));
    setVb(v => ({ ...v, x: dragRef.current!.ox - dx, y: dragRef.current!.oy - dy }));
  };
  const onSvgMouseUp = () => { dragRef.current = null; };
  const onSvgWheel = (e: React.WheelEvent<SVGSVGElement>) => {
    e.preventDefault();
    const factor = e.deltaY > 0 ? 1.15 : 0.87;
    const rect = svgRef.current!.getBoundingClientRect();
    const mx = (e.clientX - rect.left) / rect.width;
    const my = (e.clientY - rect.top) / rect.height;
    setVb(v => {
      const nw = Math.max(200, Math.min(1800, v.w * factor));
      const nh = nw * (H / W);
      return { x: v.x + (v.w - nw) * mx, y: v.y + (v.h - nh) * my, w: nw, h: nh };
    });
  };

  const nodeMap = Object.fromEntries(nodes.map(n => [n.id, n]));
  const hoverNode = hoverId ? nodeMap[hoverId] : null;

  // 노드 반지름
  const nr = (n: FNode) => Math.max((n.size || 12) * 0.65, 14);

  return (
    <div className="intel-section">
      <div className="intel-card" style={{ padding: '16px 20px' }}>

        {/* 컨트롤 */}
        <div style={{ display: 'flex', gap: 8, marginBottom: 14, flexWrap: 'wrap', alignItems: 'center' }}>
          <div className="intel-tab-group">
            {(['overview', 'threat', 'actor'] as const).map(m => (
              <button key={m} className={`intel-tab-btn ${mode === m ? 'active' : ''}`} onClick={() => setMode(m)}>
                {m === 'overview' ? t('graphOverview') : m === 'threat' ? t('graphThreatId') : t('graphActor')}
              </button>
            ))}
          </div>
          {mode === 'threat' && <input className="form-input" style={{ width: 110 }} placeholder={t('graphThreatId')} value={threatId} onChange={e => setThreatId(e.target.value)} onKeyDown={e => e.key === 'Enter' && handleSearch()}/>}
          {mode === 'actor'  && <input className="form-input" style={{ width: 150 }} placeholder="APT28, Lazarus…" value={actorName} onChange={e => setActorName(e.target.value)} onKeyDown={e => e.key === 'Enter' && handleSearch()}/>}
          <button className="btn btn-primary" onClick={handleSearch} disabled={loading} style={{ minWidth: 88 }}>
            {loading ? t('graphAnalyzing') : t('graphQuery')}
          </button>
          <button className="btn btn-secondary" onClick={() => setVb({ x: 0, y: 0, w: W, h: H })} title={t('graphReset')}>⟳</button>
        </div>

        {/* 통계 + 범례 */}
        {graphData && (
          <div style={{ display: 'flex', gap: 20, alignItems: 'center', marginBottom: 12, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 12, color: '#64748b' }}>{t('graphNodes')} <strong style={{ color: '#e2e8f0' }}>{graphData.total_nodes}</strong></span>
            <span style={{ fontSize: 12, color: '#64748b' }}>{t('graphEdges')} <strong style={{ color: '#e2e8f0' }}>{graphData.total_edges}</strong></span>
            <div style={{ display: 'flex', gap: 14, marginLeft: 'auto', alignItems: 'center' }}>
              {Object.entries(NODE_CONFIG).map(([type, cfg]) => (
                <span key={type} style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11 }}>
                  <svg width="14" height="14"><circle cx="7" cy="7" r="5" fill={cfg.fill} stroke={cfg.stroke} strokeWidth="2"/></svg>
                  <span style={{ color: '#94a3b8' }}>{cfg.label}</span>
                </span>
              ))}
            </div>
            <span style={{ fontSize: 10, color: '#475569' }}>{t('graphScrollHint')}</span>
          </div>
        )}

        {/* SVG 그래프 */}
        <div style={{ position: 'relative', borderRadius: 12, overflow: 'hidden', border: '1px solid #1e3a5f', background: '#05101f' }}>
          <svg
            ref={svgRef}
            viewBox={`${vb.x} ${vb.y} ${vb.w} ${vb.h}`}
            style={{ width: '100%', display: 'block', cursor: dragRef.current ? 'grabbing' : 'grab', userSelect: 'none' }}
            height={Math.round((svgRef.current?.clientWidth || 900) * H / W) || 520}
            onMouseDown={onSvgMouseDown}
            onMouseMove={onSvgMouseMove}
            onMouseUp={onSvgMouseUp}
            onMouseLeave={onSvgMouseUp}
            onWheel={onSvgWheel}
          >
            <defs>
              {/* 배경 그라디언트 */}
              <radialGradient id="bg-grad" cx="50%" cy="45%" r="65%">
                <stop offset="0%"   stopColor="#0d1f3c"/>
                <stop offset="100%" stopColor="#050d1a"/>
              </radialGradient>
              {/* 화살표 마커 (타입별) */}
              {Object.entries(NODE_CONFIG).map(([type, cfg]) => (
                <marker key={type} id={`arrow-${type}`} markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
                  <path d="M0,0 L0,6 L8,3 z" fill={cfg.stroke + '99'}/>
                </marker>
              ))}
              {/* 발광 필터 */}
              {Object.entries(NODE_CONFIG).map(([type, cfg]) => (
                <filter key={type} id={`glow-${type}`} x="-50%" y="-50%" width="200%" height="200%">
                  <feGaussianBlur stdDeviation="4" result="blur"/>
                  <feFlood floodColor={cfg.stroke} floodOpacity="0.6" result="color"/>
                  <feComposite in="color" in2="blur" operator="in" result="shadow"/>
                  <feMerge><feMergeNode in="shadow"/><feMergeNode in="SourceGraphic"/></feMerge>
                </filter>
              ))}
              {/* 점선 에지 애니메이션 */}
              <style>{`
                .graph-edge { transition: opacity .2s; }
                .graph-edge.dimmed { opacity: 0.12; }
                .graph-edge.active { opacity: 1; }
                .graph-node { transition: transform .15s; cursor: pointer; }
                .graph-node:hover { transform-origin: center; }
                .node-circle { transition: r .15s, filter .15s; }
              `}</style>
            </defs>

            {/* 배경 */}
            <rect x={vb.x - 200} y={vb.y - 200} width={vb.w + 400} height={vb.h + 400} fill="url(#bg-grad)"/>

            {/* 격자 점 패턴 */}
            {Array.from({ length: Math.ceil(vb.h / 40) + 2 }, (_, iy) =>
              Array.from({ length: Math.ceil(vb.w / 40) + 2 }, (_, ix) => {
                const px = vb.x + ix * 40 - (vb.x % 40);
                const py = vb.y + iy * 40 - (vb.y % 40);
                return <circle key={`d-${ix}-${iy}`} cx={px} cy={py} r="0.8" fill="#ffffff08"/>;
              })
            )}

            {/* 엣지 */}
            {edges.map((e, i) => {
              const s = nodeMap[e.source], t = nodeMap[e.target];
              if (!s || !t) return null;
              const isActive = hoverId === e.source || hoverId === e.target;
              const isDimmed = hoverId !== null && !isActive;
              const cfg = NODE_CONFIG[t.type] || NODE_CONFIG.ioc;
              const angle = Math.atan2(t.y - s.y, t.x - s.x);
              const sr = nr(s), tr = nr(t);
              const x1 = s.x + sr * Math.cos(angle);
              const y1 = s.y + sr * Math.sin(angle);
              const x2 = t.x - (tr + 6) * Math.cos(angle);
              const y2 = t.y - (tr + 6) * Math.sin(angle);
              return (
                <g key={i} className={`graph-edge ${isDimmed ? 'dimmed' : isActive ? 'active' : ''}`}>
                  <line x1={x1} y1={y1} x2={x2} y2={y2}
                    stroke={isActive ? cfg.stroke : '#2a4a6a'}
                    strokeWidth={isActive ? 1.8 : 1}
                    strokeOpacity={isActive ? 0.9 : 0.4}
                    markerEnd={`url(#arrow-${t.type})`}
                  />
                </g>
              );
            })}

            {/* 노드 */}
            {nodes.map((n) => {
              const cfg = NODE_CONFIG[n.type] || NODE_CONFIG.ioc;
              const r = nr(n);
              const isHov = hoverId === n.id;
              const isDimmed = hoverId !== null && !isHov &&
                !edges.some(e => (e.source === hoverId && e.target === n.id) || (e.target === hoverId && e.source === n.id));
              const rawLabel = n.label.replace(/^\[.*?\]\s*/, '');
              const label = rawLabel.length > 20 ? rawLabel.slice(0, 20) + '…' : rawLabel;

              return (
                <g key={n.id} className="graph-node"
                  style={{ opacity: isDimmed ? 0.2 : 1, transition: 'opacity .2s' }}
                  onMouseEnter={() => setHoverId(n.id)}
                  onMouseLeave={() => setHoverId(null)}
                >
                  {/* 외곽 발광 링 (hover) */}
                  {isHov && (
                    <circle cx={n.x} cy={n.y} r={r + 10}
                      fill="none" stroke={cfg.stroke} strokeWidth="1.5" strokeOpacity="0.35"
                    />
                  )}
                  {/* 노드 배경 원 */}
                  <circle cx={n.x} cy={n.y} r={r}
                    fill={cfg.fill}
                    stroke={cfg.stroke}
                    strokeWidth={isHov ? 2.5 : 1.5}
                    filter={isHov ? `url(#glow-${n.type})` : undefined}
                  />
                  {/* 내부 하이라이트 */}
                  <circle cx={n.x - r * 0.28} cy={n.y - r * 0.28} r={r * 0.38}
                    fill="white" fillOpacity={isHov ? 0.1 : 0.06}
                  />
                  {/* 타입 아이콘 텍스트 */}
                  <text x={n.x} y={n.y + 1} textAnchor="middle" dominantBaseline="middle"
                    fontSize={Math.max(r * 0.8, 10)} style={{ pointerEvents: 'none', userSelect: 'none' }}>
                    {n.type === 'threat' ? '⚠' : n.type === 'actor' ? '👤' : n.type === 'campaign' ? '🎯' : '🔗'}
                  </text>
                  {/* 라벨 배경 */}
                  <rect
                    x={n.x - Math.min(label.length * 3.8 + 8, 100)}
                    y={n.y + r + 5}
                    width={Math.min(label.length * 7.6 + 16, 200)}
                    height={17}
                    rx="4"
                    fill="#0a1628"
                    fillOpacity={isHov ? 0.95 : 0.8}
                    stroke={isHov ? cfg.stroke : 'none'}
                    strokeWidth="0.5"
                    strokeOpacity="0.6"
                    style={{ pointerEvents: 'none' }}
                  />
                  {/* 라벨 텍스트 */}
                  <text x={n.x} y={n.y + r + 14}
                    textAnchor="middle" dominantBaseline="middle"
                    fontSize={isHov ? 11 : 10}
                    fontWeight={isHov ? 600 : 400}
                    fill={isHov ? '#f1f5f9' : '#8ba3bf'}
                    fontFamily="-apple-system, sans-serif"
                    style={{ pointerEvents: 'none', userSelect: 'none' }}
                  >{label}</text>
                </g>
              );
            })}
          </svg>

          {/* 호버 상세 패널 */}
          {hoverNode && (() => {
            const cfg = NODE_CONFIG[hoverNode.type] || NODE_CONFIG.ioc;
            const connected = edges.filter(e => e.source === hoverNode.id || e.target === hoverNode.id);
            return (
              <div style={{
                position: 'absolute', bottom: 14, left: 14,
                background: '#0b1a30f0', backdropFilter: 'blur(8px)',
                border: `1px solid ${cfg.stroke}55`,
                borderRadius: 10, padding: '10px 14px',
                maxWidth: 260, pointerEvents: 'none',
                boxShadow: `0 0 18px ${cfg.stroke}22`,
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 5 }}>
                  <span style={{ fontSize: 15 }}>{cfg.icon}</span>
                  <span style={{ fontSize: 11, fontWeight: 700, color: cfg.stroke, letterSpacing: 1 }}>
                    {cfg.label.toUpperCase()}
                  </span>
                  <span style={{ marginLeft: 'auto', fontSize: 10, color: '#475569', background: '#1e3a5f55', padding: '1px 6px', borderRadius: 4 }}>
                    {t('graphConnections')} {connected.length}
                  </span>
                </div>
                <div style={{ fontSize: 12, color: '#cbd5e1', wordBreak: 'break-all', lineHeight: 1.5 }}>
                  {hoverNode.label.replace(/^\[.*?\]\s*/, '')}
                </div>
              </div>
            );
          })()}

          {/* 로딩 */}
          {loading && (
            <div style={{ position: 'absolute', inset: 0, background: '#050d1acc', display: 'flex', alignItems: 'center', justifyContent: 'center', borderRadius: 12 }}>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: 28, marginBottom: 8 }}>🔄</div>
                <div style={{ fontSize: 13, color: '#60a5fa' }}>{t('graphLoading')}</div>
              </div>
            </div>
          )}
          {!loading && nodes.length === 0 && (
            <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <span style={{ fontSize: 13, color: '#475569' }}>{t('graphNoData')}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── YARA / Sigma 룰 ──────────────────────────────────────────────────────────
function RulesTab() {
  const { t } = useLanguage();
  const [threatId, setThreatId] = useState('');
  const [rules, setRules] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [activeRule, setActiveRule] = useState<'yara' | 'sigma'>('yara');

  const generate = async () => {
    if (!threatId) return;
    setLoading(true);
    try {
      const data = await api.getAllRules(Number(threatId));
      setRules(data);
    } catch (e: any) {
      alert(e.message || t('rulesGenerateError'));
    } finally {
      setLoading(false);
    }
  };

  const copyRule = (text: string) => {
    navigator.clipboard.writeText(text);
    alert(t('rulesCopied'));
  };

  const downloadRule = (text: string, filename: string) => {
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="intel-section">
      <div className="intel-card">
        <h3 className="intel-card-title">{t('rulesTitle')}</h3>
        <p style={{ fontSize: 13, color: '#64748b', marginBottom: 16 }}>
          {t('rulesDesc')}
        </p>
        <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
          <input
            className="form-input" style={{ maxWidth: 200 }}
            placeholder={t('rulesThreatIdPH')}
            value={threatId} onChange={e => setThreatId(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && generate()}
          />
          <button className="btn btn-primary" onClick={generate} disabled={loading || !threatId}>
            {loading ? t('rulesGenerating') : t('rulesGenerate')}
          </button>
        </div>

        {rules && (
          <>
            <div className="intel-tab-group" style={{ marginBottom: 12 }}>
              <button className={`intel-tab-btn ${activeRule === 'yara' ? 'active' : ''}`} onClick={() => setActiveRule('yara')}>
                YARA
              </button>
              <button className={`intel-tab-btn ${activeRule === 'sigma' ? 'active' : ''}`} onClick={() => setActiveRule('sigma')}>
                Sigma
              </button>
            </div>

            <div style={{ position: 'relative' }}>
              <div style={{ display: 'flex', gap: 6, position: 'absolute', top: 8, right: 8, zIndex: 1 }}>
                <button className="btn btn-secondary" style={{ fontSize: 11, padding: '3px 8px' }}
                  onClick={() => copyRule(activeRule === 'yara' ? rules.yara : rules.sigma)}>
                  {t('rulesCopy')}
                </button>
                <button className="btn btn-secondary" style={{ fontSize: 11, padding: '3px 8px' }}
                  onClick={() => downloadRule(
                    activeRule === 'yara' ? rules.yara : rules.sigma,
                    activeRule === 'yara' ? `threat_${rules.threat_id}.yar` : `threat_${rules.threat_id}.yml`
                  )}>
                  {t('rulesDownload')}
                </button>
              </div>
              <pre style={{
                background: '#060d1a', border: '1px solid #1e293b', borderRadius: 8,
                padding: '12px 16px', fontSize: 12, color: '#22d3ee', fontFamily: 'monospace',
                whiteSpace: 'pre-wrap', maxHeight: 400, overflow: 'auto', margin: 0,
              }}>
                {activeRule === 'yara' ? rules.yara : rules.sigma}
              </pre>
            </div>
            <p style={{ fontSize: 11, color: '#475569', marginTop: 8 }}>{t('rulesGeneratedAt')}: {new Date(rules.generated_at).toLocaleString()}</p>
          </>
        )}
      </div>
    </div>
  );
}

// ─── PDF 보고서 ───────────────────────────────────────────────────────────────
function ReportTab() {
  const { t } = useLanguage();
  const [threatId, setThreatId] = useState('');
  const [downloading, setDownloading] = useState<string | null>(null);

  const download = async (type: 'threat' | 'daily') => {
    setDownloading(type);
    try {
      if (type === 'daily') {
        await api.downloadDailyReport();
      } else if (threatId) {
        await api.downloadThreatReport(Number(threatId));
      }
    } catch (e: any) {
      alert(e.message || t('reportError'));
    } finally {
      setDownloading(null);
    }
  };

  return (
    <div className="intel-section">
      <div className="intel-grid-2">
        <div className="intel-card">
          <h3 className="intel-card-title">{t('reportDailyTitle')}</h3>
          <p style={{ fontSize: 13, color: '#94a3b8', margin: '0 0 16px' }}>
            {t('reportDailyDesc')}
          </p>
          <button
            className="btn btn-primary" style={{ marginTop: 16, width: '100%' }}
            onClick={() => download('daily')} disabled={downloading === 'daily'}
          >
            {downloading === 'daily' ? t('reportGenerating') : t('reportDownloadDaily')}
          </button>
        </div>

        <div className="intel-card">
          <h3 className="intel-card-title">{t('reportDetailTitle')}</h3>
          <p style={{ fontSize: 13, color: '#94a3b8', margin: '0 0 16px' }}>
            {t('reportDetailDesc')}
          </p>
          <div style={{ display: 'flex', gap: 8 }}>
            <input
              className="form-input" placeholder={t('reportThreatIdPH')}
              value={threatId} onChange={e => setThreatId(e.target.value)}
            />
            <button
              className="btn btn-primary"
              onClick={() => download('threat')} disabled={downloading === 'threat' || !threatId}
            >
              {downloading === 'threat' ? t('reportGenerating') : t('reportDownload')}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── SIEM 연동 ────────────────────────────────────────────────────────────────
function SIEMTab() {
  const { t } = useLanguage();
  const [webhookUrl, setWebhookUrl] = useState('');
  const [format, setFormat] = useState<'json' | 'cef'>('json');
  const [threatId, setThreatId] = useState('');
  const [logs, setLogs] = useState<any[]>([]);
  const [testing, setTesting] = useState(false);
  const [sending, setSending] = useState(false);

  useEffect(() => {
    api.getSIEMLogs().then(setLogs).catch(() => {});
  }, []);

  const testWebhook = async () => {
    if (!webhookUrl) return;
    setTesting(true);
    try {
      const res = await api.testSIEMWebhook(webhookUrl, format);
      alert(`${t('siemTestResult')}: ${res.success ? '✅ 성공' : '❌ 실패'}\nHTTP ${res.status_code}`);
      api.getSIEMLogs().then(setLogs).catch(() => {});
    } catch (e: any) {
      alert(e.message);
    } finally {
      setTesting(false);
    }
  };

  const sendThreat = async () => {
    if (!webhookUrl || !threatId) return;
    setSending(true);
    try {
      const res = await api.sendToSIEM(Number(threatId), webhookUrl, format);
      alert(`${t('siemSendResult')}: ${res.success ? '✅ 성공' : '❌ 실패'}\nHTTP ${res.status_code}`);
      api.getSIEMLogs().then(setLogs).catch(() => {});
    } catch (e: any) {
      alert(e.message);
    } finally {
      setSending(false);
    }
  };

  return (
    <div className="intel-section">
      <div className="intel-grid-2">
        <div className="intel-card">
          <h3 className="intel-card-title">{t('siemWebhookTitle')}</h3>
          <p style={{ fontSize: 12, color: '#64748b', marginBottom: 12 }}>
            {t('siemWebhookDesc')}
          </p>
          <div className="form-row" style={{ marginBottom: 10 }}>
            <label className="form-label">Webhook URL</label>
            <input className="form-input" placeholder="https://your-siem.example.com/webhook"
              value={webhookUrl} onChange={e => setWebhookUrl(e.target.value)}/>
          </div>
          <div className="form-row" style={{ marginBottom: 12 }}>
            <label className="form-label">{t('siemFormat')}</label>
            <div style={{ display: 'flex', gap: 8 }}>
              {(['json', 'cef'] as const).map(f => (
                <button key={f} className={`intel-tab-btn ${format === f ? 'active' : ''}`}
                  onClick={() => setFormat(f)}>
                  {f.toUpperCase()}
                  <span style={{ fontSize: 10, color: '#94a3b8', marginLeft: 4 }}>
                    {f === 'json' ? '(Elastic/일반)' : '(Splunk/CEF)'}
                  </span>
                </button>
              ))}
            </div>
          </div>
          <button className="btn btn-secondary" style={{ width: '100%', marginBottom: 8 }}
            onClick={testWebhook} disabled={testing || !webhookUrl}>
            {testing ? t('siemTesting') : t('siemTest')}
          </button>

          <div style={{ borderTop: '1px solid #1e293b', paddingTop: 12, marginTop: 4 }}>
            <label className="form-label">{t('siemThreatId')}</label>
            <div style={{ display: 'flex', gap: 8 }}>
              <input className="form-input" placeholder="42" value={threatId} onChange={e => setThreatId(e.target.value)}/>
              <button className="btn btn-primary" onClick={sendThreat} disabled={sending || !webhookUrl || !threatId}>
                {sending ? t('siemSending') : t('siemSend')}
              </button>
            </div>
          </div>
        </div>

        <div className="intel-card">
          <h3 className="intel-card-title">{t('siemHistoryTitle')}</h3>
          {logs.length === 0 ? (
            <p style={{ color: '#64748b', fontSize: 13 }}>{t('siemNoHistory')}</p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 320, overflow: 'auto' }}>
              {logs.map((log: any) => (
                <div key={log.id} style={{
                  background: '#0d1b2e', border: '1px solid #1e293b', borderRadius: 6, padding: '8px 12px',
                  display: 'flex', gap: 8, alignItems: 'center',
                }}>
                  <span style={{ fontSize: 12, fontWeight: 700, color: log.success ? '#22c55e' : '#ef4444' }}>
                    {log.success ? '✅' : '❌'} {log.status_code || '-'}
                  </span>
                  <span style={{ fontSize: 11, color: '#64748b', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {log.url}
                  </span>
                  <span style={{ fontSize: 10, color: '#475569', flexShrink: 0 }}>
                    {new Date(log.sent_at).toLocaleString()}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="intel-card" style={{ marginTop: 16 }}>
        <h3 className="intel-card-title">{t('siemGuideTitle')}</h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
          {[
            { name: 'Splunk HEC', url: 'https://<splunk>:8088/services/collector', format: 'CEF', icon: '🔴' },
            { name: 'Elastic',    url: 'https://<elastic>:9200/_bulk',              format: 'JSON', icon: '🟡' },
            { name: 'QRadar',     url: 'https://<qradar>/api/siem/offenses',        format: 'CEF', icon: '🔵' },
          ].map(g => (
            <div key={g.name} style={{ background: '#0d1b2e', border: '1px solid #1e293b', borderRadius: 8, padding: 12 }}>
              <div style={{ fontSize: 16, marginBottom: 4 }}>{g.icon} <strong style={{ color: '#e2e8f0', fontSize: 13 }}>{g.name}</strong></div>
              <code style={{ fontSize: 10, color: '#64748b', display: 'block', wordBreak: 'break-all' }}>{g.url}</code>
              <span style={{ fontSize: 11, color: '#94a3b8' }}>{t('siemFormat2')}: {g.format}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── 다크웹 모니터링 ──────────────────────────────────────────────────────────
function DarkwebTab() {
  const { t } = useLanguage();
  const [breaches, setBreaches] = useState<any>(null);
  const [monitor, setMonitor] = useState<any>(null);
  const [searchQ, setSearchQ] = useState('');
  const [searchResult, setSearchResult] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [searching, setSearching] = useState(false);

  useEffect(() => {
    Promise.allSettled([
      api.getDarkwebBreaches(),
      api.getDarkwebMonitor(),
    ]).then(([b, m]) => {
      if (b.status === 'fulfilled') setBreaches(b.value);
      if (m.status === 'fulfilled') setMonitor(m.value);
      setLoading(false);
    });
  }, []);

  const search = async () => {
    if (!searchQ.trim()) return;
    setSearching(true);
    try {
      const res = await api.searchDarkweb(searchQ);
      setSearchResult(res);
    } catch (e) {
      console.error(e);
    } finally {
      setSearching(false);
    }
  };

  return (
    <div className="intel-section">
      <div className="intel-card" style={{ marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
          <span style={{ fontSize: 18 }}>🕵</span>
          <h3 className="intel-card-title" style={{ margin: 0 }}>{t('darkwebTitle')}</h3>
          <span style={{ fontSize: 11, background: 'rgba(239,68,68,0.1)', color: '#f87171', border: '1px solid rgba(239,68,68,0.3)', padding: '2px 8px', borderRadius: 12 }}>
            {t('darkwebOSINT')}
          </span>
        </div>
        <p style={{ fontSize: 12, color: '#64748b', margin: 0 }}>
          {t('darkwebDesc')}
        </p>
      </div>

      <div className="intel-grid-2">
        {/* 모니터링 키워드 현황 */}
        <div className="intel-card">
          <h3 className="intel-card-title">{t('darkwebMonitorTitle')}</h3>
          {loading ? <p style={{ color: '#64748b' }}>{t('loading')}</p> : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {(monitor?.results || []).slice(0, 8).map((r: any) => (
                <div key={r.keyword} style={{
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  background: '#0d1b2e', border: '1px solid #1e293b', borderRadius: 6, padding: '8px 12px',
                }}>
                  <div>
                    <span style={{ fontSize: 13, fontWeight: 600, color: '#e2e8f0' }}>{r.keyword}</span>
                    {r.latest && <div style={{ fontSize: 11, color: '#64748b', marginTop: 2 }}>{r.latest?.slice(0, 50)}</div>}
                  </div>
                  <span style={{
                    fontSize: 13, fontWeight: 700,
                    color: r.count > 0 ? '#ef4444' : '#22c55e',
                    minWidth: 30, textAlign: 'right',
                  }}>
                    {r.count > 0 ? `⚠ ${r.count}` : '✓ 0'}
                  </span>
                </div>
              ))}
              {(!monitor?.results?.length) && (
                <p style={{ color: '#64748b', fontSize: 13 }}>{t('darkwebNoMonitor')}</p>
              )}
            </div>
          )}
        </div>

        {/* 데이터 유출 현황 */}
        <div className="intel-card">
          <h3 className="intel-card-title">{t('darkwebBreachTitle')}</h3>
          {loading ? <p style={{ color: '#64748b' }}>{t('loading')}</p> : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 320, overflow: 'auto' }}>
              {(breaches?.recent_breaches || []).slice(0, 10).map((b: any) => (
                <div key={b.name} style={{
                  background: '#0d1b2e', border: '1px solid #1e293b', borderRadius: 6, padding: '8px 12px',
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: 13, fontWeight: 600, color: '#e2e8f0' }}>{b.title || b.name}</span>
                    <span style={{ fontSize: 11, color: '#ef4444', fontWeight: 700 }}>
                      {(b.pwn_count / 1_000_000).toFixed(1)}M{t('darkwebPersonUnit')}
                    </span>
                  </div>
                  <div style={{ display: 'flex', gap: 8, marginTop: 4, flexWrap: 'wrap' }}>
                    <span style={{ fontSize: 11, color: '#64748b' }}>{b.domain}</span>
                    <span style={{ fontSize: 11, color: '#64748b' }}>{b.breach_date}</span>
                    {(b.data_classes || []).slice(0, 3).map((dc: string) => (
                      <span key={dc} style={{ fontSize: 10, background: 'rgba(239,68,68,0.1)', color: '#f87171', padding: '1px 5px', borderRadius: 3 }}>{dc}</span>
                    ))}
                  </div>
                </div>
              ))}
              {(!breaches?.recent_breaches?.length) && (
                <p style={{ color: '#64748b', fontSize: 13 }}>{t('darkwebNoBreach')}</p>
              )}
            </div>
          )}
          {breaches && <p style={{ fontSize: 11, color: '#334155', marginTop: 8 }}>{t('darkwebBreachSource')} {breaches.total_breaches}{t('darkwebBreachUnit')}</p>}
        </div>
      </div>

      {/* 다크웹 검색 */}
      <div className="intel-card" style={{ marginTop: 16 }}>
        <h3 className="intel-card-title">{t('darkwebSearchTitle')}</h3>
        <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
          <input className="form-input" placeholder={t('darkwebSearchPH')}
            value={searchQ} onChange={e => setSearchQ(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && search()} style={{ flex: 1 }}/>
          <button className="btn btn-primary" onClick={search} disabled={searching || !searchQ}>
            {searching ? t('darkwebSearching') : t('darkwebSearch')}
          </button>
        </div>
        {searchResult && (
          <div>
            <p style={{ fontSize: 12, color: '#64748b', marginBottom: 8 }}>
              "{searchResult.query}" {t('btnSearch')}: {searchResult.total}{t('darkwebResultCount')}
            </p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {(searchResult.results || []).map((r: any, i: number) => (
                <div key={i} style={{
                  background: '#0d1b2e', border: '1px solid #1e293b', borderRadius: 6, padding: '10px 14px',
                }}>
                  <div style={{ fontSize: 13, fontWeight: 600, color: '#f1f5f9', marginBottom: 4 }}>{r.title || t('darkwebNoTitle')}</div>
                  <div style={{ fontSize: 11, color: '#ef4444', marginBottom: 4, wordBreak: 'break-all' }}>{r.url}</div>
                  {r.description && <p style={{ fontSize: 12, color: '#94a3b8', margin: 0 }}>{r.description?.slice(0, 200)}</p>}
                </div>
              ))}
              {searchResult.results?.length === 0 && <p style={{ color: '#64748b' }}>{t('darkwebNoResult')}</p>}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── 메인 페이지 ──────────────────────────────────────────────────────────────
export default function IntelligencePage() {
  const { t } = useLanguage();
  const [activeTab, setActiveTab] = useState<Tab>('trend');

  return (
    <div className="page-container">
      <div className="page-header">
        <h2 className="page-title">{t('intelPageTitle')}</h2>
        <p className="page-desc">{t('intelPageDesc')}</p>
      </div>

      {/* 탭 네비게이션 */}
      <div className="intel-nav">
        {TAB_IDS.map(id => (
          <button
            key={id}
            className={`intel-nav-btn ${activeTab === id ? 'active' : ''}`}
            onClick={() => setActiveTab(id)}
          >
            <span>{TAB_ICONS[id]}</span>
            <span>{t(TAB_LABEL_KEYS[id] as any)}</span>
          </button>
        ))}
      </div>

      {/* 탭 컨텐츠 */}
      {activeTab === 'trend'   && <TrendTab />}
      {activeTab === 'graph'   && <GraphTab />}
      {activeTab === 'rules'   && <RulesTab />}
      {activeTab === 'report'  && <ReportTab />}
      {activeTab === 'siem'    && <SIEMTab />}
      {activeTab === 'darkweb' && <DarkwebTab />}
    </div>
  );
}
