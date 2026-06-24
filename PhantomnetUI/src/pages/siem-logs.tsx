/**
 * siem-logs.tsx — PhantomNet++ Security Operations Center
 * Multi-panel SOC dashboard · Elasticsearch · SHA-3 · FR-SIEM.1-6
 */

import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  AreaChart, Area, CartesianGrid, PieChart, Pie, Cell, Legend,
} from 'recharts';
import {
  FileText, Download, AlertCircle, Info, AlertTriangle, XCircle,
  RefreshCw, Shield, WifiOff, ChevronDown, ChevronUp, CheckCircle,
  Activity, Database, Clock, Eye, Filter, Zap, Users,
} from 'lucide-react';

const SIEM_BASE = 'http://localhost:8003/api/siem';
const POLL_MS   = 5000;
const PAGE_SIZE = 100;

interface SIEMLog {
  log_id:     string;
  timestamp:  string;
  severity:   'Info' | 'Warning' | 'Error' | 'Critical';
  source:     string;
  event_type: string;
  message:    string;
  metadata:   Record<string, any>;
  sha3_hash:  string;
}

interface SIEMStats {
  total: number; critical: number; error: number; warning: number; info: number;
}

function useTheme() {
  const [isLight, setIsLight] = useState(() =>
    typeof document !== 'undefined' && document.documentElement.classList.contains('light')
  );
  useEffect(() => {
    const obs = new MutationObserver(() =>
      setIsLight(document.documentElement.classList.contains('light'))
    );
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });
    return () => obs.disconnect();
  }, []);
  return isLight;
}

const SEV = {
  Critical: { icon: XCircle,       color: '#ef4444', bg: 'rgba(239,68,68,0.08)',  border: 'rgba(239,68,68,0.3)',  label: 'CRITICAL'          },
  Error:    { icon: Users,          color: '#f97316', bg: 'rgba(249,115,22,0.08)', border: 'rgba(249,115,22,0.3)', label: 'HUMAN ESCALATION'  },
  Warning:  { icon: AlertTriangle, color: '#eab308', bg: 'rgba(234,179,8,0.08)',  border: 'rgba(234,179,8,0.3)',  label: 'WARNING'           },
  Info:     { icon: Info,          color: '#3b82f6', bg: 'rgba(59,130,246,0.08)', border: 'rgba(59,130,246,0.3)', label: 'INFO'              },
} as const;

const SRC_CFG = {
  IVM:  { color: '#10b981', bg: 'rgba(16,185,129,0.1)',  desc: 'Threat Detection' },
  ARE:  { color: '#a78bfa', bg: 'rgba(167,139,250,0.1)', desc: 'Response Engine'  },
  XAI:  { color: '#22d3ee', bg: 'rgba(34,211,238,0.1)',  desc: 'Explainability'   },
  AUTH: { color: '#fb923c', bg: 'rgba(251,146,60,0.1)',  desc: 'Authentication'   },
  SRC:  { color: '#f43f5e', bg: 'rgba(244,63,94,0.1)',   desc: 'Secure Coord.'    },
} as const;

function PulseDot({ color }: { color: string }) {
  return (
    <span style={{ position: 'relative', display: 'inline-flex', width: '8px', height: '8px', flexShrink: 0 }}>
      <span style={{ position: 'absolute', inset: 0, borderRadius: '50%', background: color, opacity: 0.4, animation: 'siemPulse 1.8s ease-out infinite' }} />
      <span style={{ position: 'relative', width: '8px', height: '8px', borderRadius: '50%', background: color }} />
    </span>
  );
}

function PanelHeader({ title, sub, color = '#10b981' }: { title: string; sub?: string; color?: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '7px' }}>
        <div style={{ width: '3px', height: '14px', borderRadius: '2px', background: color, flexShrink: 0 }} />
        <span style={{ fontSize: '12px', fontWeight: 700, letterSpacing: '0.03em' }}>{title}</span>
      </div>
      {sub && <span style={{ fontSize: '10px', opacity: 0.45 }}>{sub}</span>}
    </div>
  );
}

export default function SIEMLogs() {
  const isLight = useTheme();

  const [logs,        setLogs]        = useState<SIEMLog[]>([]);
  const [stats,       setStats]       = useState<SIEMStats>({ total: 0, critical: 0, error: 0, warning: 0, info: 0 });
  const [loading,     setLoading]     = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [hasMore,     setHasMore]     = useState(true);
  const [backendOk,   setBackendOk]   = useState<boolean | null>(null);
  const [expanded,    setExpanded]    = useState<Set<string>>(new Set());
  const [severity,    setSeverity]    = useState('all');
  const [source,      setSource]      = useState('all');
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [pdfLoading,  setPdfLoading]  = useState(false);

  const offsetRef   = useRef(0);
  const bottomRef   = useRef<HTMLDivElement>(null);

  const bg0 = isLight ? '#f0f4f8'          : '#060b14';
  const bg1 = isLight ? '#ffffff'          : '#0c1220';
  const bg2 = isLight ? '#f5f7fa'          : '#111827';
  const bg3 = isLight ? '#eaeff6'          : '#080d18';
  const bdr = isLight ? 'rgba(0,0,0,0.08)' : 'rgba(255,255,255,0.06)';
  const txt = isLight ? '#0f172a'          : '#e2e8f0';
  const sub = isLight ? '#64748b'          : '#475569';
  const gridLine = isLight ? 'rgba(0,0,0,0.06)' : 'rgba(255,255,255,0.04)';

  const accentOf = (sev: string) => SEV[sev as keyof typeof SEV]?.color ?? 'transparent';

  // ── Computed chart data ──────────────────────────────────────────────────────

  const severityBarData = useMemo(() => [
    { name: 'Critical',    value: stats.critical, color: '#ef4444' },
    { name: 'Escalation',  value: stats.error,    color: '#f97316' },
    { name: 'Warning',     value: stats.warning,  color: '#eab308' },
    { name: 'Info',        value: stats.info,     color: '#3b82f6' },
  ], [stats]);

  const sourceBarData = useMemo(() => {
    const counts: Record<string, number> = {};
    logs.forEach(l => { counts[l.source] = (counts[l.source] || 0) + 1; });
    return Object.entries(SRC_CFG).map(([key, cfg]) => ({
      source: key,
      count: counts[key] || 0,
      color: cfg.color,
    }));
  }, [logs]);

  const timelineData = useMemo(() => {
    const INTERVAL = 5 * 60 * 1000;
    const now = Date.now();
    const buckets: Record<number, { time: string; critical: number; escalation: number; warning: number; info: number }> = {};
    for (let i = 11; i >= 0; i--) {
      const t   = now - i * INTERVAL;
      const key = Math.floor(t / INTERVAL);
      buckets[key] = { time: new Date(t).toLocaleTimeString('en-PK', { timeZone: 'Asia/Karachi', hour: '2-digit', minute: '2-digit' }), critical: 0, escalation: 0, warning: 0, info: 0 };
    }
    logs.forEach(log => {
      const key = Math.floor(new Date(log.timestamp).getTime() / INTERVAL);
      if (buckets[key]) {
        const s = log.severity;
        if (s === 'Critical') buckets[key].critical++;
        else if (s === 'Error')   buckets[key].escalation++;
        else if (s === 'Warning') buckets[key].warning++;
        else                      buckets[key].info++;
      }
    });
    return Object.values(buckets);
  }, [logs]);

  const eventTypeData = useMemo(() => {
    const counts: Record<string, number> = {};
    logs.forEach(l => { counts[l.event_type] = (counts[l.event_type] || 0) + 1; });
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 7)
      .map(([type, count]) => ({ type: type.replace(/_/g, ' ').slice(0, 20), count }));
  }, [logs]);

  const pieData = useMemo(() => severityBarData.filter(d => d.value > 0), [severityBarData]);

  // ── Data fetching ────────────────────────────────────────────────────────────

  useEffect(() => {
    fetch(`${SIEM_BASE}/health`)
      .then(r => r.ok ? r.json() : null)
      .then(d => setBackendOk(d?.status === 'ok'))
      .catch(() => setBackendOk(false));
  }, []);

  const fetchStats = useCallback(async () => {
    try {
      const res = await fetch(`${SIEM_BASE}/stats`);
      if (!res.ok) return;
      const d: SIEMStats = await res.json();
      setStats(d);
    } catch {}
  }, []);

  const fetchLogs = useCallback(async () => {
    const p = new URLSearchParams({ limit: String(PAGE_SIZE), offset: '0' });
    if (severity !== 'all') p.set('severity', severity);
    if (source   !== 'all') p.set('source',   source);
    try {
      const res = await fetch(`${SIEM_BASE}/logs?${p}`);
      if (!res.ok) return;
      const data = await res.json();
      setLogs(data.logs ?? []);
      setHasMore((data.logs?.length ?? 0) < data.total);
      offsetRef.current = data.logs?.length ?? 0;
      setBackendOk(true);
      setLastUpdated(new Date());
    } catch { setBackendOk(false); }
    finally  { setLoading(false); }
  }, [severity, source]);

  const loadMore = useCallback(async () => {
    if (loadingMore || !hasMore) return;
    setLoadingMore(true);
    const p = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(offsetRef.current) });
    if (severity !== 'all') p.set('severity', severity);
    if (source   !== 'all') p.set('source',   source);
    try {
      const res = await fetch(`${SIEM_BASE}/logs?${p}`);
      if (!res.ok) return;
      const data = await res.json();
      const inc: SIEMLog[] = data.logs ?? [];
      setLogs(prev => { const ids = new Set(prev.map(l => l.log_id)); return [...prev, ...inc.filter(l => !ids.has(l.log_id))]; });
      offsetRef.current += inc.length;
      setHasMore(offsetRef.current < data.total);
    } catch {} finally { setLoadingMore(false); }
  }, [loadingMore, hasMore, severity, source]);

  useEffect(() => {
    const obs = new IntersectionObserver(e => { if (e[0].isIntersecting) loadMore(); }, { threshold: 0.1 });
    if (bottomRef.current) obs.observe(bottomRef.current);
    return () => obs.disconnect();
  }, [loadMore]);

  useEffect(() => {
    setLoading(true);
    fetchLogs(); fetchStats();
    const iv = setInterval(() => { fetchLogs(); fetchStats(); }, POLL_MS);
    return () => clearInterval(iv);
  }, [fetchLogs, fetchStats]);

  // ── Exports ──────────────────────────────────────────────────────────────────

  const exportLogs = () => {
    const blob = new Blob([JSON.stringify(logs, null, 2)], { type: 'application/json' });
    Object.assign(document.createElement('a'), {
      href: URL.createObjectURL(blob),
      download: `phantomnet-siem-${new Date().toISOString().split('T')[0]}.json`,
    }).click();
  };

  const exportLogsPdf = async () => {
    setPdfLoading(true);
    try {
      // Fetch ALL logs (no filters, large limit) so the report is complete
      let allLogs = logs;
      try {
        const siemRes = await fetch(`${SIEM_BASE}/logs?limit=2000&offset=0`);
        if (siemRes.ok) {
          const siemData = await siemRes.json();
          allLogs = siemData.logs ?? logs;
        }
      } catch { /* fallback to currently loaded logs */ }

      if (allLogs.length === 0) { alert('No events to report.'); return; }

      const res = await fetch('http://localhost:8004/api/report/siem/pdf', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ logs: allLogs, stats, generated_at: new Date().toISOString() }),
      });
      if (!res.ok) throw new Error();
      const blob = await res.blob();
      Object.assign(document.createElement('a'), {
        href: URL.createObjectURL(blob),
        download: `phantomnet-siem-${new Date().toISOString().split('T')[0]}.pdf`,
      }).click();
    } catch {
      alert('PDF generation failed. Start report_backend.py on port 8004.');
    } finally { setPdfLoading(false); }
  };

  const toggleExpand = (id: string) =>
    setExpanded(p => { const s = new Set(p); s.has(id) ? s.delete(id) : s.add(id); return s; });

  const btnStyle: React.CSSProperties = {
    display: 'flex', alignItems: 'center', gap: '5px',
    padding: '7px 13px', fontSize: '12px', borderRadius: '7px',
    border: `1px solid ${bdr}`, background: bg2, cursor: 'pointer',
    color: txt, fontWeight: 500,
  };

  const panel: React.CSSProperties = {
    background: bg1, border: `1px solid ${bdr}`, borderRadius: '10px', padding: '16px',
  };

  const tooltipStyle = {
    contentStyle: { background: '#1e293b', border: '1px solid rgba(255,255,255,0.12)', borderRadius: '8px', fontSize: '11px', color: '#e2e8f0' },
    labelStyle:   { color: '#94a3b8', fontSize: '10px' },
    itemStyle:    { color: '#e2e8f0' },
    cursor:       { fill: isLight ? 'rgba(0,0,0,0.04)' : 'rgba(255,255,255,0.03)' },
  };

  return (
    <div style={{ minHeight: '100vh', background: bg0, color: txt }}>

      {/* ── STICKY TOP BAR ── */}
      <div style={{ background: bg1, borderBottom: `1px solid ${bdr}`, padding: '10px 24px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', position: 'sticky', top: 0, zIndex: 20, backdropFilter: 'blur(10px)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{ width: '32px', height: '32px', borderRadius: '8px', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Shield style={{ width: '15px', color: '#ef4444' }} />
          </div>
          <div>
            <div style={{ fontSize: '28px', fontWeight: 700 }}>Logging and Monitoring</div>
            <div style={{ fontSize: '10px', color: sub }}>LSE · Elasticsearch · SHA-3 Integrity · Real-time</div>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', padding: '4px 10px', borderRadius: '20px', background: backendOk ? 'rgba(16,185,129,0.08)' : 'rgba(239,68,68,0.08)', border: `1px solid ${backendOk ? 'rgba(16,185,129,0.2)' : 'rgba(239,68,68,0.2)'}` }}>
            {backendOk === null  && <span style={{ fontSize: '10px', color: sub }}>Connecting...</span>}
            {backendOk === true  && <><PulseDot color="#10b981" /><span style={{ fontSize: '10px', color: '#10b981', fontWeight: 700, marginLeft: '3px' }}>LIVE</span></>}
            {backendOk === false && <><WifiOff style={{ width: '10px', color: '#ef4444' }} /><span style={{ fontSize: '10px', color: '#ef4444', marginLeft: '3px' }}>OFFLINE</span></>}
          </div>
          {lastUpdated && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '10px', color: sub }}>
              <Clock style={{ width: '10px' }} />{lastUpdated.toLocaleTimeString('en-PK', { timeZone: 'Asia/Karachi' })}
            </div>
          )}
          <button style={btnStyle} onClick={() => { setLoading(true); fetchLogs(); fetchStats(); }}>
            <RefreshCw style={{ width: '11px' }} /> Refresh
          </button>
          <button style={btnStyle} onClick={exportLogsPdf} disabled={pdfLoading}>
            <Download style={{ width: '11px' }} /> {pdfLoading ? 'Generating...' : 'PDF Report'}
          </button>
          <button style={btnStyle} onClick={exportLogs}>
            <Download style={{ width: '11px' }} /> Export JSON
          </button>
        </div>
      </div>

      <div style={{ padding: '18px 24px', maxWidth: '1600px', margin: '0 auto' }}>

        {/* ── ROW 1: 4 STAT CARDS ── */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '10px', marginBottom: '14px' }}>
          {[
            { key: 'critical',   label: 'Critical',          value: stats.critical, color: '#ef4444', icon: XCircle       },
            { key: 'escalation', label: 'Human Escalation',  value: stats.error,    color: '#f97316', icon: Users         },
            { key: 'warning',    label: 'Warnings',          value: stats.warning,  color: '#eab308', icon: AlertTriangle },
            { key: 'info',       label: 'Info Events',       value: stats.info,     color: '#3b82f6', icon: Info          },
          ].map(({ key, label, value, color, icon: Icon }) => {
            const pct = stats.total > 0 ? Math.round((value / stats.total) * 100) : 0;
            return (
              <div key={key} style={{ ...panel, borderTop: `3px solid ${color}`, padding: '14px 16px' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                  <span style={{ fontSize: '10px', fontWeight: 700, color, letterSpacing: '0.1em', textTransform: 'uppercase' }}>{label}</span>
                  <div style={{ width: '28px', height: '28px', borderRadius: '7px', background: color + '15', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <Icon style={{ width: '14px', color }} />
                  </div>
                </div>
                <div style={{ fontSize: '34px', fontWeight: 700, color, lineHeight: 1, marginBottom: '8px' }}>{value.toLocaleString()}</div>
                <div style={{ height: '3px', background: isLight ? 'rgba(0,0,0,0.07)' : 'rgba(255,255,255,0.06)', borderRadius: '2px', overflow: 'hidden', marginBottom: '4px' }}>
                  <div style={{ height: '100%', width: `${pct}%`, background: color, borderRadius: '2px' }} />
                </div>
                <div style={{ fontSize: '10px', color: sub }}>{pct}% of {stats.total.toLocaleString()} total</div>
              </div>
            );
          })}
        </div>

        {/* ── ROW 2: 3 CHART PANELS ── */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1.4fr', gap: '12px', marginBottom: '12px' }}>

          {/* Severity Overview Bar Chart */}
          <div style={panel}>
            <PanelHeader title="Events by Severity" sub={`${stats.total} total`} color="#ef4444" />
            <ResponsiveContainer width="100%" height={170}>
              <BarChart data={severityBarData} barSize={28} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
                <CartesianGrid vertical={false} stroke={gridLine} />
                <XAxis dataKey="name" tick={{ fontSize: 10, fill: sub }} axisLine={false} tickLine={false} interval={0} tickFormatter={(v) => v === "Escalation" ? "Human Esc." : v} />
                <YAxis tick={{ fontSize: 10, fill: sub }} axisLine={false} tickLine={false} allowDecimals={false} />
                <Tooltip {...tooltipStyle} formatter={(v: any) => [v, 'Events']} />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                  {severityBarData.map((d, i) => <Cell key={i} fill={d.color} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Source Module Bar Chart */}
          <div style={panel}>
            <PanelHeader title="Events by Source" sub="module breakdown" color="#a78bfa" />
            <ResponsiveContainer width="100%" height={170}>
              <BarChart data={sourceBarData} layout="vertical" barSize={14} margin={{ top: 0, right: 30, bottom: 0, left: 10 }}>
                <CartesianGrid horizontal={false} stroke={gridLine} />
                <XAxis type="number" tick={{ fontSize: 9, fill: sub }} axisLine={false} tickLine={false} allowDecimals={false} />
                <YAxis type="category" dataKey="source" tick={{ fontSize: 10, fill: sub }} axisLine={false} tickLine={false} width={34} />
                <Tooltip {...tooltipStyle} formatter={(v: any) => [v, 'Events']} />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {sourceBarData.map((d, i) => <Cell key={i} fill={d.color} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Event Timeline Area Chart */}
          <div style={panel}>
            <PanelHeader title="Event Timeline" sub="5-min intervals · last 60 min" color="#10b981" />
            <ResponsiveContainer width="100%" height={170}>
              <AreaChart data={timelineData} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
                <defs>
                  <linearGradient id="gcrit" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#ef4444" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0}   />
                  </linearGradient>
                  <linearGradient id="gwarn" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#eab308" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#eab308" stopOpacity={0}    />
                  </linearGradient>
                  <linearGradient id="ginfo" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#3b82f6" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}   />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke={gridLine} />
                <XAxis dataKey="time" tick={{ fontSize: 9, fill: sub }} axisLine={false} tickLine={false} interval={2} />
                <YAxis tick={{ fontSize: 9, fill: sub }} axisLine={false} tickLine={false} allowDecimals={false} />
                <Tooltip {...tooltipStyle} />
                <Area type="monotone" dataKey="critical"   stroke="#ef4444" fill="url(#gcrit)" strokeWidth={1.5} name="Critical"   dot={false} />
                <Area type="monotone" dataKey="escalation" stroke="#f97316" fill="none"        strokeWidth={1.5} name="Escalation" dot={false} strokeDasharray="3 2" />
                <Area type="monotone" dataKey="warning"    stroke="#eab308" fill="url(#gwarn)" strokeWidth={1.5} name="Warning"    dot={false} />
                <Area type="monotone" dataKey="info"       stroke="#3b82f6" fill="url(#ginfo)" strokeWidth={1.5} name="Info"       dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* ── ROW 3: ALERT OVERVIEW + EVENT TYPES ── */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.6fr', gap: '12px', marginBottom: '14px' }}>

          {/* Alert Overview — donut + big numbers */}
          <div style={panel}>
            <PanelHeader title="Alert Overview" color="#ef4444" />
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              <div style={{ flexShrink: 0 }}>
                <ResponsiveContainer width={110} height={110}>
                  <PieChart>
                    <Pie data={pieData.length ? pieData : [{ name: 'None', value: 1, color: bdr }]}
                      cx="50%" cy="50%" innerRadius={30} outerRadius={50} dataKey="value" strokeWidth={0}>
                      {(pieData.length ? pieData : [{ color: sub }]).map((d, i) => (
                        <Cell key={i} fill={d.color} opacity={0.85} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid rgba(255,255,255,0.12)', borderRadius: '8px', fontSize: '11px', color: '#e2e8f0' }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div style={{ flex: 1, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                {[
                  { label: 'Critical',    value: stats.critical, color: '#ef4444' },
                  { label: 'Escalations', value: stats.error,    color: '#f97316' },
                  { label: 'Warnings',    value: stats.warning,  color: '#eab308' },
                  { label: 'Info',        value: stats.info,     color: '#3b82f6' },
                ].map(s => (
                  <div key={s.label} style={{ background: bg2, borderRadius: '7px', padding: '8px 10px', borderLeft: `3px solid ${s.color}` }}>
                    <div style={{ fontSize: '9px', color: sub, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '2px' }}>{s.label}</div>
                    <div style={{ fontSize: '20px', fontWeight: 700, color: s.color, lineHeight: 1 }}>{s.value}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Top Event Types */}
          <div style={panel}>
            <PanelHeader title="Top Event Types" sub={`${eventTypeData.length} distinct types`} color="#22d3ee" />
            <ResponsiveContainer width="100%" height={140}>
              <BarChart data={eventTypeData} layout="vertical" barSize={12} margin={{ top: 0, right: 40, bottom: 0, left: 8 }}>
                <CartesianGrid horizontal={false} stroke={gridLine} />
                <XAxis type="number" tick={{ fontSize: 9, fill: sub }} axisLine={false} tickLine={false} allowDecimals={false} />
                <YAxis type="category" dataKey="type" tick={{ fontSize: 9, fill: sub }} axisLine={false} tickLine={false} width={130} />
                <Tooltip {...tooltipStyle} formatter={(v: any) => [v, 'Occurrences']} />
                <Bar dataKey="count" fill="#22d3ee" radius={[0, 4, 4, 0]} opacity={0.75} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* ── SOURCE MODULE FILTER TABS ── */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '8px', marginBottom: '14px' }}>
          {Object.entries(SRC_CFG).map(([key, cfg]) => {
            const active = source === key;
            return (
              <div
                key={key}
                onClick={() => { setSource(active ? 'all' : key); setLoading(true); }}
                style={{ background: active ? cfg.bg : bg1, border: `1px solid ${active ? cfg.color + '40' : bdr}`, borderRadius: '8px', padding: '9px 12px', cursor: 'pointer', transition: 'all 0.15s' }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '2px' }}>
                  <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: active ? cfg.color : sub, flexShrink: 0 }} />
                  <span style={{ fontSize: '12px', fontWeight: 700, color: active ? cfg.color : txt }}>{key}</span>
                </div>
                <div style={{ fontSize: '10px', color: sub, paddingLeft: '12px' }}>{cfg.desc}</div>
              </div>
            );
          })}
        </div>

        {/* ── LOG STREAM PANEL ── */}
        <div style={{ background: bg1, border: `1px solid ${bdr}`, borderRadius: '10px', overflow: 'hidden' }}>

          {/* Panel toolbar */}
          <div style={{ padding: '11px 16px', borderBottom: `1px solid ${bdr}`, display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap', background: bg2 }}>
            <Activity style={{ width: '13px', color: '#10b981', flexShrink: 0 }} />
            <span style={{ fontSize: '13px', fontWeight: 600 }}>Event Stream</span>
            <span style={{ fontSize: '11px', color: sub }}>{logs.length} events · refreshes every 5s</span>
            <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              <div style={{ position: 'relative' }}>
                <select
                  value={severity}
                  onChange={e => { setSeverity(e.target.value); setLoading(true); }}
                  style={{ appearance: 'none', padding: '6px 28px 6px 10px', fontSize: '12px', border: `1px solid ${bdr}`, borderRadius: '7px', background: bg1, color: txt, cursor: 'pointer', outline: 'none' }}
                >
                  <option value="all">All Levels</option>
                  <option value="Critical">Critical</option>
                  <option value="Error">Human Escalation</option>
                  <option value="Warning">Warning</option>
                  <option value="Info">Info</option>
                </select>
                <Filter style={{ position: 'absolute', right: '8px', top: '50%', transform: 'translateY(-50%)', width: '10px', color: sub, pointerEvents: 'none' }} />
              </div>
            </div>
          </div>

          {/* Column headers */}
          <div style={{ display: 'grid', gridTemplateColumns: '150px 130px 68px 170px 1fr 70px', padding: '6px 16px', borderBottom: `1px solid ${bdr}`, background: bg3 }}>
            {['TIMESTAMP', 'SEVERITY', 'SOURCE', 'EVENT TYPE', 'MESSAGE', ''].map((h, i) => (
              <div key={i} style={{ fontSize: '9px', fontWeight: 700, color: sub, letterSpacing: '0.12em' }}>{h}</div>
            ))}
          </div>

          {/* FR-SIEM.4: Log rows */}
          <div style={{ maxHeight: '55vh', overflowY: 'auto', background: bg0 }}>
            {loading && (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '64px', gap: '10px', color: sub, fontSize: '13px' }}>
                <RefreshCw style={{ width: '15px', animation: 'siemSpin 1s linear infinite' }} />
                Querying Elasticsearch...
              </div>
            )}
            {!loading && backendOk === false && (
              <div style={{ textAlign: 'center', padding: '64px', color: sub }}>
                <WifiOff style={{ width: '40px', height: '40px', margin: '0 auto 14px', opacity: 0.25, display: 'block' }} />
                <div style={{ fontSize: '15px', fontWeight: 600, marginBottom: '6px', color: txt }}>SIEM Backend Offline</div>
                <div style={{ fontSize: '12px' }}>Start siem_backend.py (port 8003) · Ensure Elasticsearch is running (port 9200)</div>
              </div>
            )}
            {!loading && backendOk && logs.length === 0 && (
              <div style={{ textAlign: 'center', padding: '64px', color: sub }}>
                <Zap style={{ width: '40px', height: '40px', margin: '0 auto 14px', opacity: 0.25, display: 'block' }} />
                <div style={{ fontSize: '15px', fontWeight: 600, marginBottom: '6px', color: txt }}>No events yet</div>
                <div style={{ fontSize: '12px' }}>Events appear as your backends process detections, logins, and actions</div>
              </div>
            )}

            {!loading && logs.map((log, idx) => {
              const sev    = SEV[log.severity as keyof typeof SEV] ?? SEV.Info;
              const src    = SRC_CFG[log.source as keyof typeof SRC_CFG] ?? { color: '#94a3b8', bg: 'rgba(148,163,184,0.1)', desc: log.source };
              const SevIcon = sev.icon;
              const isExp  = expanded.has(log.log_id);

              return (
                <div key={log.log_id}>
                  <div
                    onClick={() => toggleExpand(log.log_id)}
                    style={{
                      display: 'grid', gridTemplateColumns: '150px 130px 68px 170px 1fr 70px',
                      padding: '8px 16px', borderBottom: `1px solid ${bdr}`,
                      borderLeft: `3px solid ${accentOf(log.severity)}`,
                      background: isExp ? bg2 : idx % 2 === 0 ? bg0 : bg1,
                      cursor: 'pointer', alignItems: 'center', transition: 'background 0.1s',
                    }}
                  >
                    <div style={{ fontSize: '11px', color: sub, lineHeight: 1.4 }}>
                      <div>{new Date(log.timestamp).toLocaleTimeString('en-PK', { timeZone: 'Asia/Karachi' })}</div>
                      <div style={{ fontSize: '10px', opacity: 0.6 }}>{new Date(log.timestamp).toLocaleDateString('en-GB', { timeZone: 'Asia/Karachi' })}</div>
                    </div>
                    <div>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: '3px', padding: '2px 6px', borderRadius: '4px', background: sev.bg, fontSize: '9px', fontWeight: 700, color: sev.color, letterSpacing: '0.05em', whiteSpace: 'nowrap' }}>
                        <SevIcon style={{ width: '9px', flexShrink: 0 }} />{log.severity === 'Error' ? 'HUMAN ESCALATION' : sev.label}
                      </span>
                    </div>
                    <div>
                      <span style={{ display: 'inline-flex', padding: '2px 6px', borderRadius: '4px', background: src.bg, fontSize: '9px', fontWeight: 700, color: src.color, letterSpacing: '0.06em' }}>
                        {log.source}
                      </span>
                    </div>
                    <div style={{ fontSize: '11px', color: sub, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', paddingRight: '8px' }}>
                      {log.event_type}
                    </div>
                    <div style={{ fontSize: '12px', color: txt, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', paddingRight: '8px' }}>
                      {log.message}
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '3px', color: sub, fontSize: '11px' }}>
                      <Eye style={{ width: '11px' }} />
                      {isExp ? <ChevronUp style={{ width: '11px' }} /> : <ChevronDown style={{ width: '11px' }} />}
                    </div>
                  </div>

                  {isExp && (
                    <div style={{ background: bg2, borderBottom: `1px solid ${bdr}`, borderLeft: `3px solid ${accentOf(log.severity)}`, padding: '14px 20px 14px 32px' }}>
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '14px', marginBottom: '12px' }}>
                        {[
                          { label: 'Log ID',         value: log.log_id },
                          { label: 'Event Type',     value: log.event_type },
                          { label: 'Full Timestamp', value: new Date(log.timestamp).toISOString() },
                        ].map(({ label, value }) => (
                          <div key={label}>
                            <div style={{ fontSize: '9px', fontWeight: 700, color: sub, letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: '3px' }}>{label}</div>
                            <div style={{ fontSize: '11px', color: txt, wordBreak: 'break-all' }}>{value}</div>
                          </div>
                        ))}
                      </div>
                      <div style={{ marginBottom: '10px', padding: '9px 12px', background: 'rgba(16,185,129,0.05)', border: '1px solid rgba(16,185,129,0.15)', borderRadius: '7px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '5px', marginBottom: '4px' }}>
                          <CheckCircle style={{ width: '10px', color: '#10b981' }} />
                          <span style={{ fontSize: '9px', fontWeight: 700, color: '#10b981', letterSpacing: '0.12em', textTransform: 'uppercase' }}>SHA-3 Integrity Hash — Tamper Proof</span>
                        </div>
                        <div style={{ fontSize: '10px', color: '#10b981', wordBreak: 'break-all', opacity: 0.8 }}>{log.sha3_hash}</div>
                      </div>
                      {Object.keys(log.metadata ?? {}).length > 0 && (
                        <div>
                          <div style={{ fontSize: '9px', fontWeight: 700, color: sub, letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: '5px' }}>Metadata</div>
                          <pre style={{ fontSize: '11px', background: bg3, color: txt, padding: '9px 12px', borderRadius: '7px', overflowX: 'auto', margin: 0, border: `1px solid ${bdr}`, lineHeight: 1.7 }}>
                            {JSON.stringify(log.metadata, null, 2)}
                          </pre>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}

            <div ref={bottomRef} style={{ height: '1px' }} />
            {loadingMore && (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '14px', gap: '8px', color: sub, fontSize: '12px' }}>
                <RefreshCw style={{ width: '12px', animation: 'siemSpin 1s linear infinite' }} /> Loading historical logs...
              </div>
            )}
            {!loadingMore && !hasMore && logs.length > 0 && (
              <div style={{ textAlign: 'center', padding: '12px', fontSize: '11px', color: sub, borderTop: `1px solid ${bdr}` }}>
                ── End of log history · {logs.length} events loaded ──
              </div>
            )}
          </div>
        </div>
      </div>

      <style>{`
        @keyframes siemSpin  { to { transform: rotate(360deg); } }
        @keyframes siemPulse { 0% { transform: scale(1); opacity: 0.4; } 75% { transform: scale(2.5); opacity: 0; } }
      `}</style>
    </div>
  );
}