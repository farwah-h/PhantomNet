/**
 * PhantomNet++ Dashboard — dashboard.tsx
 *
 * Real-data sources:
 *  1. GET /api/predictions  (threat detection DB — SQLite via database.py)
 *  2. GET /api/statistics   (threat detection DB — aggregated counts)
 *  3. GET /api/are/stats    (ARE backend — isolations, switches, escalations)
 *  4. GET /api/are/actions  (ARE backend — last 50 autonomous actions)
 *  localStorage kept in sync as fallback + for notifications system.
 */

import { useState, useEffect, useCallback } from 'react';
import {
  Card, CardContent, CardDescription, CardHeader, CardTitle,
} from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import {
  AreaChart, Area,
  BarChart, Bar,
  PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  ResponsiveContainer,
} from 'recharts';
import {
  Activity, Shield, AlertTriangle, CheckCircle,
  TrendingUp, Cpu, Zap, RefreshCw,
} from 'lucide-react';
import { Button } from '@/components/ui/button';

// ── Config ──────────────────────────────────────────────────────────────────
const THREAT_URL = 'http://localhost:5000';
const ARE_URL    = 'http://localhost:8000/api/are';
const POLL_MS    = 10_000;   // refresh every 10 s

// ── Types ───────────────────────────────────────────────────────────────────
interface ThreatEntry {
  id: string;
  timestamp: string | Date;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | string;
  status: string;
  modelTarget: string;
  confidence: number;
  attackVector: string;
  category?: string;
}

interface DBStats {
  total_predictions: number;
  adversarial_count: number;
  clean_count: number;
  severity_counts: Record<string, number>;
  average_confidence: number;
}

interface AREStats {
  totalIsolations: number;
  totalModelSwitches: number;
  totalEscalations: number;
  successRate: number;
}

interface AREAction {
  id: string;
  policyName: string;
  action: string;
  target: string;
  result: string;
  executionTime: number;
  timestamp: string;
}

interface DashboardState {
  threats: ThreatEntry[];
  allScans: ThreatEntry[];
  dbStats: DBStats | null;
  areStats: AREStats | null;
  areActions: AREAction[];
  threatBackendOnline: boolean;
  areBackendOnline: boolean;
  lastRefresh: Date | null;
}

// ── Helpers ─────────────────────────────────────────────────────────────────
function readLocalThreats(key: string): ThreatEntry[] {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return [];
    return JSON.parse(raw);
  } catch { return []; }
}

/**
 * Parse any timestamp format (with or without timezone offset) to UTC ms.
 * Normalizes SQLite space separator → T so the +05:00 offset is respected.
 */
function parseTS(raw: string | Date): number {
  if (raw instanceof Date) return raw.getTime();
  const s = String(raw).trim().replace(/^(\d{4}-\d{2}-\d{2}) /, '$1T');
  const d = new Date(s);
  if (!isNaN(d.getTime())) return d.getTime();
  const m = s.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})/);
  if (m) return new Date(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]).getTime();
  return 0;
}

function buildTimeSeriesFromScans(scans: ThreatEntry[]) {
  const now       = Date.now();
  const BUCKET_MS = 3_600_000;
  const NUM       = 12;

  const buckets = Array.from({ length: NUM }, (_, i) => ({
    hour:     new Date(now - (NUM - 1 - i) * BUCKET_MS)
                .toLocaleTimeString('en-PK', { timeZone: 'Asia/Karachi', hour: '2-digit', minute: '2-digit' }),
    detected: 0,
    clean:    0,
  }));

  scans.forEach((s) => {
    const scanTime = parseTS(s.timestamp);
    if (!scanTime) return;
    const ageMs = now - scanTime;
    if (ageMs < 0 || ageMs >= NUM * BUCKET_MS) return;
    const idx = NUM - 1 - Math.floor(ageMs / BUCKET_MS);
    if (idx < 0 || idx >= NUM) return;
    if (s.status === 'detected') buckets[idx].detected += 1;
    else                         buckets[idx].clean    += 1;
  });

  return buckets;
}

function buildSeverityDist(threats: ThreatEntry[]) {
  const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  threats.forEach((t) => { if (t.severity in counts) counts[t.severity]++; });
  return Object.entries(counts)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }));
}

function buildAttackTypeDist(threats: ThreatEntry[]) {
  const counts: Record<string, number> = {};
  threats.forEach((t) => {
    const k = t.type || 'Unknown';
    counts[k] = (counts[k] || 0) + 1;
  });
  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([name, value]) => ({ name, value }));
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#3b82f6',
};
const CHART_COLORS = ['#10b981', '#3b82f6', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899'];

// ── Component ────────────────────────────────────────────────────────────────
export default function Dashboard() {
  const [state, setState] = useState<DashboardState>({
    threats: [],
    allScans: [],
    dbStats: null,
    areStats: null,
    areActions: [],
    threatBackendOnline: false,
    areBackendOnline: false,
    lastRefresh: null,
  });
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    // 1. Fetch all predictions + stats from threat detection DB
    let allScans: ThreatEntry[] = [];
    let threats: ThreatEntry[]  = [];
    let dbStats: DBStats | null = null;
    let threatOnline = false;
    try {
      const [predRes, statsRes] = await Promise.all([
        fetch(`${THREAT_URL}/api/predictions?limit=200`, { signal: AbortSignal.timeout(4000) }),
        fetch(`${THREAT_URL}/api/statistics`,            { signal: AbortSignal.timeout(4000) }),
      ]);
      if (predRes.ok) {
        threatOnline = true;
        const data = await predRes.json();
        allScans = (data.predictions ?? []).map((p: any) => {
          const ir = typeof p.individual_results === 'string'
            ? JSON.parse(p.individual_results)
            : (p.individual_results ?? {});
          const parts: string[] = [];
          if (ir?.resnet?.status)      parts.push(`ResNet: ${ir.resnet.status}`);
          if (ir?.yolo?.status)        parts.push(`YOLOv5: ${ir.yolo.status}`);
          if (ir?.autoencoder?.status) parts.push(`Autoencoder: ${ir.autoencoder.status}`);
          return {
            id:           p.threat_id,
            timestamp:    p.timestamp,
            type:         p.attack_type      ?? 'Unknown',
            severity:     p.severity         ?? 'low',
            status:       p.final_decision === 'adversarial' ? 'detected' : 'clean',
            modelTarget:  'Multi-Model Analysis',
            confidence:   p.confidence       ?? 0,
            attackVector: parts.join(' | ')  || 'Multi-Model Analysis',
            category:     p.attack_category  ?? 'Unknown',
          } as ThreatEntry;
        });
        threats = allScans.filter(s => s.status === 'detected');
        // Keep localStorage in sync for notifications
        localStorage.setItem('phantomnet_all_scans', JSON.stringify(allScans));
        localStorage.setItem('phantomnet_threats',   JSON.stringify(threats));
      }
      if (statsRes.ok) { dbStats = await statsRes.json(); }
    } catch {
      // Fall back to localStorage if backend is offline
      allScans = readLocalThreats('phantomnet_all_scans');
      threats  = readLocalThreats('phantomnet_threats');
    }

    // 2. ARE stats + actions
    let areStats: AREStats | null = null;
    let areActions: AREAction[]   = [];
    let areOnline = false;
    try {
      const [sRes, aRes] = await Promise.all([
        fetch(`${ARE_URL}/stats`,          { signal: AbortSignal.timeout(4000) }),
        fetch(`${ARE_URL}/actions?limit=50`, { signal: AbortSignal.timeout(4000) }),
      ]);
      if (sRes.ok) { areStats = await sRes.json(); areOnline = true; }
      if (aRes.ok) { const d = await aRes.json(); areActions = Array.isArray(d) ? d : (d.actions ?? []); }
    } catch { /* ARE offline */ }

    setState({
      threats,
      allScans,
      dbStats,
      areStats,
      areActions,
      threatBackendOnline: threatOnline,
      areBackendOnline: areOnline,
      lastRefresh: new Date(),
    });
    setLoading(false);
  }, []);

  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, POLL_MS);
    return () => clearInterval(timer);
  }, [refresh]);

  // ── Derived data ──────────────────────────────────────────────────────────
  const { threats, allScans, dbStats, areStats, areActions } = state;

  // Prefer DB stats (authoritative) over derived counts from local array
  const totalScans    = dbStats?.total_predictions ?? allScans.length;
  const totalThreats  = dbStats?.adversarial_count ?? threats.length;
  const cleanCount    = dbStats?.clean_count       ?? (allScans.length - threats.length);
  const activeThreats = threats.filter((t) => t.status === 'detected').length;
  const mitigationRate = totalScans > 0
    ? ((cleanCount / totalScans) * 100).toFixed(1)
    : '0.0';
  const avgConfidence = dbStats?.average_confidence != null
    ? (dbStats.average_confidence * 100).toFixed(1)
    : threats.length > 0
      ? (threats.reduce((s, t) => s + (t.confidence || 0), 0) / threats.length * 100).toFixed(1)
      : '0.0';

  const timeSeriesData  = buildTimeSeriesFromScans(allScans);
  const severityDist    = buildSeverityDist(threats);
  const attackTypeDist  = buildAttackTypeDist(threats);

  const recentThreats = threats.slice(0, 5);

  // ARE action type bar chart
  const actionTypeChart = areActions.reduce((acc: Record<string, number>, a) => {
    acc[a.action] = (acc[a.action] || 0) + 1;
    return acc;
  }, {});
  const actionBarData = Object.entries(actionTypeChart).map(([name, count]) => ({ name, count }));

  // ── UI ────────────────────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-slate-950 p-6">
      <div className="max-w-7xl mx-auto space-y-6">

        {/* ── Header ── */}
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div>
            <h1 className="text-3xl font-bold text-white">PhantomNet++ Dashboard</h1>
            <p className="text-slate-400 mt-1">Real-time adversarial threat detection & autonomous mitigation</p>
          </div>
          <div className="flex items-center gap-4">
            {/* Backend status pills */}
            <div className="flex items-center gap-2">
              <span
                className={`flex items-center gap-1.5 text-xs px-2 py-1 rounded-full border ${
                  state.threatBackendOnline
                    ? 'border-green-500/40 bg-green-500/10 text-green-400'
                    : 'border-red-500/40 bg-red-500/10 text-red-400'
                }`}
              >
                <span className={`w-1.5 h-1.5 rounded-full ${state.threatBackendOnline ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`} />
                Detection API
              </span>
              <span
                className={`flex items-center gap-1.5 text-xs px-2 py-1 rounded-full border ${
                  state.areBackendOnline
                    ? 'border-green-500/40 bg-green-500/10 text-green-400'
                    : 'border-red-500/40 bg-red-500/10 text-red-400'
                }`}
              >
                <span className={`w-1.5 h-1.5 rounded-full ${state.areBackendOnline ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`} />
                ARE API
              </span>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={refresh}
              className="border-slate-700 text-slate-300 hover:text-white hover:bg-slate-800"
            >
              <RefreshCw className="w-4 h-4 mr-1.5" />
              Refresh
            </Button>
            {state.lastRefresh && (
              <span className="text-xs text-slate-500">
                Updated {state.lastRefresh.toLocaleTimeString('en-PK', { timeZone: 'Asia/Karachi' })}
              </span>
            )}
          </div>
        </div>

        {loading && (
          <div className="text-center py-12 text-slate-400">Loading real-time data…</div>
        )}

        {/* ── KPI Cards ── */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
          <Card className="bg-slate-900 border-slate-800">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-slate-400 flex items-center gap-2">
                <Shield className="w-4 h-4" /> Total Scans
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">{totalScans}</div>
              <p className="text-xs text-slate-500 mt-1">Images analysed</p>
            </CardContent>
          </Card>

          <Card className="bg-slate-900 border-slate-800">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-slate-400 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4" /> Threats Found
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-red-400">{totalThreats}</div>
              <p className="text-xs text-slate-500 mt-1">{cleanCount} clean scans</p>
            </CardContent>
          </Card>

          <Card className="bg-slate-900 border-slate-800">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-slate-400 flex items-center gap-2">
                <CheckCircle className="w-4 h-4" /> Clean Rate
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-400">{mitigationRate}%</div>
              <Progress value={parseFloat(mitigationRate)} className="mt-2 h-1" />
            </CardContent>
          </Card>

          <Card className="bg-slate-900 border-slate-800">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-slate-400 flex items-center gap-2">
                <Cpu className="w-4 h-4" /> Avg Confidence
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-blue-400">{avgConfidence}%</div>
              <p className="text-xs text-slate-500 mt-1">Detection certainty</p>
            </CardContent>
          </Card>

          <Card className="bg-slate-900 border-slate-800">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-slate-400 flex items-center gap-2">
                <Zap className="w-4 h-4" /> ARE Actions
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-purple-400">
                {areStats ? (areStats.totalIsolations + areStats.totalModelSwitches + areStats.totalEscalations) : '—'}
              </div>
              <p className="text-xs text-slate-500 mt-1">
                {areStats ? `${areStats.successRate}% success rate` : 'ARE offline'}
              </p>
            </CardContent>
          </Card>
        </div>

        {/* ── ARE Stats Row ── */}
        {areStats && (
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {[
              { label: 'Isolations', value: areStats.totalIsolations, color: 'text-red-400' },
              { label: 'Model Switches', value: areStats.totalModelSwitches, color: 'text-yellow-400' },
              { label: 'Escalations', value: areStats.totalEscalations, color: 'text-orange-400' },
            ].map(({ label, value, color }) => (
              <Card key={label} className="bg-slate-900 border-slate-800">
                <CardContent className="pt-5 pb-4 flex items-center justify-between">
                  <span className="text-sm text-slate-400">{label}</span>
                  <span className={`text-xl font-bold ${color}`}>{value}</span>
                </CardContent>
              </Card>
            ))}
          </div>
        )}

        {/* ── Charts Row 1 ── */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

          {/* Scan activity over time */}
          <Card className="bg-slate-900 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white">Scan Activity (Last 12 h)</CardTitle>
              <CardDescription className="text-slate-400">Detected vs clean scans per hour</CardDescription>
            </CardHeader>
            <CardContent>
              {allScans.length === 0 ? (
                <div className="flex items-center justify-center h-[280px] text-slate-500 text-sm">
                  No scan data yet — analyse images in Threat Detection
                </div>
              ) : (
                <ResponsiveContainer width="100%" height={280}>
                  <AreaChart data={timeSeriesData}>
                    <defs>
                      <linearGradient id="gDetected" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                      </linearGradient>
                      <linearGradient id="gClean" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.2} />
                        <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis dataKey="hour" stroke="#475569" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                    <YAxis stroke="#475569" tick={{ fill: '#94a3b8', fontSize: 11 }} allowDecimals={false} />
                    <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }} labelStyle={{ color: '#e2e8f0' }} />
                    <Legend />
                    <Area type="monotone" dataKey="detected" stroke="#ef4444" fill="url(#gDetected)" name="Detected" strokeWidth={2} />
                    <Area type="monotone" dataKey="clean"    stroke="#3b82f6" fill="url(#gClean)"    name="Clean"    strokeWidth={2} />
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </CardContent>
          </Card>

          {/* Severity distribution */}
          <Card className="bg-slate-900 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white">Severity Distribution</CardTitle>
              <CardDescription className="text-slate-400">Breakdown of detected threats by severity</CardDescription>
            </CardHeader>
            <CardContent>
              {severityDist.length === 0 ? (
                <div className="flex items-center justify-center h-[280px] text-slate-500 text-sm">
                  No threats detected yet
                </div>
              ) : (
                <ResponsiveContainer width="100%" height={280}>
                  <PieChart>
                    <Pie
                      data={severityDist}
                      cx="50%"
                      cy="50%"
                      outerRadius={100}
                      dataKey="value"
                      labelLine={false}
                    >
                      {severityDist.map((entry) => (
                        <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name] ?? '#8b5cf6'} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
                      formatter={(value: number, name: string) => {
                        const total = severityDist.reduce((s, d) => s + d.value, 0);
                        const color = SEVERITY_COLORS[name] ?? '#8b5cf6';
                        return [
                          <span style={{ color }}>{value} ({((value / total) * 100).toFixed(0)}%)</span>,
                          <span style={{ color }}>{name}</span>,
                        ];
                      }}
                    />
                    <Legend
                      content={({ payload }) => {
                        const total = severityDist.reduce((s, d) => s + d.value, 0);
                        return (
                          <div style={{ display: 'flex', justifyContent: 'center', flexWrap: 'wrap', gap: '16px', marginTop: '12px' }}>
                            {payload?.map((entry: any) => {
                              const item = severityDist.find(d => d.name === entry.value);
                              const pct = item ? ((item.value / total) * 100).toFixed(0) : '0';
                              return (
                                <div key={entry.value} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                  <div style={{ width: 10, height: 10, borderRadius: 2, background: entry.color, flexShrink: 0 }} />
                                  <span style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'capitalize' }}>{entry.value}</span>
                                  <span style={{ fontSize: '0.75rem', color: '#e2e8f0', fontWeight: 600 }}>{pct}%</span>
                                </div>
                              );
                            })}
                          </div>
                        );
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              )}
            </CardContent>
          </Card>
        </div>

        {/* ── Charts Row 2 ── */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

          {/* Attack type distribution */}
          <Card className="bg-slate-900 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white">Top Attack Types</CardTitle>
              <CardDescription className="text-slate-400">Most frequent adversarial techniques</CardDescription>
            </CardHeader>
            <CardContent>
              {attackTypeDist.length === 0 ? (
                <div className="flex items-center justify-center h-[240px] text-slate-500 text-sm">
                  No attack type data yet
                </div>
              ) : (
                <ResponsiveContainer width="100%" height={240}>
                  <BarChart data={attackTypeDist} layout="vertical">
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                    <XAxis type="number" stroke="#475569" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                    <YAxis type="category" dataKey="name" stroke="#475569" tick={{ fill: '#94a3b8', fontSize: 11 }} width={120} />
                    <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }} />
                    <Bar dataKey="value" name="Count" radius={[0, 4, 4, 0]}>
                      {attackTypeDist.map((_entry, idx) => (
                        <Cell key={idx} fill={CHART_COLORS[idx % CHART_COLORS.length]} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              )}
            </CardContent>
          </Card>

          {/* ARE action breakdown */}
          <Card className="bg-slate-900 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Activity className="w-5 h-5 text-purple-500" />
                ARE Action Breakdown
              </CardTitle>
              <CardDescription className="text-slate-400">Autonomous response actions by type</CardDescription>
            </CardHeader>
            <CardContent>
              {actionBarData.length === 0 ? (
                <div className="flex items-center justify-center h-[240px] text-slate-500 text-sm">
                  {state.areBackendOnline ? 'No actions logged yet' : 'ARE backend offline'}
                </div>
              ) : (
                <ResponsiveContainer width="100%" height={240}>
                  <BarChart data={actionBarData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis dataKey="name" stroke="#475569" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                    <YAxis stroke="#475569" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                    <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }} />
                    <Bar dataKey="count" name="Actions" fill="#8b5cf6" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </CardContent>
          </Card>
        </div>

        {/* ── Bottom Row: Recent Threats + Recent ARE Actions ── */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

          {/* Recent Threats */}
          <Card className="bg-slate-900 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white">Recent Threats</CardTitle>
              <CardDescription className="text-slate-400">Latest 5 adversarial detections</CardDescription>
            </CardHeader>
            <CardContent>
              {recentThreats.length === 0 ? (
                <div className="text-center py-8">
                  <Shield className="w-10 h-10 text-slate-700 mx-auto mb-2" />
                  <p className="text-slate-500 text-sm">No threats detected yet</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {recentThreats.map((threat) => (
                    <div
                      key={threat.id}
                      className="flex items-center justify-between p-3 rounded-lg bg-slate-800/50 border border-slate-700 hover:border-slate-600 transition-colors"
                    >
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-mono text-xs text-slate-400">{threat.id}</span>
                          <Badge
                            variant="outline"
                            className={
                              threat.severity === 'critical'
                                ? 'border-red-500/50 bg-red-500/10 text-red-400'
                                : threat.severity === 'high'
                                ? 'border-orange-500/50 bg-orange-500/10 text-orange-400'
                                : threat.severity === 'medium'
                                ? 'border-yellow-500/50 bg-yellow-500/10 text-yellow-400'
                                : 'border-blue-500/50 bg-blue-500/10 text-blue-400'
                            }
                          >
                            {threat.severity.toUpperCase()}
                          </Badge>
                        </div>
                        <p className="text-white text-sm font-medium mt-1 truncate">{threat.type}</p>
                        <p className="text-xs text-slate-400 truncate">
                          {threat.modelTarget} • {threat.attackVector}
                        </p>
                      </div>
                      <div className="ml-3 text-right shrink-0">
                        <div className="text-xs text-slate-500">conf.</div>
                        <div className="text-white text-sm font-medium">
                          {(threat.confidence * 100).toFixed(0)}%
                        </div>
                        <Badge
                          variant="outline"
                          className={
                            threat.status === 'detected'
                              ? 'border-red-500/50 bg-red-500/10 text-red-400 text-xs mt-1'
                              : 'border-green-500/50 bg-green-500/10 text-green-400 text-xs mt-1'
                          }
                        >
                          {threat.status.toUpperCase()}
                        </Badge>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Recent ARE Actions */}
          <Card className="bg-slate-900 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <TrendingUp className="w-5 h-5 text-green-500" />
                Recent ARE Actions
              </CardTitle>
              <CardDescription className="text-slate-400">Latest autonomous response actions</CardDescription>
            </CardHeader>
            <CardContent>
              {areActions.length === 0 ? (
                <div className="text-center py-8">
                  <Zap className="w-10 h-10 text-slate-700 mx-auto mb-2" />
                  <p className="text-slate-500 text-sm">
                    {state.areBackendOnline ? 'No actions logged yet' : 'ARE backend is offline'}
                  </p>
                </div>
              ) : (
                <div className="space-y-3 max-h-[320px] overflow-y-auto pr-1 no-scrollbar">
                  {areActions.slice(0, 8).map((action) => (
                    <div
                      key={action.id}
                      className="flex items-center justify-between p-3 rounded-lg bg-slate-800/50 border border-slate-700"
                    >
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <Badge
                            variant="outline"
                            className="border-purple-500/50 bg-purple-500/10 text-purple-400 text-xs"
                          >
                            {action.action}
                          </Badge>
                          <span className="text-xs text-slate-400 truncate">{action.policyName}</span>
                        </div>
                        <p className="text-sm text-slate-300 mt-1 truncate">Target: {action.target}</p>
                        <p className="text-xs text-slate-500">
                          {parseTS(action.timestamp) ? new Date(parseTS(action.timestamp)).toLocaleString('en-GB', { timeZone: 'Asia/Karachi' }) : action.timestamp} • {action.executionTime}ms
                        </p>
                      </div>
                      <Badge
                        variant="outline"
                        className={
                          action.result === 'success'
                            ? 'border-green-500/50 bg-green-500/10 text-green-400 text-xs ml-2 shrink-0'
                            : action.result === 'failed'
                            ? 'border-red-500/50 bg-red-500/10 text-red-400 text-xs ml-2 shrink-0'
                            : 'border-yellow-500/50 bg-yellow-500/10 text-yellow-400 text-xs ml-2 shrink-0'
                        }
                      >
                        {action.result}
                      </Badge>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>

      </div>
    </div>
  );
}