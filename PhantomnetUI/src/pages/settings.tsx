/**
 * settings.tsx — PhantomNet++ Admin Settings
 * Three sections:
 *  1. Detection Mode   → threat_detection_backend (port 5000)
 *  2. SRC Rate Limit   → src_backend (port 8006)
 *  3. Module Health    → all backends health checks
 */

import { useState, useEffect, useCallback } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Slider } from "@/components/ui/slider";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Shield, Lock, Server,
  CheckCircle, XCircle, Loader2, RefreshCw, AlertTriangle, Save,
} from "lucide-react";

// ── Backend URLs ──────────────────────────────────────────────────────────────
const IVM_BASE  = "http://localhost:5000";
const SRC_BASE  = "http://localhost:8006";

// ── Module registry for health checks ────────────────────────────────────────
const MODULES = [
  { name: "IVM",    label: "Threat Detection",   url: "http://localhost:5000/api/health",        port: 5000 },
  { name: "ARE",    label: "Response Engine",     url: "http://localhost:8000/api/are/health",    port: 8000 },
  { name: "XAI",    label: "Explainability",      url: "http://localhost:5001/api/xai/health",    port: 5001 },
  { name: "SIEM",   label: "SIEM Logger",         url: "http://localhost:8003/api/siem/health",   port: 8003 },
  { name: "SRC",    label: "Secure Coord.",        url: "http://localhost:8006/api/src/health",    port: 8006 },
  { name: "DAG",    label: "Attack Simulator",    url: "http://localhost:8001/docs",             port: 8001 },
  { name: "Report", label: "Report Backend",      url: "http://localhost:8004/api/report/health", port: 8004 },
  { name: "Auth",   label: "Authentication",      url: "http://localhost:8002/api/auth/health",   port: 8002 },
];

type ModuleHealth = "online" | "offline" | "checking";

interface Toast { msg: string; type: "success" | "error" | "info" }

export default function Settings() {
  // ── Detection mode state ───────────────────────────────────────────────────
  const [detectionMode,    setDetectionMode]    = useState<"normal" | "hardened">("normal");
  const [modeLoading,      setModeLoading]      = useState(false);

  // ── SRC rate limit state ───────────────────────────────────────────────────
  const [rateLimit,        setRateLimit]        = useState(() => parseInt(localStorage.getItem('src_rate_limit') ?? '60', 10));
  const [rateLimitDirty,   setRateLimitDirty]   = useState(false);
  const [rateLimitLoading, setRateLimitLoading] = useState(false);

  // ── Module health state ────────────────────────────────────────────────────
  const [health,           setHealth]           = useState<Record<string, ModuleHealth>>({});
  const [healthLoading,    setHealthLoading]    = useState(false);

  // ── Toast ──────────────────────────────────────────────────────────────────
  const [toast,            setToast]            = useState<Toast | null>(null);

  const showToast = (msg: string, type: Toast["type"] = "success") => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3500);
  };

  // ── Load on mount ─────────────────────────────────────────────────────────
  useEffect(() => {
    fetch(`${IVM_BASE}/api/active-model`)
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (d) setDetectionMode(d.active_model); })
      .catch(() => {});

    fetch(`${SRC_BASE}/api/src/status`)
      .then(r => r.ok ? r.json() : null)
      .then(d => {
        if (d?.rate_limits?.[0]?.limit) {
          setRateLimit(d.rate_limits[0].limit);
          localStorage.setItem('src_rate_limit', String(d.rate_limits[0].limit));
        }
      })
      .catch(() => {});
  }, []);

  // ── Health check ──────────────────────────────────────────────────────────
  const checkHealth = useCallback(async () => {
    setHealthLoading(true);
    const init: Record<string, ModuleHealth> = {};
    MODULES.forEach(m => { init[m.name] = "checking"; });
    setHealth(init);

    await Promise.all(MODULES.map(async m => {
      try {
        const r = await fetch(m.url, { signal: AbortSignal.timeout(3000) });
        const ok = m.name === "DAG" ? r.status < 500 : r.ok;
        setHealth(prev => ({ ...prev, [m.name]: ok ? "online" : "offline" }));
      } catch {
        setHealth(prev => ({ ...prev, [m.name]: "offline" }));
      }
    }));
    setHealthLoading(false);
  }, []);

  useEffect(() => { checkHealth(); }, [checkHealth]);

  // ── Toggle detection mode ─────────────────────────────────────────────────
  const toggleMode = async () => {
    const next = detectionMode === "normal" ? "hardened" : "normal";
    setModeLoading(true);
    try {
      const res = await fetch(`${IVM_BASE}/api/switch-model`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ model: next }),
      });
      if (!res.ok) throw new Error();
      setDetectionMode(next);
      showToast(`Detection mode switched to ${next.toUpperCase()}.`, "info");
    } catch {
      showToast("Failed to switch mode. Is IVM backend running?", "error");
    } finally {
      setModeLoading(false);
    }
  };

  // ── Save rate limit ────────────────────────────────────────────────────────
  const saveRateLimit = async () => {
    setRateLimitLoading(true);
    try {
      const res = await fetch(`${SRC_BASE}/api/src/rate-limit`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ limit: rateLimit }),
      });
      if (!res.ok) throw new Error();
      setRateLimitDirty(false);
      localStorage.setItem('src_rate_limit', String(rateLimit));
      showToast(`SRC rate limit updated to ${rateLimit} req/min.`);
    } catch {
      showToast("Failed to update rate limit. Is SRC backend running?", "error");
    } finally {
      setRateLimitLoading(false);
    }
  };

  const onlineCount = Object.values(health).filter(h => h === "online").length;

  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Settings</h1>
          <p className="text-muted-foreground mt-1">
            Admin configuration — all changes take effect immediately
          </p>
        </div>
        <Badge variant="outline" className="text-emerald-400 border-emerald-400/30 bg-emerald-400/5 px-3 py-1">
          {onlineCount} / {MODULES.length} modules online
        </Badge>
      </div>

      {/* Toast */}
      {toast && (
        <Alert variant={toast.type === "error" ? "destructive" : "default"}>
          {toast.type === "success" && <CheckCircle className="h-4 w-4 text-emerald-400" />}
          {toast.type === "error"   && <XCircle     className="h-4 w-4" />}
          {toast.type === "info"    && <AlertTriangle className="h-4 w-4 text-amber-400" />}
          <AlertDescription>{toast.msg}</AlertDescription>
        </Alert>
      )}

      <Tabs defaultValue="mode" className="space-y-6">
        <TabsList className="bg-muted border border-border">
          <TabsTrigger value="mode">Detection Mode</TabsTrigger>
          <TabsTrigger value="src">SRC Rate Limit</TabsTrigger>
          <TabsTrigger value="health">Module Health</TabsTrigger>
        </TabsList>

        {/* ── Tab 1: Detection Mode ── */}
        <TabsContent value="mode" className="space-y-6">
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <Shield className="h-5 w-5 text-emerald-400" />
                <div>
                  <CardTitle>Detection Mode</CardTitle>
                  <CardDescription>Switch between Normal and Hardened detection posture</CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-6">

              <div className="flex items-center justify-between p-4 rounded-lg border border-border bg-muted/30">
                <div>
                  <p className="font-medium text-sm">Current Mode</p>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    {detectionMode === "hardened"
                      ? "Hardened — tighter thresholds, boosted model weights, lower decision bar"
                      : "Normal — balanced ensemble with standard thresholds"}
                  </p>
                </div>
                <Badge variant={detectionMode === "hardened" ? "destructive" : "default"} className="text-sm px-3 py-1">
                  {detectionMode.toUpperCase()}
                </Badge>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="p-4 rounded-lg border border-border space-y-2">
                  <p className="text-sm font-semibold">Normal Mode</p>
                  <div className="space-y-1 text-xs text-muted-foreground">
                    <p>YOLO weight: <span className="text-foreground font-mono">1.5</span></p>
                    <p>Autoencoder weight: <span className="text-foreground font-mono">1.2</span></p>
                    <p>ResNet weight: <span className="text-foreground font-mono">1.0</span></p>
                    <p>Decision threshold: <span className="text-foreground font-mono">0.55</span></p>
                    <p>YOLO conf: <span className="text-foreground font-mono">0.25</span></p>
                  </div>
                </div>
                <div className="p-4 rounded-lg border border-red-500/30 bg-red-500/5 space-y-2">
                  <p className="text-sm font-semibold text-red-400">Hardened Mode</p>
                  <div className="space-y-1 text-xs text-muted-foreground">
                    <p>YOLO weight: <span className="text-red-400 font-mono">2.0 ↑</span></p>
                    <p>Autoencoder weight: <span className="text-red-400 font-mono">1.8 ↑</span></p>
                    <p>ResNet weight: <span className="text-red-400 font-mono">1.2 ↑</span></p>
                    <p>Decision threshold: <span className="text-red-400 font-mono">0.40 ↓</span></p>
                    <p>YOLO conf: <span className="text-red-400 font-mono">0.15 ↓</span></p>
                  </div>
                </div>
              </div>

              <Alert>
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription className="text-xs">
                  Switching to Hardened mode increases sensitivity but may cause more false positives.
                </AlertDescription>
              </Alert>

              <div className="flex items-center justify-between">
                <div>
                  <Label className="text-sm font-medium">
                    {detectionMode === "normal" ? "Switch to Hardened Mode" : "Switch to Normal Mode"}
                  </Label>
                  <p className="text-xs text-muted-foreground mt-0.5">Takes effect immediately</p>
                </div>
                {modeLoading
                  ? <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
                  : <Switch checked={detectionMode === "hardened"} onCheckedChange={toggleMode} />}
              </div>

            </CardContent>
          </Card>
        </TabsContent>

        {/* ── Tab 2: SRC Rate Limit ── */}
        <TabsContent value="src" className="space-y-6">
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <Lock className="h-5 w-5 text-rose-400" />
                <div>
                  <CardTitle>SRC Rate Limiting</CardTitle>
                  <CardDescription>Maximum requests per module per minute (DoS protection)</CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-6">

              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div>
                    <Label className="text-sm font-medium">Rate Limit</Label>
                    <p className="text-xs text-muted-foreground mt-0.5">Requests per module per minute before throttling</p>
                  </div>
                  <span className="text-2xl font-mono font-bold text-rose-400">
                    {rateLimit} <span className="text-sm text-muted-foreground font-normal">req/min</span>
                  </span>
                </div>
                <Slider
                  min={10} max={200} step={5}
                  value={[rateLimit]}
                  onValueChange={([v]) => { setRateLimit(v); setRateLimitDirty(true); }}
                  className="w-full [&_[role=slider]]:bg-rose-400 [&_[role=slider]]:border-rose-400 [&_.bg-primary]:bg-rose-400"
                />
                <div className="flex justify-between text-[10px] text-muted-foreground">
                  <span>10 (strict)</span><span>60 (default)</span><span>200 (permissive)</span>
                </div>
              </div>

              <div className="grid grid-cols-3 gap-3 text-center">
                {[
                  { label: "Strict",     value: 20,  color: "text-red-400",     desc: "High security" },
                  { label: "Default",    value: 60,  color: "text-emerald-400", desc: "Recommended"   },
                  { label: "Permissive", value: 120, color: "text-blue-400",    desc: "High traffic"  },
                ].map(p => (
                  <button
                    key={p.label}
                    onClick={() => { setRateLimit(p.value); setRateLimitDirty(true); }}
                    className={`p-3 rounded-lg border border-border hover:bg-muted/50 transition-colors cursor-pointer ${rateLimit === p.value ? 'bg-muted' : ''}`}
                  >
                    <p className={`text-lg font-mono font-bold ${p.color}`}>{p.value}</p>
                    <p className="text-xs font-medium">{p.label}</p>
                    <p className="text-[10px] text-muted-foreground">{p.desc}</p>
                  </button>
                ))}
              </div>

              <Button onClick={saveRateLimit} disabled={!rateLimitDirty || rateLimitLoading} className="gap-2 w-full">
                {rateLimitLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
                {rateLimitDirty ? `Save Rate Limit (${rateLimit} req/min)` : "No Changes to Save"}
              </Button>

            </CardContent>
          </Card>
        </TabsContent>

        {/* ── Tab 3: Module Health ── */}
        <TabsContent value="health" className="space-y-6">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Server className="h-5 w-5 text-blue-400" />
                  <div>
                    <CardTitle>Module Health</CardTitle>
                    <CardDescription>Live status of all PhantomNet++ backend services</CardDescription>
                  </div>
                </div>
                <Button variant="outline" size="sm" onClick={checkHealth} disabled={healthLoading} className="gap-1">
                  {healthLoading ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
                  Refresh
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {MODULES.map(m => {
                  const status = health[m.name] ?? "checking";
                  return (
                    <div
                      key={m.name}
                      className={`flex items-center justify-between p-4 rounded-lg border transition-colors ${
                        status === "online"   ? "border-emerald-500/30 bg-emerald-500/5" :
                        status === "offline"  ? "border-red-500/30 bg-red-500/5" :
                        "border-border bg-muted/20"
                      }`}
                    >
                      <div className="flex items-center gap-3">
                        <div className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${
                          status === "online"   ? "bg-emerald-400 animate-pulse" :
                          status === "offline"  ? "bg-red-400" :
                          "bg-yellow-400 animate-pulse"
                        }`} />
                        <div>
                          <p className="text-sm font-semibold">{m.name}</p>
                          <p className="text-xs text-muted-foreground">{m.label}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] font-mono text-muted-foreground">:{m.port}</span>
                        {status === "online"   && <CheckCircle className="h-4 w-4 text-emerald-400" />}
                        {status === "offline"  && <XCircle     className="h-4 w-4 text-red-400" />}
                        {status === "checking" && <Loader2     className="h-4 w-4 text-yellow-400 animate-spin" />}
                      </div>
                    </div>
                  );
                })}
              </div>

              <div className="mt-4 p-3 rounded-lg bg-muted/30 border border-border">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">System Status</span>
                  <span className={`font-semibold ${
                    onlineCount === MODULES.length ? "text-emerald-400" :
                    onlineCount > MODULES.length / 2 ? "text-amber-400" : "text-red-400"
                  }`}>
                    {onlineCount === MODULES.length
                      ? "All Systems Operational"
                      : onlineCount > MODULES.length / 2
                      ? "Partial Outage"
                      : "Critical — Multiple Modules Down"}
                  </span>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

      </Tabs>
    </div>
  );
}