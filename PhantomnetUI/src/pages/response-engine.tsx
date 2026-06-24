/**
 * Autonomous Response Engine (ARE) — ResponseEngine.tsx
 * Connected to: are_backend.py  (FastAPI on http://localhost:8000)
 *
 * Permissions:
 *   user            → view policies & action log only (no add/edit/toggle/release)
 *   security_analyst → full control including threat intel sync
 *   admin           → view only (same as user)
 *
 * Threat Intel:
 *   The security analyst syncs live MITRE ATT&CK techniques directly
 *   from this page. Admin has zero involvement. New policies arrive
 *   disabled and are logged to SIEM. Only the analyst can enable them.
 */

"use client";

import { useEffect, useState, useCallback } from "react";
import {
  Card, CardContent, CardDescription, CardHeader, CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Switch } from "@/components/ui/switch";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Shield, CheckCircle, XCircle, AlertTriangle, Activity,
  Settings, Info, ArrowUpDown, Loader2, Lock, LockOpen, Eye,
  Globe, RefreshCw,
} from "lucide-react";
import { useSession, ViewOnlyBanner } from "@/hooks/useSession";

const API_BASE = "http://localhost:8000/api/are";

// ── Dark mode hook ─────────────────────────────────────────────────────────────
function useIsDark() {
  const [isDark, setIsDark] = useState(
    () => document.documentElement.classList.contains("dark")
  );
  useEffect(() => {
    const obs = new MutationObserver(() =>
      setIsDark(document.documentElement.classList.contains("dark"))
    );
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });
    return () => obs.disconnect();
  }, []);
  return isDark;
}

// ── Types ──────────────────────────────────────────────────────────────────────
type ActionType = "isolate" | "switch_model" | "escalate" | "retrain" | "block" | "log" | "monitor";
type ActionStatus = "success" | "failed" | "partial_success" | "pending";

interface ResponsePolicy {
  id: string; priority: number; name: string; condition: string;
  action: ActionType; enabled: boolean; lastTriggered: string | null;
  triggerCount: number; createdAt: string;
}
interface AutonomousAction {
  id: string; policyId: string; policyName: string; action: ActionType;
  target: string; reason: string; details: string; result: ActionStatus;
  executionTime: number; timestamp: string;
}
interface AREStats {
  totalIsolations: number; totalModelSwitches: number;
  totalEscalations: number; successRate: number;
}
interface IsolationRecord {
  threat_id: string; filename: string; isolated_at: string;
  expires_at: string; duration_s: number; remaining_s: number;
  policy_name: string; status: "active" | "expired" | "released";
}
interface PolicyFormState {
  name: string; priority: string; condition: string; action: ActionType; enabled: boolean;
}
const DEFAULT_FORM: PolicyFormState = {
  name: "", priority: "", condition: "", action: "monitor", enabled: false,
};

// ── Helpers ────────────────────────────────────────────────────────────────────
const ACTION_CONFIG: Record<ActionType, { variant: any; icon: any; label: string }> = {
  isolate:      { variant: "destructive", icon: Shield,        label: "Isolate"       },
  switch_model: { variant: "default",     icon: Activity,      label: "Switch Model"  },
  escalate:     { variant: "outline",     icon: AlertTriangle, label: "Escalate"      },
  retrain:      { variant: "secondary",   icon: Settings,      label: "Retrain"       },
  block:        { variant: "destructive", icon: XCircle,       label: "Block"         },
  log:          { variant: "secondary",   icon: Activity,      label: "Log"           },
  monitor:      { variant: "secondary",   icon: Activity,      label: "Monitor"       },
};

function ActionBadge({ action }: { action: ActionType }) {
  const cfg = ACTION_CONFIG[action] ?? ACTION_CONFIG.monitor;
  const Icon = cfg.icon;
  return (
    <Badge variant={cfg.variant} className="gap-1 capitalize">
      <Icon className="h-3 w-3" />{cfg.label}
    </Badge>
  );
}
function ResultIcon({ result }: { result: ActionStatus }) {
  if (result === "success") return <CheckCircle className="h-4 w-4 text-green-500" />;
  if (result === "failed")  return <XCircle     className="h-4 w-4 text-red-500" />;
  return <Activity className="h-4 w-4 text-yellow-500" />;
}
function fmtDate(iso: string | null) {
  if (!iso) return "Never";
  return new Date(iso).toLocaleString();
}

// Identifies policies sourced from live MITRE ATT&CK feed
function isIntelPolicy(policy: ResponsePolicy): boolean {
  return policy.name.startsWith("[INTEL");
}

// ── Component ──────────────────────────────────────────────────────────────────
export default function ResponseEngine() {
  const isDark = useIsDark();
  const { can, session } = useSession();

  const canControl = can("responseEngineControl"); // analyst only
  const roleLabel  = session?.role === "user"
    ? "Standard User"
    : session?.role === "admin" ? "Administrator" : "";

  // Core state
  const [stats,      setStats]      = useState<AREStats | null>(null);
  const [policies,   setPolicies]   = useState<ResponsePolicy[]>([]);
  const [actions,    setActions]    = useState<AutonomousAction[]>([]);
  const [isolations, setIsolations] = useState<IsolationRecord[]>([]);
  const [loadingStats,      setLoadingStats]      = useState(true);
  const [loadingPolicies,   setLoadingPolicies]   = useState(true);
  const [loadingActions,    setLoadingActions]     = useState(true);
  const [loadingIsolations, setLoadingIsolations] = useState(true);
  const [sortBy,    setSortBy]    = useState<"priority" | "condition" | "name">("priority");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("asc");
  const [modalOpen,      setModalOpen]      = useState(false);
  const [editingPolicy,  setEditingPolicy]  = useState<ResponsePolicy | null>(null);
  const [form,           setForm]           = useState<PolicyFormState>(DEFAULT_FORM);
  const [conditionError, setConditionError] = useState<string>("");
  const [savingPolicy,   setSavingPolicy]   = useState(false);

  // Threat intel state — analyst only
  const [syncing,     setSyncing]     = useState(false);
  const [syncMessage, setSyncMessage] = useState<{ok: boolean; text: string} | null>(null);

  // Fetch helpers
  const fetchStats = useCallback(async () => {
    try {
      setLoadingStats(true);
      const res = await fetch(`${API_BASE}/stats`);
      setStats(await res.json());
    } catch (e) { console.error("Stats fetch failed", e); }
    finally { setLoadingStats(false); }
  }, []);

  const fetchPolicies = useCallback(async () => {
    try {
      setLoadingPolicies(true);
      const res  = await fetch(`${API_BASE}/policies?sort_by=${sortBy}&order=${sortOrder}`);
      const data = await res.json();
      setPolicies(data.policies ?? []);
    } catch (e) { console.error("Policies fetch failed", e); }
    finally { setLoadingPolicies(false); }
  }, [sortBy, sortOrder]);

  const fetchActions = useCallback(async () => {
    try {
      setLoadingActions(true);
      const res  = await fetch(`${API_BASE}/actions?limit=20`);
      const data = await res.json();
      setActions(data.actions ?? []);
    } catch (e) { console.error("Actions fetch failed", e); }
    finally { setLoadingActions(false); }
  }, []);

  const fetchIsolations = useCallback(async () => {
    try {
      setLoadingIsolations(true);
      const res = await fetch(`${API_BASE}/isolations`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setIsolations(data.isolations ?? []);
    } catch (e) { console.error("Isolations fetch failed:", e); }
    finally { setLoadingIsolations(false); }
  }, []);

  useEffect(() => { fetchStats(); },    [fetchStats]);
  useEffect(() => { fetchPolicies(); }, [fetchPolicies]);
  useEffect(() => { fetchActions(); },  [fetchActions]);
  useEffect(() => {
    fetchIsolations();
    const t = setInterval(fetchIsolations, 10_000);
    return () => clearInterval(t);
  }, [fetchIsolations]);

  // ── Analyst-only: sync threat intel from MITRE ATT&CK ─────────────────────
  async function syncThreatIntel() {
    if (!canControl) return;
    setSyncing(true);
    setSyncMessage(null);
    try {
      const res  = await fetch(`${API_BASE}/sync-threat-intel`, { method: "POST" });
      const data = await res.json();
      if (data.success) {
        setSyncMessage({ ok: true, text: "Sync complete. New techniques logged to SIEM and added for review below." });
        fetchPolicies(); // refresh to show new intel policies
      } else {
        setSyncMessage({ ok: false, text: `Sync failed: ${data.error}` });
      }
    } catch {
      setSyncMessage({ ok: false, text: "Sync failed — is ARE backend running?" });
    } finally {
      setSyncing(false);
    }
  }

  // ── Policy actions — all guarded by canControl ─────────────────────────────
  async function togglePolicy(policy: ResponsePolicy) {
    if (!canControl) return;
    const newState = !policy.enabled;
    setPolicies(prev =>
      prev.map(p => p.id === policy.id ? { ...p, enabled: newState } : p)
    );
    try {
      await fetch(`${API_BASE}/policies/${policy.id}/toggle`, {
        method:  "PATCH",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ enabled: newState }),
      });
    } catch {
      setPolicies(prev =>
        prev.map(p => p.id === policy.id ? { ...p, enabled: !newState } : p)
      );
    }
  }

  function handleSort(col: typeof sortBy) {
    if (sortBy === col) setSortOrder(o => o === "asc" ? "desc" : "asc");
    else { setSortBy(col); setSortOrder("asc"); }
  }

  function openAdd() {
    if (!canControl) return;
    setEditingPolicy(null); setForm(DEFAULT_FORM); setConditionError(""); setModalOpen(true);
  }

  function openEdit(policy: ResponsePolicy) {
    if (!canControl) return;
    setEditingPolicy(policy);
    setForm({
      name:      policy.name,
      priority:  String(policy.priority),
      condition: policy.condition,
      action:    policy.action,
      enabled:   policy.enabled,
    });
    setConditionError(""); setModalOpen(true);
  }

  async function validateCondition(condition: string) {
    if (!condition.trim()) { setConditionError(""); return; }
    try {
      const res  = await fetch(`${API_BASE}/validate-condition`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ condition }),
      });
      const data = await res.json();
      setConditionError(data.valid ? "" : data.error);
    } catch {
      setConditionError("Could not validate condition.");
    }
  }

  async function savePolicy() {
    if (!canControl) return;
    if (conditionError) return;
    await validateCondition(form.condition);
    if (conditionError) return;
    setSavingPolicy(true);
    try {
      const payload = {
        name:      form.name,
        priority:  Number(form.priority),
        condition: form.condition,
        action:    form.action,
        enabled:   form.enabled,
      };
      if (editingPolicy) {
        await fetch(`${API_BASE}/policies/${editingPolicy.id}`, {
          method:  "PATCH",
          headers: { "Content-Type": "application/json" },
          body:    JSON.stringify(payload),
        });
      } else {
        await fetch(`${API_BASE}/policies`, {
          method:  "POST",
          headers: { "Content-Type": "application/json" },
          body:    JSON.stringify(payload),
        });
      }
      setModalOpen(false); fetchPolicies();
    } catch (e) { console.error("Save failed", e); }
    finally { setSavingPolicy(false); }
  }

  async function releaseIsolation(threat_id: string) {
    if (!canControl) return;
    try {
      await fetch(`${API_BASE}/isolations/${threat_id}`, { method: "DELETE" });
      fetchIsolations(); fetchActions();
    } catch (e) { console.error("Release failed", e); }
  }

  // Split policies
  const atlasPolicies = policies.filter(p => !isIntelPolicy(p));
  const intelPolicies = policies.filter(p => isIntelPolicy(p));
  const pendingIntel  = intelPolicies.filter(p => !p.enabled).length;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Autonomous Response Engine (ARE)</h1>
        <p className="text-muted-foreground mt-2">
          Monitor and configure automated threat response policies
        </p>
      </div>

      {/* View-only banner for user and admin */}
      {!canControl && <ViewOnlyBanner role={roleLabel} />}

      {/* Pending intel banner — analyst only */}
      {canControl && pendingIntel > 0 && (
        <Alert className="border-blue-500/40 bg-blue-500/5">
          <Globe className="h-4 w-4 text-blue-400" />
          <AlertDescription className="text-sm">
            <span className="font-semibold text-blue-400">
              {pendingIntel} threat intel {pendingIntel === 1 ? "policy" : "policies"}
            </span>
            {" "}pending your review — scroll down to the Threat Intel Policies section.
          </AlertDescription>
        </Alert>
      )}

      {/* Stats */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {[
          { title: "Total Isolations",  value: stats?.totalIsolations,    sub: "Threats contained",     icon: Shield,        tip: "Total threats contained by isolating the agent or stream" },
          { title: "Model Switches",    value: stats?.totalModelSwitches,  sub: "Automatic failovers",   icon: Activity,      tip: "Automatic failovers to a fallback model triggered by policy" },
          { title: "Escalations",       value: stats?.totalEscalations,   sub: "Human review required", icon: AlertTriangle, tip: "Incidents forwarded to human reviewers" },
        ].map(({ title, value, sub, icon: Icon, tip }) => (
          <Card key={title}>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">{title}</CardTitle>
              <div className="flex items-center gap-1">
                <Info className="h-3 w-3 text-muted-foreground cursor-help" title={tip} />
                <Icon className="h-4 w-4 text-muted-foreground" />
              </div>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {loadingStats ? <Loader2 className="h-5 w-5 animate-spin" /> : value ?? 0}
              </div>
              <p className="text-xs text-muted-foreground">{sub}</p>
            </CardContent>
          </Card>
        ))}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Success Rate</CardTitle>
            <div className="flex items-center gap-1">
              <Info className="h-3 w-3 text-muted-foreground cursor-help" title="Percentage of autonomous actions that completed successfully" />
              <CheckCircle className="h-4 w-4 text-muted-foreground" />
            </div>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {loadingStats ? <Loader2 className="h-5 w-5 animate-spin" /> : `${stats?.successRate?.toFixed(1) ?? "0.0"}%`}
            </div>
            <Progress value={stats?.successRate ?? 0} className="mt-2" />
          </CardContent>
        </Card>
      </div>

      {/* ── ATLAS Policies ── */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Response Policies</CardTitle>
              <CardDescription>
                {canControl
                  ? "Configure automated response rules and thresholds"
                  : "View active response policies"}
              </CardDescription>
            </div>
            <div className="flex items-center gap-2">
              {canControl && (
                <Button onClick={openAdd}>
                  <Settings className="mr-2 h-4 w-4" /> Add Policy
                </Button>
              )}
              {!canControl && (
                <Badge variant="outline" className="gap-1 text-muted-foreground">
                  <Eye className="h-3 w-3" /> View only
                </Badge>
              )}
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {loadingPolicies ? (
            <div className="flex justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>
                    <Button variant="ghost" size="sm" onClick={() => handleSort("priority")} className="gap-1 -ml-3">
                      Priority <ArrowUpDown className="h-3 w-3" />
                    </Button>
                  </TableHead>
                  <TableHead>
                    <Button variant="ghost" size="sm" onClick={() => handleSort("name")} className="gap-1 -ml-3">
                      Policy Name <ArrowUpDown className="h-3 w-3" />
                    </Button>
                  </TableHead>
                  <TableHead>
                    <Button variant="ghost" size="sm" onClick={() => handleSort("condition")} className="gap-1 -ml-3">
                      Condition <ArrowUpDown className="h-3 w-3" />
                    </Button>
                  </TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Last Triggered</TableHead>
                  {canControl && <TableHead>Actions</TableHead>}
                </TableRow>
              </TableHeader>
              <TableBody>
                {atlasPolicies.map(policy => (
                  <TableRow key={policy.id}>
                    <TableCell className="font-medium">#{policy.priority}</TableCell>
                    <TableCell className="font-semibold">{policy.name}</TableCell>
                    <TableCell>
                      <code className="text-xs bg-muted px-2 py-1 rounded break-all">
                        {policy.condition}
                      </code>
                    </TableCell>
                    <TableCell><ActionBadge action={policy.action} /></TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Switch
                          checked={policy.enabled}
                          onCheckedChange={() => togglePolicy(policy)}
                          disabled={!canControl}
                        />
                        <span className="text-xs text-muted-foreground">
                          {policy.enabled ? "Enabled" : "Disabled"}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {fmtDate(policy.lastTriggered)}
                    </TableCell>
                    {canControl && (
                      <TableCell>
                        <Button variant="ghost" size="sm" onClick={() => openEdit(policy)}>Edit</Button>
                      </TableCell>
                    )}
                  </TableRow>
                ))}
                {atlasPolicies.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={canControl ? 7 : 6} className="text-center text-muted-foreground py-6">
                      No policies found.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* ── Threat Intel Policies — analyst only section ── */}
      {canControl && (
        <Card className="border-blue-500/20">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Globe className="h-5 w-5 text-blue-400" />
                <div>
                  <CardTitle className="flex items-center gap-2">
                    Threat Intel Policies
                    {pendingIntel > 0 && (
                      <Badge className="bg-blue-500/20 text-blue-400 border-blue-500/30 text-xs">
                        {pendingIntel} pending review
                      </Badge>
                    )}
                  </CardTitle>
                  <CardDescription>
                    Live MITRE ATT&CK techniques — synced and managed exclusively by the security analyst.
                    New policies are logged to SIEM and arrive disabled. Enable only what is relevant.
                  </CardDescription>
                </div>
              </div>

              {/* Sync button — analyst only, in the card header */}
              <div className="flex items-center gap-2 shrink-0">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={fetchPolicies}
                  disabled={loadingPolicies}
                  title="Refresh"
                >
                  <RefreshCw className="h-3 w-3" />
                </Button>
                <Button
                  size="sm"
                  onClick={syncThreatIntel}
                  disabled={syncing}
                  className="gap-2"
                >
                  {syncing
                    ? <><Loader2 className="h-3 w-3 animate-spin" /> Syncing...</>
                    : <><Globe className="h-3 w-3" /> Sync MITRE ATT&amp;CK</>}
                </Button>
              </div>
            </div>
          </CardHeader>

          <CardContent className="space-y-4">

            {/* Sync result message */}
            {syncMessage && (
              <Alert variant={syncMessage.ok ? "default" : "destructive"}>
                {syncMessage.ok
                  ? <CheckCircle className="h-4 w-4 text-emerald-400" />
                  : <XCircle className="h-4 w-4" />}
                <AlertDescription className="text-xs">{syncMessage.text}</AlertDescription>
              </Alert>
            )}

            {/* Intel policies list */}
            {loadingPolicies ? (
              <div className="flex justify-center py-8">
                <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
              </div>
            ) : intelPolicies.length === 0 ? (
              <div className="text-center py-10 text-muted-foreground">
                <Globe className="h-10 w-10 mx-auto mb-3 opacity-20" />
                <p className="text-sm">No threat intel policies yet.</p>
                <p className="text-xs mt-1">Click "Sync MITRE ATT&CK" to fetch the latest ML-relevant techniques.</p>
              </div>
            ) : (
              <div className="space-y-3">
                {intelPolicies.map(policy => {
                  const mitreMatch = policy.name.match(/\[INTEL\s+([^\]]+)\]/);
                  const mitreId    = mitreMatch ? mitreMatch[1] : "";
                  const techName   = policy.name.replace(/\[INTEL[^\]]*\]\s*/, "");

                  return (
                    <div
                      key={policy.id}
                      className={`p-4 rounded-lg border transition-colors ${
                        policy.enabled
                          ? "border-blue-500/40 bg-blue-500/5"
                          : "border-border bg-muted/10"
                      }`}
                    >
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap mb-1">
                            {mitreId && (
                              <Badge variant="outline" className="text-[10px] font-mono text-blue-400 border-blue-400/30 shrink-0">
                                {mitreId}
                              </Badge>
                            )}
                            <span className="text-sm font-semibold">{techName}</span>
                            {!policy.enabled && (
                              <Badge variant="outline" className="text-[10px] text-amber-400 border-amber-400/30 shrink-0">
                                Pending Review
                              </Badge>
                            )}
                          </div>
                          <div className="flex items-center gap-3 flex-wrap">
                            <code className="text-xs bg-muted px-2 py-0.5 rounded text-muted-foreground">
                              {policy.condition}
                            </code>
                            <ActionBadge action={policy.action} />
                            <span className="text-xs text-muted-foreground">Priority #{policy.priority}</span>
                          </div>
                          {policy.triggerCount > 0 && (
                            <p className="text-xs text-muted-foreground mt-1">
                              Triggered {policy.triggerCount}× · Last: {fmtDate(policy.lastTriggered)}
                            </p>
                          )}
                        </div>

                        {/* Toggle — analyst only */}
                        {/* Edit + Toggle — analyst only */}
                        <div className="flex items-center gap-3 shrink-0">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => openEdit(policy)}
                            className="text-xs h-7 px-2"
                          >
                            Edit
                          </Button>
                          <div className="flex items-center gap-2">
                            <span className="text-xs text-muted-foreground">
                              {policy.enabled ? "Enabled" : "Disabled"}
                            </span>
                            <Switch
                              checked={policy.enabled}
                              onCheckedChange={() => togglePolicy(policy)}
                            />
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })}

                <Alert className="border-blue-500/20 bg-blue-500/5">
                  <Info className="h-4 w-4 text-blue-400" />
                  <AlertDescription className="text-xs text-muted-foreground">
                    Intel policies default to <strong>priority 99, action: log, disabled</strong>.
                    Each policy creation is individually logged to SIEM.
                    Enable only techniques relevant to your deployment environment.
                  </AlertDescription>
                </Alert>
              </div>
            )}

          </CardContent>
        </Card>
      )}

      {/* Actions Log */}
      <Card>
        <CardHeader>
          <CardTitle>Autonomous Actions Log</CardTitle>
          <CardDescription>Real-time automated responses to detected threats</CardDescription>
        </CardHeader>
        <CardContent>
          {loadingActions ? (
            <div className="flex justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : (
            <div className="space-y-3">
              {actions.map(action => (
                <Alert key={action.id} className={action.result === "failed" ? "border-red-500" : ""}>
                  <div className="flex items-start gap-3">
                    <ResultIcon result={action.result} />
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <span className="font-semibold">{action.policyName}</span>
                        <ActionBadge action={action.action} />
                        <span className="text-xs text-muted-foreground ml-auto">{fmtDate(action.timestamp)}</span>
                      </div>
                      <AlertDescription className="text-sm space-y-1">
                        <div><span className="font-medium">Target:</span> {action.target}</div>
                        <div>
                          <span className="font-medium">Reason: </span>
                          <code className="text-xs bg-muted px-1 py-0.5 rounded">{action.reason}</code>
                        </div>
                        <div>{action.details}</div>
                        <div className="text-xs text-muted-foreground">
                          Execution time: {action.executionTime.toFixed(1)} ms
                        </div>
                      </AlertDescription>
                    </div>
                  </div>
                </Alert>
              ))}
              {actions.length === 0 && (
                <p className="text-center text-muted-foreground py-6">No actions logged yet.</p>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Isolated Threats */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Lock className="h-4 w-4 text-red-400" /> Isolated Threats
              </CardTitle>
              <CardDescription>
                Threats quarantined by ARE policies
                {canControl ? " — release manually to re-analyse" : ""}
              </CardDescription>
            </div>
            <Button variant="ghost" size="sm" onClick={fetchIsolations}>Refresh</Button>
          </div>
        </CardHeader>
        <CardContent>
          {loadingIsolations ? (
            <div className="flex justify-center py-6">
              <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
            </div>
          ) : isolations.length === 0 ? (
            <p className="text-center text-muted-foreground py-6">No isolated threats.</p>
          ) : (
            <div className="space-y-3">
              {[...isolations]
                .sort((a, b) =>
                  a.status === "active" && b.status !== "active" ? -1 :
                  b.status === "active" && a.status !== "active" ? 1 : 0
                )
                .map(iso => {
                  const isActive   = iso.status === "active";
                  const isExpired  = iso.status === "expired" || (iso.status === "active" && iso.remaining_s === 0);
                  const isReleased = iso.status === "released";
                  return (
                    <div
                      key={iso.threat_id}
                      style={{
                        border:       `1px solid ${isActive ? "rgba(239,68,68,0.4)" : "rgba(255,255,255,0.08)"}`,
                        borderRadius: "10px",
                        padding:      "14px 16px",
                        background:   isActive ? "rgba(239,68,68,0.06)" : "rgba(255,255,255,0.02)",
                        display:      "flex",
                        alignItems:   "center",
                        gap:          "14px",
                      }}
                    >
                      <div style={{ flexShrink: 0 }}>
                        {isActive && !isExpired && <Lock     className="h-5 w-5 text-red-400" />}
                        {isExpired               && <LockOpen className="h-5 w-5 text-muted-foreground" />}
                        {isReleased              && <LockOpen className="h-5 w-5 text-green-500" />}
                      </div>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-semibold text-sm truncate">{iso.threat_id}</span>
                          <span className="text-xs text-muted-foreground truncate">— {iso.filename}</span>
                          <Badge
                            variant={isActive && !isExpired ? "destructive" : "secondary"}
                            className="text-xs capitalize ml-auto"
                          >
                            {isActive && !isExpired
                              ? `Active${iso.remaining_s > 0 ? ` · ${iso.remaining_s}s left` : ""}`
                              : iso.status}
                          </Badge>
                        </div>
                        <div className="text-xs text-muted-foreground mt-1 space-y-0.5">
                          <div>Policy: <span className="text-foreground/70">{iso.policy_name}</span></div>
                          <div>Isolated: {fmtDate(iso.isolated_at)} · Duration: {iso.duration_s}s</div>
                        </div>
                      </div>
                      {canControl && isActive && !isExpired && !isReleased && (
                        <Button
                          size="sm"
                          variant="outline"
                          className="shrink-0 text-xs border-red-500/40 hover:border-red-400 hover:text-red-400"
                          onClick={() => releaseIsolation(iso.threat_id)}
                        >
                          <LockOpen className="h-3 w-3 mr-1" /> Release
                        </Button>
                      )}
                    </div>
                  );
                })}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Add/Edit Policy Modal — analyst only */}
      {canControl && modalOpen && (
        <>
          <div
            className="fixed inset-0 z-50"
            style={{ backgroundColor: "rgba(0,0,0,0.6)", backdropFilter: "blur(4px)" }}
            onClick={() => setModalOpen(false)}
          />
          <div
            className="fixed z-50"
            style={{ left: "50%", top: "50%", transform: "translate(-50%, -50%)", width: "100%", maxWidth: "520px", padding: "0 16px" }}
          >
            <div style={{ backgroundColor: isDark ? "rgba(0,0,0,0.85)" : "#ffffff", border: isDark ? "1px solid rgba(255,255,255,0.10)" : "1px solid #e2e8f0", borderRadius: "20px", padding: "36px 32px", color: isDark ? "white" : "#0f172a", boxShadow: isDark ? "0 30px 80px rgba(0,0,0,0.9)" : "0 20px 60px rgba(0,0,0,0.15)" }}>
              <div style={{ marginBottom: "24px" }}>
                <h2 style={{ fontSize: "1.2rem", fontWeight: 700, color: isDark ? "#fff" : "#0f172a", marginBottom: "6px" }}>
                  {editingPolicy ? "Edit Policy" : "Add Policy"}
                </h2>
                <p style={{ fontSize: "0.8rem", color: isDark ? "rgba(255,255,255,0.45)" : "#64748b" }}>
                  {editingPolicy ? "Modify the policy configuration below." : "Configure a new automated response policy."}
                </p>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
                {[
                  { label: "Policy Name",             key: "name",      placeholder: "e.g. Critical Threat Isolation",                                          type: "text"   },
                  { label: "Priority (1 = highest)",  key: "priority",  placeholder: "e.g. 1",                                                                  type: "number" },
                  { label: "Condition",               key: "condition", placeholder: 'threat.severity == "critical" AND threat.confidence >= 0.9',               type: "text"   },
                ].map(({ label, key, placeholder, type }) => (
                  <div key={key}>
                    <label style={{ display: "block", fontSize: "0.78rem", fontWeight: 500, color: isDark ? "rgba(255,255,255,0.7)" : "#374151", marginBottom: "6px" }}>
                      {label}
                    </label>
                    <input
                      type={type}
                      placeholder={placeholder}
                      value={form[key as keyof PolicyFormState] as string}
                      onChange={e => { setForm(f => ({ ...f, [key]: e.target.value })); if (key === "condition") setConditionError(""); }}
                      onBlur={key === "condition" ? e => validateCondition(e.target.value) : undefined}
                      style={{ width: "100%", padding: "9px 13px", borderRadius: "10px", background: isDark ? "rgba(255,255,255,0.06)" : "#f8fafc", border: (key === "condition" && conditionError) ? "1px solid rgba(239,68,68,0.75)" : isDark ? "1px solid rgba(255,255,255,0.13)" : "1px solid #cbd5e1", color: isDark ? "#fff" : "#0f172a", fontSize: "0.875rem", outline: "none", boxSizing: "border-box" }}
                    />
                    {key === "condition" && conditionError && (
                      <p style={{ marginTop: "4px", fontSize: "0.72rem", color: "rgba(239,68,68,0.9)" }}>{conditionError}</p>
                    )}
                    {key === "condition" && (
                      <p style={{ marginTop: "5px", fontSize: "0.69rem", color: isDark ? "rgba(255,255,255,0.3)" : "#94a3b8", lineHeight: 1.6 }}>
                        Fields: threat.severity · threat.confidence · threat.status · agent.deviation · agent.confidence · model.accuracy&nbsp;&nbsp;Ops: == != &gt;= &lt;= &gt; &lt;&nbsp;&nbsp;Chain: AND / OR
                      </p>
                    )}
                  </div>
                ))}
                <div>
                  <label style={{ display: "block", fontSize: "0.78rem", fontWeight: 500, color: isDark ? "rgba(255,255,255,0.7)" : "#374151", marginBottom: "6px" }}>
                    Action
                  </label>
                  <select
                    value={form.action}
                    onChange={e => setForm(f => ({ ...f, action: e.target.value as ActionType }))}
                    style={{ width: "100%", padding: "9px 13px", borderRadius: "10px", background: isDark ? "rgba(10,10,10,0.95)" : "#f8fafc", border: isDark ? "1px solid rgba(255,255,255,0.13)" : "1px solid #cbd5e1", color: isDark ? "#fff" : "#0f172a", fontSize: "0.875rem", outline: "none", cursor: "pointer", boxSizing: "border-box" }}
                  >
                    {(["isolate","switch_model","escalate","retrain","block","log","monitor"] as ActionType[]).map(a => (
                      <option key={a} value={a}>{ACTION_CONFIG[a].label}</option>
                    ))}
                  </select>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                  <Switch
                    id="pol-enabled"
                    checked={form.enabled}
                    onCheckedChange={v => setForm(f => ({ ...f, enabled: v }))}
                  />
                  <label htmlFor="pol-enabled" style={{ fontSize: "0.8rem", color: isDark ? "rgba(255,255,255,0.55)" : "#475569", cursor: "pointer" }}>
                    {form.enabled ? "Enabled — goes live immediately on save" : "Disabled"}
                  </label>
                </div>
              </div>
              <div style={{ display: "flex", justifyContent: "flex-end", gap: "10px", marginTop: "28px" }}>
                <button
                  onClick={() => setModalOpen(false)}
                  style={{ padding: "9px 22px", borderRadius: "10px", fontSize: "0.85rem", cursor: "pointer", background: isDark ? "rgba(255,255,255,0.07)" : "#f1f5f9", border: isDark ? "1px solid rgba(255,255,255,0.15)" : "1px solid #cbd5e1", color: isDark ? "rgba(255,255,255,0.7)" : "#475569" }}
                >
                  Cancel
                </button>
                <button
                  onClick={savePolicy}
                  disabled={savingPolicy || !form.name.trim() || !form.priority || !form.condition.trim() || !!conditionError}
                  style={{ padding: "9px 22px", borderRadius: "10px", fontSize: "0.85rem", fontWeight: 600, cursor: (savingPolicy || !form.name.trim() || !form.priority || !form.condition.trim() || !!conditionError) ? "not-allowed" : "pointer", background: (savingPolicy || !form.name.trim() || !form.priority || !form.condition.trim() || !!conditionError) ? (isDark ? "rgba(255,255,255,0.1)" : "#e2e8f0") : (isDark ? "rgba(255,255,255,0.95)" : "#0f172a"), border: "none", color: (savingPolicy || !form.name.trim() || !form.priority || !form.condition.trim() || !!conditionError) ? (isDark ? "rgba(255,255,255,0.25)" : "#94a3b8") : (isDark ? "#000" : "#fff"), display: "flex", alignItems: "center", gap: "6px" }}
                >
                  {savingPolicy && <Loader2 className="h-4 w-4 animate-spin" />}
                  {editingPolicy ? "Save Changes" : "Create Policy"}
                </button>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}