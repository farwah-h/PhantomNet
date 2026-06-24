"use client";

import { useEffect, useState, useCallback } from "react";
import {
  Card, CardContent, CardDescription, CardHeader, CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Shield, CheckCircle, XCircle, AlertTriangle,
  Key, FileText, Zap, Lock, Activity,
  ShieldCheck, ShieldAlert, RotateCw, Eye, Loader2,
} from "lucide-react";

const API_BASE = "http://localhost:8006/api/src";
const POLL_MS  = 8_000;

interface CertStatus {
  module:      string;
  status:      "valid" | "expiring_soon" | "expired" | "not_issued";
  issued_at?:  string;
  expires_at?: string;
  days_left?:  number;
  cert_path?:  string;
}

interface RateStatus {
  module:    string;
  count:     number;
  limit:     number;
  remaining: number;
  throttled: boolean;
}

interface AuditLog {
  id:           string;
  timestamp:    string;
  source:       string;
  destination:  string;
  event_type:   string;
  message:      string;
  payload_hash: string;
}

interface SRCStatus {
  status:       string;
  timestamp:    string;
  certificates: CertStatus[];
  rate_limits:  RateStatus[];
  recent_logs:  AuditLog[];
  encryption:   { algorithm: string; key_bits: number; mode: string };
  signing:      { algorithm: string; key_source: string };
}

function timeAgo(iso: string): string {
  const normalized = iso.replace(/^(\d{4}-\d{2}-\d{2}) /, '$1T');
  const diff = Math.floor((Date.now() - new Date(normalized).getTime()) / 1000);
  if (diff < 60)    return `${diff}s ago`;
  if (diff < 3600)  return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function certColor(status: CertStatus["status"]) {
  if (status === "valid")         return "text-emerald-400";
  if (status === "expiring_soon") return "text-amber-400";
  if (status === "expired")       return "text-red-400";
  return "text-muted-foreground";
}

function certBadgeVariant(status: CertStatus["status"]): "default" | "secondary" | "destructive" | "outline" {
  if (status === "valid")         return "default";
  if (status === "expiring_soon") return "secondary";
  if (status === "expired")       return "destructive";
  return "outline";
}

function rateColor(pct: number) {
  if (pct < 60) return "bg-emerald-500";
  if (pct < 85) return "bg-amber-500";
  return "bg-red-500";
}

export default function SRCCoordination() {
  const [status,       setStatus]       = useState<SRCStatus | null>(null);
  const [loading,      setLoading]      = useState(true);
  const [error,        setError]        = useState<string | null>(null);
  const [rotating,     setRotating]     = useState<string | null>(null);
  const [rotatingAll,  setRotatingAll]  = useState(false);
  const [verifyResult, setVerifyResult] = useState<Record<string, boolean | null>>(() => {
    try {
      const stored = localStorage.getItem("src_verify_results");
      return stored ? JSON.parse(stored) : {};
    } catch { return {}; }
  });

  const fetchStatus = useCallback(async () => {
    try {
      const res  = await fetch(`${API_BASE}/status`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: SRCStatus = await res.json();
      setStatus(data);
      setVerifyResult(prev => {
        const next        = { ...prev };
        const existingIds = new Set(data.recent_logs.map(l => l.id));
        Object.keys(next).forEach(id => { if (!existingIds.has(id)) delete next[id]; });
        try { localStorage.setItem("src_verify_results", JSON.stringify(next)); } catch {}
        return next;
      });
      setError(null);
    } catch {
      setError("Cannot reach SRC backend. Make sure src_backend.py is running on port 8006.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
    const id = setInterval(fetchStatus, POLL_MS);
    return () => clearInterval(id);
  }, [fetchStatus]);

  const rotateCert = async (module: string) => {
    setRotating(module);
    try {
      const res = await fetch(`${API_BASE}/rotate-cert`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ module }),
      });
      if (!res.ok) throw new Error();
      await fetchStatus();
    } catch {
      setError(`Failed to rotate certificate for ${module}.`);
    } finally {
      setRotating(null);
    }
  };

  const rotateAll = async () => {
    setRotatingAll(true);
    try {
      const res = await fetch(`${API_BASE}/rotate-all`, { method: "POST" });
      if (!res.ok) throw new Error();
      await fetchStatus();
    } catch {
      setError("Failed to rotate all certificates.");
    } finally {
      setRotatingAll(false);
    }
  };

  const verifyLog = async (logId: string) => {
    try {
      const res  = await fetch(`${API_BASE}/verify/${logId}`);
      const data = await res.json();
      setVerifyResult(prev => {
        const next = { ...prev, [logId]: data.verified };
        try { localStorage.setItem("src_verify_results", JSON.stringify(next)); } catch {}
        return next;
      });
    } catch {
      setVerifyResult(prev => {
        const next = { ...prev, [logId]: false };
        try { localStorage.setItem("src_verify_results", JSON.stringify(next)); } catch {}
        return next;
      });
    }
  };

  if (loading) return (
    <div className="flex items-center justify-center h-64 gap-3 text-muted-foreground">
      <Loader2 className="h-6 w-6 animate-spin" />
      <span>Connecting to SRC module...</span>
    </div>
  );

  if (error) return (
    <div className="space-y-6">
      <SRCHeader />
      <Alert variant="destructive">
        <ShieldAlert className="h-4 w-4" />
        <AlertDescription>{error}</AlertDescription>
      </Alert>
      <div className="text-sm text-muted-foreground bg-muted rounded-lg p-4 font-mono">
        <p className="font-semibold mb-2 text-foreground">To start the SRC backend:</p>
        <p>pip install fastapi uvicorn cryptography</p>
        <p>python src_backend.py</p>
        <p className="mt-2 text-xs">→ Server will start on http://localhost:8006</p>
      </div>
    </div>
  );

  if (!status) return null;

  const validCerts    = status.certificates.filter(c => c.status === "valid").length;
  const expiringCerts = status.certificates.filter(c => c.status === "expiring_soon").length;
  const expiredCerts  = status.certificates.filter(c => c.status === "expired").length;
  const throttledMods = status.rate_limits.filter(r => r.throttled).length;

  return (
    <div className="space-y-6">

      <SRCHeader />

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <SummaryCard
          icon={<ShieldCheck className="h-5 w-5 text-emerald-400" />}
          label="Valid Certs"
          value={`${validCerts} / ${status.certificates.length}`}
          sub="modules secured"
          color="text-emerald-400"
        />
        <SummaryCard
          icon={<Lock className="h-5 w-5 text-blue-400" />}
          label="Encryption"
          value="AES-256"
          sub="GCM mode active"
          color="text-blue-400"
        />
        <SummaryCard
          icon={<FileText className="h-5 w-5 text-purple-400" />}
          label="Audit Logs"
          value={String(status.recent_logs.length)}
          sub="recent entries"
          color="text-purple-400"
        />
        <SummaryCard
          icon={<Activity className="h-5 w-5 text-amber-400" />}
          label="Throttled"
          value={String(throttledMods)}
          sub="modules rate-limited"
          color={throttledMods > 0 ? "text-red-400" : "text-emerald-400"}
        />
      </div>

      {/* Encryption & Signing info */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <div className="flex items-center gap-2">
              <Lock className="h-4 w-4 text-blue-400" />
              <CardTitle className="text-sm">Encryption Layer</CardTitle>
            </div>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <InfoRow label="Algorithm"       value={status.encryption.algorithm} />
            <InfoRow label="Key Size"        value={`${status.encryption.key_bits} bits`} />
            <InfoRow label="Mode"            value={status.encryption.mode} />
            <InfoRow label="Nonce"           value="12-byte random per message" />
            <InfoRow label="Forward Secrecy" value="Yes — ephemeral nonce per session" />
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <div className="flex items-center gap-2">
              <Key className="h-4 w-4 text-purple-400" />
              <CardTitle className="text-sm">Audit Log Signing</CardTitle>
            </div>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <InfoRow label="Algorithm"        value={status.signing.algorithm} />
            <InfoRow label="Key Source"       value={status.signing.key_source} />
            <InfoRow label="Hash Input"       value="ID + timestamp + source + dest + payload hash" />
            <InfoRow label="Tamper Detection" value="Yes — signature mismatch detected" />
            <InfoRow label="Log Format"       value="SQLite with SHA3-256 signatures" />
          </CardContent>
        </Card>
      </div>

      {/* Certificate Status */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-emerald-400" />
              <div>
                <CardTitle>Module Certificates (mTLS)</CardTitle>
                <CardDescription>Self-signed X.509 certificates — auto-rotate every 30 days</CardDescription>
              </div>
            </div>
            <Button size="sm" variant="outline" onClick={rotateAll} disabled={rotatingAll} className="gap-1">
              {rotatingAll ? <Loader2 className="h-3 w-3 animate-spin" /> : <RotateCw className="h-3 w-3" />}
              Rotate All
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {expiringCerts > 0 && (
            <Alert className="mb-4">
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription>{expiringCerts} certificate(s) expiring soon. Consider rotating.</AlertDescription>
            </Alert>
          )}
          {expiredCerts > 0 && (
            <Alert variant="destructive" className="mb-4">
              <XCircle className="h-4 w-4" />
              <AlertDescription>{expiredCerts} certificate(s) have expired. Rotate immediately.</AlertDescription>
            </Alert>
          )}
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Module</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Issued</TableHead>
                <TableHead>Expires</TableHead>
                <TableHead>Days Left</TableHead>
                <TableHead>Action</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {status.certificates.map(cert => (
                <TableRow key={cert.module}>
                  <TableCell className="font-mono font-semibold">{cert.module}</TableCell>
                  <TableCell>
                    <Badge variant={certBadgeVariant(cert.status)} className="capitalize">
                      {cert.status.replace("_", " ")}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {cert.issued_at ? timeAgo(cert.issued_at) : "—"}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {cert.expires_at ? new Date(cert.expires_at.replace(/^(\d{4}-\d{2}-\d{2}) /, '$1T')).toLocaleDateString('en-GB', { timeZone: 'Asia/Karachi' }) : "—"}
                  </TableCell>
                  <TableCell>
                    {cert.days_left !== undefined
                      ? <span className={certColor(cert.status)}>{cert.days_left}d</span>
                      : "—"}
                  </TableCell>
                  <TableCell>
                    <Button
                      size="sm" variant="ghost"
                      onClick={() => rotateCert(cert.module)}
                      disabled={rotating === cert.module}
                      className="h-7 px-2 text-xs gap-1"
                    >
                      {rotating === cert.module
                        ? <Loader2 className="h-3 w-3 animate-spin" />
                        : <RotateCw className="h-3 w-3" />}
                      Rotate
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Rate Limiting */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Zap className="h-5 w-5 text-amber-400" />
            <div>
              <CardTitle>Rate Limiting (DoS Protection)</CardTitle>
              <CardDescription>Max {status.rate_limits[0]?.limit ?? 60} requests per module per minute</CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {status.rate_limits.map(r => {
            const pct = Math.min(100, Math.round((r.count / r.limit) * 100));
            return (
              <div key={r.module}>
                <div className="flex items-center justify-between mb-1 text-sm">
                  <span className="font-mono font-medium">{r.module}</span>
                  <div className="flex items-center gap-2">
                    <span className="text-muted-foreground text-xs">{r.count} / {r.limit} req/min</span>
                    {r.throttled
                      ? <Badge variant="destructive" className="text-xs">THROTTLED</Badge>
                      : <Badge variant="outline" className="text-xs text-emerald-400 border-emerald-400/30">OK</Badge>}
                  </div>
                </div>
                <div className="h-2 rounded-full bg-muted overflow-hidden">
                  <div className={`h-full rounded-full transition-all ${rateColor(pct)}`} style={{ width: `${pct}%` }} />
                </div>
              </div>
            );
          })}
        </CardContent>
      </Card>

      {/* Signed Audit Log */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <FileText className="h-5 w-5 text-purple-400" />
            <div>
              <CardTitle>Signed Audit Log</CardTitle>
              <CardDescription>All inter-module events — HMAC-SHA3-256 signed, tamper-detectable</CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Log ID</TableHead>
                <TableHead>Time</TableHead>
                <TableHead>Source → Dest</TableHead>
                <TableHead>Event</TableHead>
                <TableHead>Message</TableHead>
                <TableHead>Integrity</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {status.recent_logs.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center text-muted-foreground py-8">
                    No audit entries yet. Run a threat detection to see real inter-module events.
                  </TableCell>
                </TableRow>
              ) : (
                status.recent_logs.map(log => (
                  <TableRow key={log.id}>
                    <TableCell className="font-mono text-xs">{log.id}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{timeAgo(log.timestamp)}</TableCell>
                    <TableCell className="font-mono text-xs">
                      <span className="text-blue-400">{log.source}</span>
                      <span className="text-muted-foreground"> → </span>
                      <span className="text-emerald-400">{log.destination}</span>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-xs">{log.event_type}</Badge>
                    </TableCell>
                    <TableCell className="text-xs" style={{whiteSpace: "normal", wordBreak: "break-word", maxWidth: "300px"}}>
                      {log.message}
                    </TableCell>
                    <TableCell>
                      {verifyResult[log.id] === undefined ? (
                        <Button size="sm" variant="ghost" onClick={() => verifyLog(log.id)} className="h-7 px-2 text-xs gap-1">
                          <Eye className="h-3 w-3" /> Verify
                        </Button>
                      ) : verifyResult[log.id] ? (
                        <span className="flex items-center gap-1 text-emerald-400 text-xs">
                          <CheckCircle className="h-3 w-3" /> Intact
                        </span>
                      ) : (
                        <span className="flex items-center gap-1 text-red-400 text-xs">
                          <XCircle className="h-3 w-3" /> Tampered!
                        </span>
                      )}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

    </div>
  );
}

function SRCHeader() {
  return (
    <div className="flex items-center justify-between">
      <div>
        <h1 className="text-3xl font-bold text-foreground flex items-center gap-3">
          <ShieldCheck className="h-8 w-8 text-emerald-400" />
          Secure Response & Coordination
        </h1>
        <p className="text-muted-foreground mt-1">
          Inter-module communication security — mTLS · AES-256-GCM · Signed Audit Logs · Rate Limiting
        </p>
      </div>
      <Badge variant="outline" className="text-emerald-400 border-emerald-400/30 bg-emerald-400/5 text-xs px-3 py-1">
        SRC · Port 8006
      </Badge>
    </div>
  );
}

function SummaryCard({ icon, label, value, sub, color }: {
  icon: React.ReactNode; label: string; value: string; sub: string; color: string;
}) {
  return (
    <Card>
      <CardContent className="pt-5">
        <div className="flex items-start justify-between">
          <div>
            <p className="text-xs text-muted-foreground">{label}</p>
            <p className={`text-2xl font-bold mt-1 ${color}`}>{value}</p>
            <p className="text-xs text-muted-foreground mt-0.5">{sub}</p>
          </div>
          <div className="mt-1">{icon}</div>
        </div>
      </CardContent>
    </Card>
  );
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between">
      <span className="text-muted-foreground">{label}</span>
      <span className="font-mono text-xs text-right max-w-[55%]">{value}</span>
    </div>
  );
}