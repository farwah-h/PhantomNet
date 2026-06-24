"use client";

/**
 * PhantomNet++ — User Profile Page (profile.tsx)
 * Accessible to all roles. Shows session info, role, and page permissions.
 */

import { useNavigate } from "react-router-dom";
import {
  Shield, ShieldCheck, User, UserCheck, Mail, Key,
  LogOut, ArrowLeft, CheckCircle, XCircle,
} from "lucide-react";
import { getSession, clearSession } from "@/App";
import { ROLE_PERMISSIONS } from "@/pages/login";

// ── Role display config ───────────────────────────────────────────────────────
const ROLE_CONFIG = {
  admin: {
    label:       "Administrator",
    description: "Full platform access. Manages users, settings, and system configuration.",
    Icon:        ShieldCheck,
    accent:      "#f59e0b",
    bg:          "rgba(245,158,11,0.08)",
    border:      "rgba(245,158,11,0.2)",
  },
  security_analyst: {
    label:       "Security Analyst",
    description: "Handles escalated threats. Reviews critical incidents and takes response actions.",
    Icon:        UserCheck,
    accent:      "#10b981",
    bg:          "rgba(16,185,129,0.08)",
    border:      "rgba(16,185,129,0.2)",
  },
  user: {
    label:       "Standard User",
    description: "Uploads images for analysis and monitors detection results and active policies.",
    Icon:        User,
    accent:      "#64748b",
    bg:          "rgba(100,116,139,0.08)",
    border:      "rgba(100,116,139,0.18)",
  },
};

const PAGE_LABELS: Record<string, string> = {
  dashboard:              "Dashboard",
  threatDetection:        "Threat Detection",
  attackSimulation:       "Attack Simulation",
  xaiEngine:              "XAI Engine",
  responseEngine:         "ARE — View",
  responseEngineControl:  "ARE — Control",
  analystReview:          "Analyst Review",
  analystReviewAction:    "Review Actions",
  siemLogs:               "SIEM Logs",
  settings:               "Settings",
};

// ── Component ─────────────────────────────────────────────────────────────────
export default function ProfilePage() {
  const navigate = useNavigate();
  const session  = getSession();

  if (!session) {
    navigate("/login", { replace: true });
    return null;
  }

  const role     = session.role;
  const roleConf = ROLE_CONFIG[role] ?? ROLE_CONFIG.user;
  const perms    = ROLE_PERMISSIONS[role].pages;

  const initials = session.displayName
    .split(" ")
    .map(w => w[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();

  const handleLogout = () => {
    clearSession();
    navigate("/login", { replace: true });
  };

  return (
    <div className="max-w-2xl mx-auto space-y-6 py-2">

      {/* Back */}
      <button
        onClick={() => navigate(-1)}
        className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors cursor-pointer"
      >
        <ArrowLeft className="h-4 w-4" /> Back
      </button>

      {/* Avatar + name card */}
      <div className="rounded-xl border border-border bg-card p-6 flex items-center gap-6">
        <div style={{
          width: 72, height: 72, borderRadius: "50%", flexShrink: 0,
          background: roleConf.bg, border: `2px solid ${roleConf.border}`,
          display: "flex", alignItems: "center", justifyContent: "center",
        }}>
          <span style={{ fontSize: "1.5rem", fontWeight: 700, color: roleConf.accent }}>{initials}</span>
        </div>

        <div className="flex-1 min-w-0">
          <h1 className="text-xl font-bold text-foreground truncate">{session.displayName}</h1>
          <div className="flex items-center gap-1.5 mt-1 text-sm text-muted-foreground">
            <Mail className="h-3.5 w-3.5 flex-shrink-0" />
            <span className="truncate">{session.email}</span>
          </div>
          <div style={{
            display: "inline-flex", alignItems: "center", gap: "5px",
            marginTop: "10px", padding: "4px 12px", borderRadius: "99px",
            background: roleConf.bg, border: `1px solid ${roleConf.border}`,
            fontSize: "0.72rem", fontWeight: 600, color: roleConf.accent,
          }}>
            <roleConf.Icon style={{ width: 11, height: 11 }} />
            {roleConf.label}
          </div>
        </div>

        <button
          onClick={handleLogout}
          style={{
            display: "flex", alignItems: "center", gap: "6px",
            padding: "8px 14px", borderRadius: "8px", cursor: "pointer",
            background: "rgba(239,68,68,0.07)", border: "1px solid rgba(239,68,68,0.2)",
            color: "#f87171", fontSize: "0.8rem", fontWeight: 600,
            flexShrink: 0, transition: "background 0.15s",
          }}
          onMouseEnter={e => e.currentTarget.style.background = "rgba(239,68,68,0.14)"}
          onMouseLeave={e => e.currentTarget.style.background = "rgba(239,68,68,0.07)"}
        >
          <LogOut style={{ width: 14, height: 14 }} />
          Log out
        </button>
      </div>

      {/* Role description */}
      <div className="rounded-xl border border-border bg-card p-5">
        <div className="flex items-center gap-2 mb-3">
          <Key className="h-4 w-4 text-muted-foreground" />
          <h2 className="text-sm font-semibold text-foreground">Role & Access Level</h2>
        </div>
        <p className="text-sm text-muted-foreground leading-relaxed">{roleConf.description}</p>
      </div>

      {/* Permissions grid */}
      <div className="rounded-xl border border-border bg-card p-5">
        <div className="flex items-center gap-2 mb-4">
          <Shield className="h-4 w-4 text-muted-foreground" />
          <h2 className="text-sm font-semibold text-foreground">Page Permissions</h2>
        </div>
        <div className="grid grid-cols-2 gap-2">
          {Object.entries(PAGE_LABELS).map(([key, label]) => {
            const allowed = perms[key as keyof typeof perms];
            return (
              <div
                key={key}
                className="flex items-center gap-2.5 px-3 py-2 rounded-lg"
                style={{
                  background: allowed ? "rgba(16,185,129,0.05)" : "rgba(0,0,0,0.02)",
                  border: `1px solid ${allowed ? "rgba(16,185,129,0.15)" : "rgba(0,0,0,0.06)"}`,
                }}
              >
                {allowed
                  ? <CheckCircle className="h-3.5 w-3.5 text-emerald-400 flex-shrink-0" />
                  : <XCircle    className="h-3.5 w-3.5 text-muted-foreground/30 flex-shrink-0" />
                }
                <span className={`text-xs font-medium ${allowed ? "text-foreground" : "text-muted-foreground/40"}`}>
                  {label}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Session info */}
      <div className="rounded-xl border border-border bg-card p-5">
        <div className="flex items-center gap-2 mb-3">
          <Key className="h-4 w-4 text-muted-foreground" />
          <h2 className="text-sm font-semibold text-foreground">Session Info</h2>
        </div>
        <div className="space-y-2 text-sm">
          <div className="flex justify-between">
            <span className="text-muted-foreground">Session type</span>
            <span className="text-foreground font-medium">Browser session</span>
          </div>
          <div className="flex justify-between">
            <span className="text-muted-foreground">Persists until</span>
            <span className="text-foreground font-medium">Browser tab closes</span>
          </div>
          <div className="flex justify-between">
            <span className="text-muted-foreground">Account</span>
            <span className="text-foreground font-medium font-mono text-xs">{session.email}</span>
          </div>
        </div>
      </div>

    </div>
  );
}