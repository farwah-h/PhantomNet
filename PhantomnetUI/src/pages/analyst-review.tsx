"use client";

/**
 * PhantomNet++ — Security Analyst Review Panel (analyst-review.tsx)
 *
 * Permissions:
 *   security_analyst → full access: view + take actions (confirm/harmless)
 *   admin            → view only: sees all escalated items, no action buttons
 *   user             → page hidden entirely (blocked at router level)
 */

import { useState, useEffect, useCallback } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import {
  AlertTriangle, CheckCircle, Clock, Lock, Unlock,
  RefreshCw, UserCheck, ShieldAlert, Shield, Eye,
} from 'lucide-react';
import { useSession, ViewOnlyBanner } from '@/hooks/useSession';

const ARE_BASE = 'http://localhost:8000/api/are';

// ── Theme hook ────────────────────────────────────────────────────────────────
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

// ── Theme tokens ──────────────────────────────────────────────────────────────
function tokens(light: boolean) {
  return {
    pageBg:        light ? '#f8fafc'                          : 'hsl(222.2 84% 4.9%)',
    cardBg:        light ? '#ffffff'                          : 'hsl(222.2 84% 4.9%)',
    cardBorder:    light ? '#e2e8f0'                          : 'hsl(217.2 32.6% 17.5%)',
    cardBorderRed: light ? 'rgba(239,68,68,0.25)'             : 'rgba(239,68,68,0.2)',
    iconBg:        light ? 'rgba(16,185,129,0.08)'            : 'rgba(16,185,129,0.1)',
    iconBorder:    light ? 'rgba(16,185,129,0.25)'            : 'rgba(16,185,129,0.3)',
    title:         light ? '#0f172a'                          : '#f1f5f9',
    subtitle:      light ? '#64748b'                          : 'hsl(215 20.2% 65.1%)',
    statCardBg:    light ? '#ffffff'                          : 'hsl(222.2 84% 4.9%)',
    statCardBorder:light ? '#e2e8f0'                          : 'hsl(217.2 32.6% 17.5%)',
    statLabel:     light ? '#64748b'                          : 'hsl(215 20.2% 65.1%)',
    metaBg:        light ? 'rgba(0,0,0,0.02)'                : 'rgba(255,255,255,0.02)',
    metaBorder:    light ? 'rgba(0,0,0,0.06)'                : 'rgba(255,255,255,0.05)',
    metaLabel:     light ? 'rgba(30,41,59,0.4)'              : 'rgba(148,163,184,0.4)',
    metaValue:     light ? '#1e293b'                          : '#f1f5f9',
    detailBg:      light ? 'rgba(239,68,68,0.04)'            : 'rgba(239,68,68,0.05)',
    detailBorder:  light ? 'rgba(239,68,68,0.15)'            : 'rgba(239,68,68,0.12)',
    detailText:    light ? 'rgba(185,28,28,0.85)'            : 'rgba(248,113,113,0.75)',
    noteBg:        light ? 'rgba(16,185,129,0.04)'           : 'rgba(16,185,129,0.05)',
    noteBorder:    light ? 'rgba(16,185,129,0.2)'            : 'rgba(16,185,129,0.15)',
    noteText:      light ? '#065f46'                          : 'rgba(52,211,153,0.8)',
    harmlessBg:    light ? 'rgba(16,185,129,0.07)'           : 'rgba(16,185,129,0.08)',
    harmlessBgHov: light ? 'rgba(16,185,129,0.14)'           : 'rgba(16,185,129,0.14)',
    harmlessBorder:light ? 'rgba(16,185,129,0.35)'           : 'rgba(16,185,129,0.3)',
    harmlessColor: light ? '#059669'                          : '#34d399',
    confirmBg:     light ? 'rgba(239,68,68,0.07)'            : 'rgba(239,68,68,0.08)',
    confirmBgHov:  light ? 'rgba(239,68,68,0.14)'            : 'rgba(239,68,68,0.14)',
    confirmBorder: light ? 'rgba(239,68,68,0.35)'            : 'rgba(239,68,68,0.3)',
    confirmColor:  light ? '#dc2626'                          : '#f87171',
    errBg:         light ? 'rgba(239,68,68,0.06)'            : 'rgba(239,68,68,0.08)',
    errBorder:     light ? 'rgba(239,68,68,0.2)'             : 'rgba(239,68,68,0.25)',
    modalBg:       light ? '#ffffff'                          : '#0f172a',
    modalBorder:   light ? 'rgba(16,185,129,0.2)'            : 'rgba(16,185,129,0.2)',
    modalTitle:    light ? '#0f172a'                          : '#f1f5f9',
    modalSub:      light ? 'rgba(30,41,59,0.5)'              : 'rgba(148,163,184,0.5)',
    modalLabel:    light ? 'rgba(16,185,129,0.8)'            : 'rgba(16,185,129,0.7)',
    textareaBg:    light ? '#f8fafc'                          : 'rgba(255,255,255,0.04)',
    textareaBorder:light ? 'rgba(16,185,129,0.2)'            : 'rgba(16,185,129,0.15)',
    textareaFocus: light ? 'rgba(16,185,129,0.5)'            : 'rgba(16,185,129,0.4)',
    textareaColor: light ? '#0f172a'                          : '#e2e8f0',
    cancelBg:      light ? '#f1f5f9'                          : 'rgba(255,255,255,0.04)',
    cancelBorder:  light ? '#cbd5e1'                          : 'rgba(255,255,255,0.08)',
    cancelColor:   light ? '#475569'                          : 'rgba(148,163,184,0.7)',
    emptyIcon:     light ? 'rgba(30,41,59,0.15)'             : 'rgba(100,116,139,0.3)',
    emptyText:     light ? '#94a3b8'                          : 'hsl(215 20.2% 65.1%)',
    spinnerTrack:  light ? 'rgba(16,185,129,0.15)'           : 'rgba(16,185,129,0.2)',
  };
}

// ── Types ─────────────────────────────────────────────────────────────────────
type ReviewStatus = 'pending' | 'confirmed' | 'harmless';

interface EscalatedItem {
  actionId:     string;
  filename:     string;
  policyName:   string;
  details:      string;
  timestamp:    string;
  reviewStatus: ReviewStatus;
  analystNote?: string;
}

function loadDecisions(): Record<string, { status: ReviewStatus; note: string }> {
  try { return JSON.parse(localStorage.getItem('phantomnet_analyst_decisions') || '{}'); }
  catch { return {}; }
}
function saveDecisions(d: Record<string, { status: ReviewStatus; note: string }>) {
  localStorage.setItem('phantomnet_analyst_decisions', JSON.stringify(d));
}

function statusStyle(s: ReviewStatus, light: boolean) {
  const map = {
    pending:   { label: 'Pending Review',    bg: 'rgba(245,158,11,0.1)',  border: 'rgba(245,158,11,0.25)',  color: light ? '#b45309' : '#fbbf24' },
    confirmed: { label: 'Threat Confirmed',  bg: 'rgba(239,68,68,0.1)',   border: 'rgba(239,68,68,0.25)',   color: light ? '#dc2626' : '#f87171' },
    harmless:  { label: 'Cleared — Harmless',bg: 'rgba(16,185,129,0.1)', border: 'rgba(16,185,129,0.25)', color: light ? '#059669' : '#34d399' },
  };
  return map[s];
}

// ── Component ─────────────────────────────────────────────────────────────────
export default function AnalystReview() {
  const isLight = useTheme();
  const t = tokens(isLight);
  const { can, session } = useSession();

  // Permission: only security_analyst can take action
  const canAct = can('analystReviewAction');

  const [items,     setItems]          = useState<EscalatedItem[]>([]);
  const [loading,   setLoading]        = useState(true);
  const [error,     setError]          = useState('');
  const [acting,    setActing]         = useState<string | null>(null);
  const [decisions, setDecisionsState] = useState(loadDecisions);
  const [modal,     setModal]          = useState<{ item: EscalatedItem; intent: 'confirm' | 'harmless' } | null>(null);
  const [noteText,  setNoteText]       = useState('');

  const load = useCallback(async () => {
    setLoading(true); setError('');
    try {
      const res = await fetch(`${ARE_BASE}/actions?limit=200`);
      if (!res.ok) throw new Error('ARE backend unreachable');
      const data = await res.json();
      const all: any[] = Array.isArray(data) ? data : (data.actions ?? []);
      const dec = loadDecisions();
      const escalated: EscalatedItem[] = all
        .filter(a => a.action === 'escalate')
        .map(a => ({
          actionId:     a.id,
          filename:     a.target,
          policyName:   a.policyName,
          details:      a.details ?? '',
          timestamp:    a.timestamp,
          reviewStatus: (dec[a.id]?.status ?? 'pending') as ReviewStatus,
          analystNote:  dec[a.id]?.note,
        }))
        .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
      setItems(escalated);
    } catch (e: any) {
      setError(e.message ?? 'Failed to load.');
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, []);

  const submitDecision = async () => {
    if (!modal || !canAct) return;
    const { item, intent } = modal;
    const newStatus = (intent === 'harmless' ? 'harmless' : 'confirmed') as ReviewStatus;
    const note      = noteText.trim();
    setActing(item.actionId); setModal(null);
    try {
      if (intent === 'harmless') {
        // Release existing isolation so file can be re-analyzed
        await fetch(`${ARE_BASE}/isolations/by-filename/${encodeURIComponent(item.filename)}`, { method: 'DELETE' });
      } else {
        // Confirm threat → create isolation record so it appears in ARE isolations tab
        await fetch(`${ARE_BASE}/isolations/manual`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            filename:   item.filename,
            policyName: `Analyst Confirmed — ${item.policyName}`,
            note,
          }),
        });
      }

      // Persist decision to DB
      const next = { ...decisions, [item.actionId]: { status: newStatus, note } };
      saveDecisions(next); setDecisionsState(next);
      setItems(prev => prev.map(i => i.actionId === item.actionId
        ? { ...i, reviewStatus: newStatus, analystNote: note }
        : i
      ));

      // ── SIEM: log analyst decision ──────────────────────────────────────
      fetch('http://localhost:8003/api/siem/log', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          severity:   intent === 'confirm' ? 'Critical' : 'Info',
          source:     'ARE',
          event_type: intent === 'confirm' ? 'AnalystConfirmedThreat' : 'AnalystClearedThreat',
          message:    intent === 'confirm'
            ? `Analyst confirmed threat: ${item.filename} — isolated permanently`
            : `Analyst cleared as harmless: ${item.filename} — isolation released`,
          metadata: {
            action_id:   item.actionId,
            filename:    item.filename,
            policy_name: item.policyName,
            analyst:     session?.email ?? 'analyst',
            note,
          },
        }),
      }).catch(() => {});   // SIEM is fire-and-forget
      // ───────────────────────────────────────────────────────────────────

    } catch { alert('Action failed. Ensure ARE backend is running on port 8000.'); }
    finally { setActing(null); }
  };

  const pending   = items.filter(i => i.reviewStatus === 'pending').length;
  const confirmed = items.filter(i => i.reviewStatus === 'confirmed').length;
  const cleared   = items.filter(i => i.reviewStatus === 'harmless').length;

  return (
    <div style={{ minHeight: '100vh', background: t.pageBg, padding: '24px', transition: 'background 0.3s' }}>
      <div style={{ maxWidth: '960px', margin: '0 auto' }}>

        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px', flexWrap: 'wrap', gap: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <div style={{ width: 44, height: 44, borderRadius: '12px', background: t.iconBg, border: `1px solid ${t.iconBorder}`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <UserCheck size={21} color="#10b981" />
            </div>
            <div>
              <h1 style={{ fontSize: '1.4rem', fontWeight: 800, color: t.title, margin: 0 }}>Security Analyst Review</h1>
              <p style={{ fontSize: '0.78rem', color: t.subtitle, marginTop: '3px' }}>
                {canAct ? 'Human review queue — escalated threats awaiting analyst decision' : 'Viewing escalated threat queue (read-only)'}
              </p>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            {!canAct && (
              <span style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '0.7rem', padding: '4px 10px', borderRadius: '6px', background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.2)', color: '#f59e0b' }}>
                <Eye size={11} /> View only
              </span>
            )}
            <Button variant="outline" onClick={load} className="gap-2">
              <RefreshCw className="w-4 h-4" /> Refresh
            </Button>
          </div>
        </div>

        {/* View-only banner for admin */}
        {!canAct && session?.role === 'admin' && (
          <ViewOnlyBanner role="Administrator" />
        )}

        {/* Stat cards */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: '14px', marginBottom: '24px' }}>
          {[
            { label: 'Pending Review',      value: pending,   Icon: Clock,       color: '#f59e0b', glow: 'rgba(245,158,11,0.12)'  },
            { label: 'Confirmed Threats',   value: confirmed, Icon: ShieldAlert, color: '#ef4444', glow: 'rgba(239,68,68,0.12)'   },
            { label: 'Cleared as Harmless', value: cleared,   Icon: CheckCircle, color: '#10b981', glow: 'rgba(16,185,129,0.12)'  },
          ].map(({ label, value, Icon, color, glow }) => (
            <div key={label} style={{ background: t.statCardBg, border: `1px solid ${t.statCardBorder}`, borderRadius: '14px', padding: '18px 20px', display: 'flex', alignItems: 'center', gap: '14px' }}>
              <div style={{ width: 38, height: 38, borderRadius: '10px', background: glow, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                <Icon size={18} color={color} />
              </div>
              <div>
                <div style={{ fontSize: '1.5rem', fontWeight: 800, color, lineHeight: 1 }}>{value}</div>
                <div style={{ fontSize: '0.7rem', color: t.statLabel, marginTop: '3px' }}>{label}</div>
              </div>
            </div>
          ))}
        </div>

        {/* Error */}
        {error && (
          <div style={{ background: t.errBg, border: `1px solid ${t.errBorder}`, borderRadius: '10px', padding: '10px 14px', color: '#f87171', fontSize: '0.82rem', marginBottom: '20px' }}>
            ⚠ {error} — Make sure the ARE backend is running on port 8000.
          </div>
        )}

        {/* Content */}
        {loading ? (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '80px 0', gap: '14px' }}>
            <div style={{ width: 28, height: 28, border: `2.5px solid ${t.spinnerTrack}`, borderTopColor: '#10b981', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
            <p style={{ fontSize: '0.82rem', color: t.emptyText }}>Loading escalated threats...</p>
          </div>
        ) : items.length === 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '80px 0', gap: '10px' }}>
            <Shield size={44} color={t.emptyIcon} />
            <p style={{ fontSize: '0.88rem', color: t.emptyText }}>No escalated threats found.</p>
            <p style={{ fontSize: '0.75rem', color: t.subtitle, opacity: 0.7 }}>They appear here when an ARE escalation policy fires.</p>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {items.map(item => {
              const isPending = item.reviewStatus === 'pending';
              const ss = statusStyle(item.reviewStatus, isLight);
              return (
                <div key={item.actionId} style={{ background: t.cardBg, border: `1px solid ${isPending ? t.cardBorderRed : t.cardBorder}`, borderRadius: '14px', padding: '20px', display: 'flex', flexDirection: 'column', gap: '12px' }}>

                  {/* Top row */}
                  <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <div style={{ width: 32, height: 32, borderRadius: '8px', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.22)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                        <AlertTriangle size={15} color="#f87171" />
                      </div>
                      <div>
                        <p style={{ fontSize: '0.88rem', fontWeight: 700, color: t.title, margin: 0 }}>{item.filename}</p>
                        <p style={{ fontSize: '0.68rem', color: t.subtitle, marginTop: '2px', fontFamily: 'monospace' }}>{item.actionId}</p>
                      </div>
                    </div>
                    <span style={{ fontSize: '0.65rem', fontWeight: 600, padding: '3px 10px', borderRadius: '999px', background: ss.bg, border: `1px solid ${ss.border}`, color: ss.color }}>
                      {ss.label}
                    </span>
                  </div>

                  {/* Meta */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(180px,1fr))', gap: '8px' }}>
                    {[{ label: 'Policy', value: item.policyName }, { label: 'Escalated at', value: new Date(String(item.timestamp).replace(/^(\d{4}-\d{2}-\d{2}) /, '$1T')).toLocaleString('en-GB', { timeZone: 'Asia/Karachi' }) }].map(({ label, value }) => (
                      <div key={label} style={{ background: t.metaBg, border: `1px solid ${t.metaBorder}`, borderRadius: '7px', padding: '7px 10px' }}>
                        <p style={{ fontSize: '0.62rem', color: t.metaLabel, margin: '0 0 3px', textTransform: 'uppercase', letterSpacing: '0.07em' }}>{label}</p>
                        <p style={{ fontSize: '0.8rem', color: t.metaValue, margin: 0 }}>{value}</p>
                      </div>
                    ))}
                  </div>

                  {/* ARE details */}
                  {item.details && (
                    <div style={{ background: t.detailBg, border: `1px solid ${t.detailBorder}`, borderRadius: '7px', padding: '8px 11px' }}>
                      <p style={{ fontSize: '0.62rem', color: t.metaLabel, margin: '0 0 3px', textTransform: 'uppercase', letterSpacing: '0.07em' }}>ARE Details</p>
                      <p style={{ fontSize: '0.8rem', color: t.detailText, margin: 0 }}>{item.details}</p>
                    </div>
                  )}

                  {/* Analyst note */}
                  {item.analystNote && (
                    <div style={{ background: t.noteBg, border: `1px solid ${t.noteBorder}`, borderRadius: '7px', padding: '8px 11px' }}>
                      <p style={{ fontSize: '0.62rem', color: 'rgba(16,185,129,0.55)', margin: '0 0 3px', textTransform: 'uppercase', letterSpacing: '0.07em' }}>Analyst Note</p>
                      <p style={{ fontSize: '0.8rem', color: t.noteText, margin: 0 }}>{item.analystNote}</p>
                    </div>
                  )}

                  {/* Action buttons — ANALYST ONLY */}
                  {canAct && isPending && (
                    <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                      <button
                        onClick={() => { setNoteText(''); setModal({ item, intent: 'harmless' }); }}
                        disabled={acting === item.actionId}
                        style={{ flex: 1, minWidth: '150px', padding: '9px 14px', background: t.harmlessBg, border: `1px solid ${t.harmlessBorder}`, borderRadius: '8px', color: t.harmlessColor, fontWeight: 700, fontSize: '0.78rem', cursor: acting === item.actionId ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}
                        onMouseEnter={e => { e.currentTarget.style.background = t.harmlessBgHov; }}
                        onMouseLeave={e => { e.currentTarget.style.background = t.harmlessBg; }}
                      >
                        <Unlock size={13} /> Mark as Harmless
                      </button>
                      <button
                        onClick={() => { setNoteText(''); setModal({ item, intent: 'confirm' }); }}
                        disabled={acting === item.actionId}
                        style={{ flex: 1, minWidth: '150px', padding: '9px 14px', background: t.confirmBg, border: `1px solid ${t.confirmBorder}`, borderRadius: '8px', color: t.confirmColor, fontWeight: 700, fontSize: '0.78rem', cursor: acting === item.actionId ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}
                        onMouseEnter={e => { e.currentTarget.style.background = t.confirmBgHov; }}
                        onMouseLeave={e => { e.currentTarget.style.background = t.confirmBg; }}
                      >
                        <Lock size={13} /> Confirm Threat
                      </button>
                    </div>
                  )}

                  {/* Admin view-only indicator on pending items */}
                  {!canAct && isPending && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', padding: '7px 10px', borderRadius: '7px', background: 'rgba(245,158,11,0.06)', border: '1px solid rgba(245,158,11,0.15)' }}>
                      <Eye size={11} color="#f59e0b" />
                      <span style={{ fontSize: '0.68rem', color: '#f59e0b' }}>Awaiting security analyst decision</span>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {/* Confirmation Modal — analyst only */}
        {canAct && modal && (
          <>
            <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.55)', backdropFilter: 'blur(6px)', zIndex: 50 }} />
            <div style={{ position: 'fixed', zIndex: 51, left: '50%', top: '50%', transform: 'translate(-50%,-50%)', width: '100%', maxWidth: '420px', padding: '0 16px' }}>
              <div style={{ background: t.modalBg, border: `1px solid ${t.modalBorder}`, borderRadius: '16px', padding: '26px 22px', boxShadow: '0 30px 80px rgba(0,0,0,0.35)' }}>
                <h3 style={{ fontSize: '1rem', fontWeight: 700, color: t.modalTitle, margin: '0 0 6px' }}>
                  {modal.intent === 'harmless' ? '✅ Mark as Harmless' : '🔒 Confirm Threat'}
                </h3>
                <p style={{ fontSize: '0.75rem', color: t.modalSub, marginBottom: '18px' }}>
                  {modal.intent === 'harmless'
                    ? `Releases isolation for "${modal.item.filename}". The file can be re-analyzed.`
                    : `Permanently confirms "${modal.item.filename}" as a real threat. It stays isolated.`}
                </p>
                <label style={{ display: 'block', fontSize: '0.68rem', fontWeight: 600, color: t.modalLabel, marginBottom: '6px', letterSpacing: '0.1em', textTransform: 'uppercase' }}>
                  Analyst Note (optional)
                </label>
                <textarea
                  value={noteText} onChange={e => setNoteText(e.target.value)}
                  placeholder="Add your analysis notes..."
                  rows={3}
                  style={{ width: '100%', padding: '9px 11px', borderRadius: '8px', background: t.textareaBg, border: `1px solid ${t.textareaBorder}`, color: t.textareaColor, fontSize: '0.82rem', resize: 'vertical', outline: 'none', boxSizing: 'border-box', fontFamily: 'inherit' }}
                  onFocus={e => e.target.style.borderColor = t.textareaFocus}
                  onBlur={e => e.target.style.borderColor = t.textareaBorder}
                />
                <div style={{ display: 'flex', gap: '8px', marginTop: '16px' }}>
                  <button onClick={() => setModal(null)} style={{ flex: 1, padding: '10px', borderRadius: '8px', background: t.cancelBg, border: `1px solid ${t.cancelBorder}`, color: t.cancelColor, cursor: 'pointer', fontSize: '0.82rem', fontFamily: 'inherit' }}>
                    Cancel
                  </button>
                  <button onClick={submitDecision} style={{ flex: 1, padding: '10px', borderRadius: '8px', fontWeight: 700, fontSize: '0.82rem', background: modal.intent === 'harmless' ? '#059669' : '#dc2626', border: 'none', color: '#fff', cursor: 'pointer', fontFamily: 'inherit' }}>
                    Confirm
                  </button>
                </div>
              </div>
            </div>
          </>
        )}

      </div>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}