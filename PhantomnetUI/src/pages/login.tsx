"use client";

/**
 * PhantomNet++ — Login (login.tsx)
 * Three roles: admin | security_analyst | user
 * Credentials verified against auth_backend.py (port 8002) — NOT hardcoded.
 */

import { useState, useEffect, useRef } from 'react';
import { Eye, EyeOff, Lock, AlertCircle, Shield, User, ShieldCheck, Loader2, Sun, Moon } from 'lucide-react';

const AUTH_URL = 'http://localhost:8002/api/auth';

// ── Role definitions ───────────────────────────────────────────────────────────
export type Role = 'admin' | 'security_analyst' | 'user';

export const ROLE_PERMISSIONS: Record<Role, {
  label: string;
  description: string;
  pages: {
    dashboard: boolean;
    threatDetection: boolean;
    attackSimulation: boolean;
    xaiEngine: boolean;
    responseEngine: boolean;
    responseEngineControl: boolean;
    analystReview: boolean;
    analystReviewAction: boolean;
    siemLogs: boolean;
    settings: boolean;
    srcCoordination: boolean;
  };
}> = {
  admin: {
    label: 'Administrator',
    description: 'Full platform access. Manages users, settings, and system configuration.',
    pages: {
      dashboard:              true,
      threatDetection:        true,
      attackSimulation:       true,
      xaiEngine:              true,
      responseEngine:         true,
      responseEngineControl:  false,
      analystReview:          true,
      analystReviewAction:    false,
      siemLogs:               true,
      settings:               true,
      srcCoordination:        true,
    },
  },
  security_analyst: {
    label: 'Security Analyst',
    description: 'Handles escalated threats. Reviews critical incidents and takes response actions.',
    pages: {
      dashboard:              true,
      threatDetection:        true,
      attackSimulation:       true,
      xaiEngine:              true,
      responseEngine:         true,
      responseEngineControl:  true,
      analystReview:          true,
      analystReviewAction:    true,
      siemLogs:               true,
      settings:               false,
      srcCoordination:        false,
    },
  },
  user: {
    label: 'Standard User',
    description: 'Uploads images for analysis and monitors detection results and active policies.',
    pages: {
      dashboard:              true,
      threatDetection:        true,
      attackSimulation:       false,
      xaiEngine:              true,
      responseEngine:         true,
      responseEngineControl:  false,
      analystReview:          false,
      analystReviewAction:    false,
      siemLogs:               false,
      settings:               false,
      srcCoordination:        false,
    },
  },
};

// ── Role badge config ──────────────────────────────────────────────────────────
const ROLE_BADGE: Record<Role, { icon: typeof Shield; accent: string; bg: string; border: string }> = {
  admin:            { icon: ShieldCheck, accent: '#f59e0b', bg: 'rgba(245,158,11,0.08)',  border: 'rgba(245,158,11,0.25)'  },
  security_analyst: { icon: Shield,      accent: '#10b981', bg: 'rgba(16,185,129,0.08)',  border: 'rgba(16,185,129,0.25)'  },
  user:             { icon: User,        accent: '#64748b', bg: 'rgba(100,116,139,0.08)', border: 'rgba(100,116,139,0.2)'  },
};

const DEMO_CARDS = [
  { label: 'Administrator',    email: 'admin@phantomnet.io',    role: 'admin'            as Role },
  { label: 'Security Analyst', email: 'analyst@phantomnet.io', role: 'security_analyst' as Role },
  { label: 'Standard User',    email: 'user@phantomnet.io',    role: 'user'             as Role },
];

// ── Theme ──────────────────────────────────────────────────────────────────────
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

function toggleTheme() {
  document.documentElement.classList.toggle('light');
}

function tokens(light: boolean) {
  return {
    pageBg:           light ? '#f8fafc'                               : '#020817',
    gridLine:         light ? 'rgba(16,185,129,0.07)'                 : 'rgba(16,185,129,0.04)',
    orb1:             light ? 'rgba(16,185,129,0.06)'                 : 'rgba(16,185,129,0.07)',
    leftBorder:       light ? 'rgba(16,185,129,0.15)'                 : 'rgba(16,185,129,0.08)',
    logoBg:           light ? 'rgba(16,185,129,0.08)'                 : 'rgba(16,185,129,0.08)',
    logoBorder:       light ? 'rgba(16,185,129,0.3)'                  : 'rgba(16,185,129,0.35)',
    logoShadow:       light ? '0 0 20px rgba(16,185,129,0.1)'         : '0 0 24px rgba(16,185,129,0.12)',
    headline:         light ? '#0f172a'                               : '#f1f5f9',
    subtext:          light ? 'rgba(30,41,59,0.55)'                   : 'rgba(148,163,184,0.55)',
    featureLabel:     light ? '#334155'                               : '#cbd5e1',
    featureSub:       light ? 'rgba(30,41,59,0.4)'                    : 'rgba(148,163,184,0.4)',
    rightBg:          light ? 'rgba(248,250,252,0.85)'                : 'rgba(2,8,23,0.7)',
    formTitle:        light ? '#0f172a'                               : '#f1f5f9',
    formSub:          light ? 'rgba(30,41,59,0.45)'                   : 'rgba(148,163,184,0.45)',
    inputBg:          light ? '#ffffff'                               : 'rgba(15,23,42,0.9)',
    inputBorder:      light ? 'rgba(16,185,129,0.25)'                 : 'rgba(16,185,129,0.15)',
    inputFocus:       light ? 'rgba(16,185,129,0.6)'                  : 'rgba(16,185,129,0.5)',
    inputText:        light ? '#0f172a'                               : '#e2e8f0',
    inputPlaceholder: light ? 'rgba(30,41,59,0.35)'                   : 'rgba(148,163,184,0.35)',
    labelColor:       light ? 'rgba(16,185,129,0.85)'                 : 'rgba(16,185,129,0.75)',
    btnBg:            light ? 'rgba(16,185,129,0.1)'                  : 'rgba(16,185,129,0.12)',
    btnBgHover:       light ? 'rgba(16,185,129,0.18)'                 : 'rgba(16,185,129,0.2)',
    btnBorder:        light ? 'rgba(16,185,129,0.5)'                  : 'rgba(16,185,129,0.4)',
    btnColor:         light ? '#059669'                               : '#10b981',
    dividerLine:      light ? 'rgba(16,185,129,0.12)'                 : 'rgba(16,185,129,0.08)',
    dividerText:      light ? 'rgba(30,41,59,0.3)'                    : 'rgba(148,163,184,0.25)',
    hintBg:           light ? 'rgba(255,255,255,0.7)'                 : 'rgba(15,23,42,0.7)',
    hintBorder:       light ? 'rgba(16,185,129,0.12)'                 : 'rgba(16,185,129,0.07)',
    hintBgHover:      light ? 'rgba(16,185,129,0.06)'                 : 'rgba(16,185,129,0.05)',
    hintBorderHov:    light ? 'rgba(16,185,129,0.25)'                 : 'rgba(16,185,129,0.2)',
    hintEmail:        light ? 'rgba(30,41,59,0.4)'                    : 'rgba(148,163,184,0.3)',
    errBg:            light ? 'rgba(239,68,68,0.06)'                  : 'rgba(239,68,68,0.07)',
    errBorder:        light ? 'rgba(239,68,68,0.25)'                  : 'rgba(239,68,68,0.2)',
  };
}

// ── Component ──────────────────────────────────────────────────────────────────
export default function LoginPage({ onLogin }: { onLogin?: (role: Role, displayName: string) => void }) {
  const isLight = useTheme();
  const t = tokens(isLight);

  const [email,    setEmail]    = useState('');
  const [password, setPassword] = useState('');
  const [showPw,   setShowPw]   = useState(false);
  const [error,    setError]    = useState('');
  const [loading,  setLoading]  = useState(false);
  const [preview,  setPreview]  = useState<Role | null>(null);

  // Derive role from typed email for live indicator
  const emailRole = DEMO_CARDS.find(c => c.email === email.trim().toLowerCase())?.role ?? null;
  const activeRole = preview ?? emailRole;

  // Keep last role in ref so preview panel doesn't flash away on mouse-leave
  const lastRoleRef = useRef<Role>('admin');
  if (activeRole) lastRoleRef.current = activeRole;
  const displayRole = activeRole ?? lastRoleRef.current;

  const badge = ROLE_BADGE[displayRole];
  const perms  = ROLE_PERMISSIONS[displayRole].pages;

  // ── Submit — hits auth backend ─────────────────────────────────────────────
  const submit = async () => {
    setError('');
    if (!email.trim() || !password.trim()) {
      setError('Please enter your email and password.');
      return;
    }
    setLoading(true);
    try {
      const res = await fetch(`${AUTH_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email.trim().toLowerCase(), password }),
      });

      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        setError(data.detail ?? 'Invalid email or password.');
        return;
      }

      const data = await res.json();
      const user = data.user;
      const role = user.role as Role;

      sessionStorage.setItem('phantomnet_session', JSON.stringify({
        email:       user.email,
        role:        role,
        displayName: user.displayName,
        userId:      user.id,
        permissions: ROLE_PERMISSIONS[role].pages,
      }));

      onLogin?.(role, user.displayName);

    } catch (err) {
      // Network error — auth backend probably not running
      setError('Cannot reach auth server. Make sure auth_backend.py is running on port 8002.');
    } finally {
      setLoading(false);
    }
  };

  const quickFill = (cardEmail: string) => {
    setEmail(cardEmail);
    setPassword('');
    setError('');
    setPreview(null);
  };

  return (
    <div style={{ height: '100vh', background: t.pageBg, display: 'flex', alignItems: 'stretch', fontFamily: "'Outfit', sans-serif", overflow: 'hidden', position: 'relative', transition: 'background 0.3s' }}>

      {/* Grid background */}
      <div style={{ position: 'absolute', inset: 0, zIndex: 0, backgroundImage: `linear-gradient(${t.gridLine} 1px,transparent 1px),linear-gradient(90deg,${t.gridLine} 1px,transparent 1px)`, backgroundSize: '48px 48px' }} />
      <div style={{ position: 'absolute', width: '600px', height: '600px', borderRadius: '50%', background: `radial-gradient(circle,${t.orb1} 0%,transparent 70%)`, top: '-150px', left: '-150px', zIndex: 0 }} />
      <div style={{ position: 'absolute', width: '400px', height: '400px', borderRadius: '50%', background: `radial-gradient(circle,${t.orb1} 0%,transparent 70%)`, bottom: '-100px', right: '400px', zIndex: 0 }} />

      {/* ── Left — branding ── */}
      <div className="pn-left" style={{ flex: 1, minWidth: '400px', display: 'flex', flexDirection: 'column', justifyContent: 'flex-start', padding: '44px 56px 28px', position: 'relative', zIndex: 1, borderRight: `1px solid ${t.leftBorder}`, overflowY: 'auto', scrollbarWidth: 'none' }}>

        {/* Logo */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '28px' }}>
          <div style={{ width: '52px', height: '52px', background: t.logoBg, border: `1.5px solid ${t.logoBorder}`, borderRadius: '14px', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: t.logoShadow }}>
            <svg viewBox="0 0 64 64" width="32" height="32">
              <polygon points="32,4 58,18 58,46 32,60 6,46 6,18" fill="none" stroke="#10b981" strokeWidth="3" />
              <circle cx="32" cy="32" r="8" fill="#10b981" opacity="0.9" />
              <line x1="32" y1="4"  x2="32" y2="24" stroke="#10b981" strokeWidth="1.5" opacity="0.5" />
              <line x1="32" y1="40" x2="32" y2="60" stroke="#10b981" strokeWidth="1.5" opacity="0.5" />
              <line x1="6"  y1="18" x2="24" y2="27" stroke="#10b981" strokeWidth="1.5" opacity="0.5" />
              <line x1="40" y1="37" x2="58" y2="46" stroke="#10b981" strokeWidth="1.5" opacity="0.5" />
              <line x1="58" y1="18" x2="40" y2="27" stroke="#10b981" strokeWidth="1.5" opacity="0.5" />
              <line x1="24" y1="37" x2="6"  y2="46" stroke="#10b981" strokeWidth="1.5" opacity="0.5" />
            </svg>
          </div>
          <div>
            <div style={{ fontSize: '1.3rem', fontWeight: 800, color: t.headline, letterSpacing: '-0.02em' }}>
              PhantomNet<span style={{ color: '#10b981' }}>++</span>
            </div>
            <div style={{ fontSize: '0.74rem', color: 'rgba(16,185,129,0.6)', letterSpacing: '0.15em', textTransform: 'uppercase', marginTop: '2px' }}>
              Adversarial Threat Detection
            </div>
          </div>
        </div>

        <h1 style={{ fontSize: '1.9rem', fontWeight: 800, color: t.headline, lineHeight: 1.1, marginBottom: '12px', letterSpacing: '-0.03em' }}>
          Defend.<br /><span style={{ color: '#10b981' }}>Detect.</span><br />Respond.
        </h1>
        <p style={{ fontSize: '0.82rem', color: t.subtext, lineHeight: 1.7, maxWidth: '380px', marginBottom: '20px' }}>
          Real-time adversarial attack detection powered by ensemble AI. Monitor threats, trigger autonomous responses, and protect your systems 24/7.
        </p>

        {[
          { label: 'Ensemble Detection',         sub: 'ResNet50 · YOLOv5 · Autoencoder'         },
          { label: 'Autonomous Response Engine', sub: 'Policy-driven automated mitigation'       },
          { label: 'Role-Based Access Control',  sub: 'Admin · Security Analyst · Standard User' },
        ].map(f => (
          <div key={f.label} style={{ display: 'flex', alignItems: 'center', gap: '14px', marginBottom: '10px' }}>
            <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#10b981', boxShadow: '0 0 8px rgba(16,185,129,0.7)', flexShrink: 0 }} />
            <div>
              <div style={{ fontSize: '0.8rem', fontWeight: 600, color: t.featureLabel }}>{f.label}</div>
              <div style={{ fontSize: '0.7rem', color: t.featureSub, marginTop: '1px' }}>{f.sub}</div>
            </div>
          </div>
        ))}

        {/* Role permission preview panel — opacity fade, no layout shift */}
        <div style={{ marginTop: '16px', background: badge.bg, border: `1px solid ${badge.border}`, borderRadius: '12px', padding: '14px 16px', maxWidth: '380px', opacity: activeRole ? 1 : 0, transition: 'opacity 0.2s, background 0.2s, border-color 0.2s', pointerEvents: activeRole ? 'auto' : 'none' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
            <badge.icon size={14} color={badge.accent} />
            <span style={{ fontSize: '0.72rem', fontWeight: 700, color: badge.accent, letterSpacing: '0.1em', textTransform: 'uppercase' }}>
              {ROLE_PERMISSIONS[displayRole].label}
            </span>
          </div>
          <p style={{ fontSize: '0.74rem', color: t.featureSub, margin: '0 0 10px', lineHeight: 1.5 }}>
            {ROLE_PERMISSIONS[displayRole].description}
          </p>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '4px' }}>
            {[
              { key: 'dashboard',             label: 'Dashboard'         },
              { key: 'threatDetection',       label: 'Threat Detection'  },
              { key: 'attackSimulation',      label: 'Attack Simulation' },
              { key: 'xaiEngine',             label: 'XAI Engine'        },
              { key: 'responseEngine',        label: 'ARE — view'        },
              { key: 'responseEngineControl', label: 'ARE — control'     },
              { key: 'analystReview',         label: 'Analyst Review'    },
              { key: 'analystReviewAction',   label: 'Review Actions'    },
              { key: 'siemLogs',              label: 'SIEM Logs'         },
              { key: 'srcCoordination',       label: 'SRC Coordination'  },
              { key: 'settings',              label: 'Settings'          },
            ].map(({ key, label }) => {
              const allowed = perms[key as keyof typeof perms];
              const dimColor = isLight ? 'rgba(30,41,59,0.22)' : 'rgba(148,163,184,0.22)';
              return (
                <div key={key} style={{ display: 'flex', alignItems: 'center', gap: '5px', padding: '2px 0' }}>
                  <span style={{ fontSize: '12px', fontWeight: 700, flexShrink: 0, color: allowed ? badge.accent : dimColor }}>
                    {allowed ? '✓' : '✗'}
                  </span>
                  <span style={{ fontSize: '0.72rem', fontWeight: allowed ? 600 : 400, color: allowed ? badge.accent : dimColor }}>
                    {label}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* ── Right — form ── */}
      <div style={{ width: '440px', flexShrink: 0, display: 'flex', flexDirection: 'column', justifyContent: 'center', padding: '28px 44px', position: 'relative', zIndex: 1, background: t.rightBg, backdropFilter: 'blur(20px)' }}>

        <div style={{ marginBottom: '20px' }}>
          <h2 style={{ fontSize: '1.3rem', fontWeight: 700, color: t.formTitle, margin: '0 0 6px' }}>Secure Access</h2>
          <p style={{ fontSize: '0.80rem', color: t.formSub, margin: 0 }}>Authenticate to access the platform</p>
        </div>

        {/* Error */}
        {error && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', background: t.errBg, border: `1px solid ${t.errBorder}`, borderRadius: '8px', padding: '9px 12px', marginBottom: '18px' }}>
            <AlertCircle size={13} color="#f87171" style={{ flexShrink: 0 }} />
            <span style={{ fontSize: '0.80rem', color: '#f87171' }}>{error}</span>
          </div>
        )}

        {/* Email */}
        <div style={{ marginBottom: '14px' }}>
          <label style={{ display: 'block', fontSize: '0.80rem', fontWeight: 600, color: t.labelColor, marginBottom: '6px', letterSpacing: '0.12em', textTransform: 'uppercase' }}>Email</label>
          <input
            type="email" placeholder="you@phantomnet.io" value={email}
            onChange={e => { setEmail(e.target.value); setError(''); setPreview(null); }}
            onKeyDown={e => e.key === 'Enter' && submit()}
            style={{ width: '100%', padding: '11px 13px', borderRadius: '8px', background: t.inputBg, border: `1px solid ${t.inputBorder}`, color: t.inputText, fontSize: '0.83rem', outline: 'none', boxSizing: 'border-box', fontFamily: 'inherit', transition: 'border-color 0.2s' }}
            onFocus={e => e.target.style.borderColor = t.inputFocus}
            onBlur={e => e.target.style.borderColor = t.inputBorder}
          />
        </div>

        {/* Password */}
        <div style={{ marginBottom: '18px' }}>
          <label style={{ display: 'block', fontSize: '0.80rem', fontWeight: 600, color: t.labelColor, marginBottom: '6px', letterSpacing: '0.12em', textTransform: 'uppercase' }}>Password</label>
          <div style={{ position: 'relative' }}>
            <input
              type={showPw ? 'text' : 'password'} placeholder="••••••••" value={password}
              onChange={e => { setPassword(e.target.value); setError(''); }}
              onKeyDown={e => e.key === 'Enter' && submit()}
              style={{ width: '100%', padding: '11px 38px 11px 13px', borderRadius: '8px', background: t.inputBg, border: `1px solid ${t.inputBorder}`, color: t.inputText, fontSize: '0.83rem', outline: 'none', boxSizing: 'border-box', fontFamily: 'inherit', transition: 'border-color 0.2s' }}
              onFocus={e => e.target.style.borderColor = t.inputFocus}
              onBlur={e => e.target.style.borderColor = t.inputBorder}
            />
            <button onClick={() => setShowPw(v => !v)} style={{ position: 'absolute', right: '11px', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: t.inputPlaceholder, padding: '2px', display: 'flex' }}>
              {showPw ? <EyeOff size={14} /> : <Eye size={14} />}
            </button>
          </div>
        </div>

        {/* Role indicator — shows role when typed email matches a known account */}
        {emailRole && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '7px', marginBottom: '14px', padding: '7px 10px', background: ROLE_BADGE[emailRole].bg, border: `1px solid ${ROLE_BADGE[emailRole].border}`, borderRadius: '7px' }}>
            {(() => { const Icon = ROLE_BADGE[emailRole].icon; return <Icon size={12} color={ROLE_BADGE[emailRole].accent} />; })()}
            <span style={{ fontSize: '0.80rem', color: ROLE_BADGE[emailRole].accent, fontWeight: 600 }}>
              Signing in as {ROLE_PERMISSIONS[emailRole].label}
            </span>
          </div>
        )}

        {/* Submit */}
        <button
          onClick={submit} disabled={loading}
          style={{ width: '100%', padding: '12px', background: loading ? 'rgba(16,185,129,0.06)' : t.btnBg, border: `1px solid ${loading ? 'rgba(16,185,129,0.2)' : t.btnBorder}`, borderRadius: '8px', color: loading ? 'rgba(16,185,129,0.4)' : t.btnColor, fontWeight: 700, fontSize: '0.82rem', cursor: loading ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px', fontFamily: 'inherit', letterSpacing: '0.06em', transition: 'all 0.2s' }}
          onMouseEnter={e => { if (!loading) e.currentTarget.style.background = t.btnBgHover; }}
          onMouseLeave={e => { if (!loading) e.currentTarget.style.background = t.btnBg; }}
        >
          {loading
            ? <><div style={{ width: 13, height: 13, border: '2px solid rgba(16,185,129,0.2)', borderTopColor: '#10b981', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />Authenticating...</>
            : <><Lock size={13} />Sign In</>}
        </button>

        {/* Divider */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', margin: '16px 0 10px' }}>
          <div style={{ flex: 1, height: '1px', background: t.dividerLine }} />
          <span style={{ fontSize: '0.72rem', color: t.dividerText, letterSpacing: '0.12em', textTransform: 'uppercase' }}>Login as</span>
          <div style={{ flex: 1, height: '1px', background: t.dividerLine }} />
        </div>

        {/* Quick-fill cards */}
        {DEMO_CARDS.map(c => {
          const b = ROLE_BADGE[c.role];
          return (
            <button
              key={c.email}
              onClick={() => quickFill(c.email)}
              onMouseEnter={() => setPreview(c.role)}
              onMouseLeave={() => setPreview(null)}
              style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '9px 12px', borderRadius: '7px', background: t.hintBg, border: `1px solid ${t.hintBorder}`, cursor: 'pointer', marginBottom: '7px', fontFamily: 'inherit', transition: 'all 0.15s', width: '100%', textAlign: 'left' }}
              onMouseEnterCapture={undefined}
            >
              {(() => { const Icon = b.icon; return <Icon size={13} color={b.accent} style={{ flexShrink: 0 }} />; })()}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: '0.73rem', color: b.accent, fontWeight: 600 }}>{c.label}</div>
              </div>
              <span style={{ fontSize: '0.72rem', color: t.dividerText, letterSpacing: '0.06em' }}>hover to preview</span>
            </button>
          );
        })}

        <p style={{ fontSize: '0.72rem', color: t.dividerText, textAlign: 'center', margin: '10px 0 0', lineHeight: 1.5 }}>
          Hover a card to preview permissions · Enter password to sign in
        </p>
      </div>

      {/* ── Theme toggle ── */}
      <button
        onClick={toggleTheme}
        style={{ position: 'absolute', top: '16px', right: '16px', zIndex: 10, width: '36px', height: '36px', borderRadius: '8px', background: t.hintBg, border: `1px solid ${t.hintBorder}`, display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer', transition: 'all 0.2s' }}
        title="Toggle light / dark mode"
      >
        {isLight ? <Moon size={15} color={t.subtext} /> : <Sun size={15} color={t.subtext} />}
      </button>

      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
        .pn-left::-webkit-scrollbar { display: none; }
      `}</style>
    </div>
  );
}