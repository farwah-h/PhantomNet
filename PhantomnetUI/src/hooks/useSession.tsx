/**
 * PhantomNet++ — useSession hook + AccessDenied component
 * Import this in any page that needs role/permission awareness.
 *
 * Usage:
 *   const { session, can } = useSession();
 *   if (!can('responseEngineControl')) return <AccessDenied />;
 */

import { useMemo } from 'react';
import { ShieldOff } from 'lucide-react';
import type { PhantomSession } from '@/App';
import { getSession } from '@/App';
import { ROLE_PERMISSIONS, type Role } from '@/pages/login';

// ── Hook ──────────────────────────────────────────────────────────────────────
export function useSession() {
  const session: PhantomSession | null = useMemo(() => getSession(), []);

  function can(permKey: keyof typeof ROLE_PERMISSIONS[Role]['pages']): boolean {
    if (!session) return false;
    return !!session.permissions[permKey];
  }

  return { session, can };
}

// ── AccessDenied UI ───────────────────────────────────────────────────────────
export function AccessDenied({ message }: { message?: string }) {
  return (
    <div style={{
      display: 'flex', flexDirection: 'column', alignItems: 'center',
      justifyContent: 'center', minHeight: '60vh', gap: '16px',
      fontFamily: "'JetBrains Mono', monospace",
    }}>
      <div style={{
        width: '56px', height: '56px', borderRadius: '14px',
        background: 'rgba(239,68,68,0.08)', border: '1.5px solid rgba(239,68,68,0.25)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
      }}>
        <ShieldOff size={24} color="#f87171" />
      </div>
      <div style={{ textAlign: 'center' }}>
        <div style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--foreground)', marginBottom: '6px' }}>
          Access Restricted
        </div>
        <div style={{ fontSize: '0.78rem', color: 'var(--muted-foreground)', maxWidth: '320px', lineHeight: 1.6 }}>
          {message ?? "You don't have permission to perform this action. Contact your administrator if you believe this is an error."}
        </div>
      </div>
    </div>
  );
}

// ── ViewOnly banner — shows when a user can see but not control ───────────────
export function ViewOnlyBanner({ role }: { role?: string }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: '8px',
      padding: '8px 14px', borderRadius: '8px', marginBottom: '16px',
      background: 'rgba(245,158,11,0.07)', border: '1px solid rgba(245,158,11,0.2)',
    }}>
      <ShieldOff size={13} color="#f59e0b" style={{ flexShrink: 0 }} />
      <span style={{ fontSize: '0.73rem', color: '#f59e0b' }}>
        View-only mode — {role ?? 'your role'} cannot modify these settings.
      </span>
    </div>
  );
}