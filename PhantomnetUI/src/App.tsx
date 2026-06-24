import { BrowserRouter, Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import { ThemeProvider } from '@/components/theme-provider';
import { DashboardLayout } from '@/components/layout/dashboard-layout';
import Dashboard from '@/pages/dashboard';
import ThreatDetection from '@/pages/threat-detection';
import AttackSimulation from '@/pages/attack-simulation';
import XAIEngine from '@/pages/xai-engine';
import ResponseEngine from '@/pages/response-engine';
import SIEMLogs from '@/pages/siem-logs';
import Settings from '@/pages/settings';
import AnalystReview from '@/pages/analyst-review';
import ProfilePage from '@/pages/profile';
import LoginPage, { type Role, ROLE_PERMISSIONS } from '@/pages/login';
import SRCCoordination from '@/pages/srcCoordination';

export interface PhantomSession {
  email: string;
  role: Role;
  displayName: string;
  id: string;
  permissions: typeof ROLE_PERMISSIONS[Role]['pages'];
}

export function getSession(): PhantomSession | null {
  try {
    const raw = sessionStorage.getItem('phantomnet_session');
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}

export function clearSession() {
  sessionStorage.removeItem('phantomnet_session');
}

function ProtectedRoute({ element, permKey }: { element: React.ReactElement; permKey?: keyof PhantomSession['permissions'] }) {
  const session = getSession();
  if (!session) return <Navigate to="/login" replace />;
  if (permKey && !session.permissions[permKey]) return <Navigate to="/dashboard" replace />;
  return element;
}

function LoginWrapper() {
  const navigate = useNavigate();
  const session  = getSession();
  if (session) return <Navigate to="/dashboard" replace />;
  return <LoginPage onLogin={() => navigate('/dashboard', { replace: true })} />;
}

function App() {
  return (
    <ThemeProvider defaultTheme="dark" storageKey="phantomnet-theme">
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginWrapper />} />
          <Route path="/" element={<Navigate to="/login" replace />} />
          <Route path="/" element={<ProtectedRoute element={<DashboardLayout />} />}>
            <Route path="dashboard"         element={<ProtectedRoute element={<Dashboard />}       permKey="dashboard" />} />
            <Route path="threat-detection"  element={<ProtectedRoute element={<ThreatDetection />} permKey="threatDetection" />} />
            <Route path="attack-simulation" element={<ProtectedRoute element={<AttackSimulation />} permKey="attackSimulation" />} />
            <Route path="xai-engine"        element={<ProtectedRoute element={<XAIEngine />}       permKey="xaiEngine" />} />
            <Route path="response-engine"   element={<ProtectedRoute element={<ResponseEngine />}  permKey="responseEngine" />} />
            <Route path="siem-logs"         element={<ProtectedRoute element={<SIEMLogs />}        permKey="siemLogs" />} />
            <Route path="analyst-review"    element={<ProtectedRoute element={<AnalystReview />}   permKey="analystReview" />} />
            <Route path="srcCoordination"   element={<ProtectedRoute element={<SRCCoordination />} permKey="srcCoordination" />} />
            <Route path="settings"          element={<ProtectedRoute element={<Settings />}        permKey="settings" />} />
            <Route path="profile"           element={<ProtectedRoute element={<ProfilePage />} />} />
          </Route>
          <Route path="*" element={<Navigate to="/login" replace />} />
        </Routes>
      </BrowserRouter>
    </ThemeProvider>
  );
}

export default App;