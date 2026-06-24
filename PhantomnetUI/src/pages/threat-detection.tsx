import { useState, useEffect } from 'react';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  LineChart,
  Line,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';
import { type ThreatData } from '@/lib/mock-data';
import {
  Shield,
  AlertTriangle,
  AlertCircle,
  CheckCircle,
  Eye,
  Ban,
  XCircle,
  Filter,
  Clock,
  Target,
  TrendingUp,
  Activity,
  Zap,
  ShieldAlert,
  Upload,
  Image as ImageIcon,
  Loader2,
  RefreshCw,
  Lock,
  Unlock,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { getSession } from '@/App';

/**
 * Parse SQLite datetime ("YYYY-MM-DD HH:MM:SS") as LOCAL time.
 * Date.parse() treats strings without timezone as UTC in Chrome/Windows,
 * causing a 5-hour offset for PKT (UTC+5).
 */
function parseLocalTS(raw: string | Date | null | undefined): Date {
  if (!raw) return new Date();
  if (raw instanceof Date) return raw;
  const s = String(raw).trim();
  const m = s.match(/^(\d{4})-(\d{2})-(\d{2})[\sT](\d{2}):(\d{2}):(\d{2})/);
  if (m) {
    return new Date(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
  }
  return new Date(s);
}



const BACKEND_URL = 'http://localhost:5000';
const ARE_BASE    = 'http://localhost:8000/api/are';

export default function ThreatDetection() {
  const canRelease = getSession()?.role === 'security_analyst';

  // Always start empty — DB is the source of truth, synced on mount.
  // localStorage is only written to keep the notifications system in sync,
  // never read back as the primary data source (avoids stale cross-role data).
  const [threats, setThreats] = useState<ThreatData[]>([]);
  const [allScans, setAllScans] = useState<ThreatData[]>([]);
  const [dbSynced, setDbSynced] = useState(false);
  
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [selectedStatus, setSelectedStatus] = useState<string>('all');
  const [uploadedImage, setUploadedImage] = useState<File | null>(null);
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [backendStatus, setBackendStatus] = useState<'connected' | 'disconnected' | 'checking'>('checking');
  const [currentScanResult, setCurrentScanResult] = useState<any>(null);
  const [activeTab, setActiveTab] = useState<'threats' | 'all'>('threats');

  // Isolation state — set when a selected file is currently isolated by ARE
  const [isolationInfo, setIsolationInfo] = useState<{
    threat_id: string;
    filename: string;
    isolated_at: string;
    policy_name: string;
  } | null>(null);
  const [releasingIsolation, setReleasingIsolation] = useState(false);

  // Escalation alert state — set when ARE fires an escalate action
  const [escalationAlert, setEscalationAlert] = useState<{
    filename: string;
    severity: string;
    confidence: number;
    policy_name: string;
    threat_id: string;
    timestamp: string;
  } | null>(null);

  // ── Sync from DB on mount (and every 15 s) ───────────────────────────────
  // This ensures all roles always see the same shared dataset regardless of
  // which user performed the scans or what is cached in localStorage.
  useEffect(() => {
    const syncFromDB = async () => {
      try {
        const res = await fetch(`${BACKEND_URL}/api/predictions?limit=500`, {
          signal: AbortSignal.timeout(5000),
        });
        if (!res.ok) return;
        const data = await res.json();
        const fetched: ThreatData[] = (data.predictions ?? []).map((p: any) => {
          const ir = typeof p.individual_results === 'string'
            ? JSON.parse(p.individual_results)
            : (p.individual_results ?? {});
          const parts: string[] = [];
          if (ir?.resnet?.status)      parts.push(`ResNet: ${ir.resnet.status}`);
          if (ir?.yolo?.status)        parts.push(`YOLOv5: ${ir.yolo.status}`);
          if (ir?.autoencoder?.status) parts.push(`Autoencoder: ${ir.autoencoder.status}`);
          return {
            id:               p.threat_id,
            timestamp:        parseLocalTS(p.timestamp),
            type:             p.attack_type      ?? 'Unknown',
            severity:         (p.severity        ?? 'low') as ThreatData['severity'],
            status:           p.final_decision === 'adversarial' ? 'detected' : 'clean',
            modelTarget:      'Multi-Model Analysis',
            confidence:       p.confidence       ?? 0,
            attackVector:     parts.join(' | ')  || 'Multi-Model Analysis',
            category:         p.attack_category  ?? 'Unknown',
            characteristics:  p.characteristics  ? (typeof p.characteristics === 'string' ? JSON.parse(p.characteristics) : p.characteristics) : [],
            primaryIndicator: p.primary_indicator ?? '',
          } as ThreatData;
        });

        const allFromDB  = fetched;
        const threatOnly = fetched.filter(s => s.status === 'detected');
        setAllScans(allFromDB);
        setThreats(threatOnly);
        setDbSynced(true);

        // Keep localStorage in sync for the notifications system only
        localStorage.setItem('phantomnet_all_scans', JSON.stringify(allFromDB));
        localStorage.setItem('phantomnet_threats',   JSON.stringify(threatOnly));
      } catch {
        // Backend offline — show nothing rather than stale data from another session
        if (!dbSynced) {
          setAllScans([]);
          setThreats([]);
          setDbSynced(true);
        }
      }
    };

    syncFromDB();
    const iv = setInterval(syncFromDB, 15_000);
    return () => clearInterval(iv);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Check backend health
  useEffect(() => {
    const checkBackend = async () => {
      try {
        const response = await fetch(`${BACKEND_URL}/api/health`);
        if (response.ok) {
          setBackendStatus('connected');
        } else {
          setBackendStatus('disconnected');
        }
      } catch (error) {
        setBackendStatus('disconnected');
      }
    };

    checkBackend();
    const interval = setInterval(checkBackend, 30000);
    return () => clearInterval(interval);
  }, []);

  // Handle image upload — check isolation status before accepting
  const handleImageUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    // Reset isolation info for the new file
    setIsolationInfo(null);

    // Check if this file is currently isolated by ARE
    try {
      const res = await fetch(`${ARE_BASE}/isolations/check-filename/${encodeURIComponent(file.name)}`);
      if (res.ok) {
        const data = await res.json();
        if (data.isolated) {
          setIsolationInfo(data.record);
          // Still show the file name but block analysis
          setUploadedImage(file);
          setImagePreview(null); // don't preview isolated images
          return;
        }
      }
    } catch {
      // ARE offline — allow upload to proceed, backend will re-check
    }

    setUploadedImage(file);
    const reader = new FileReader();
    reader.onloadend = () => setImagePreview(reader.result as string);
    reader.readAsDataURL(file);
  };

  // FIXED: Analyze image and add to feed AUTOMATICALLY
  const analyzeImage = async () => {
    if (!uploadedImage) {
      alert('Please upload an image first');
      return;
    }

    setAnalyzing(true);

    try {
      const formData = new FormData();
      formData.append('image', uploadedImage);

      const response = await fetch(`${BACKEND_URL}/api/detect`, {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        if (response.status === 403) {
          const errData = await response.json();
          if (errData?.detail?.error === 'FILE_ISOLATED') {
            setIsolationInfo({
              threat_id:   errData.detail.threat_id,
              filename:    errData.detail.filename,
              isolated_at: errData.detail.isolated_at,
              policy_name: errData.detail.policy_name,
            });
            setImagePreview(null);
            return;
          }
        }
        throw new Error('Detection failed');
      }

      const result = await response.json();
      console.log('✅ Detection Complete:', result);

      // Only evaluate if the ensemble says adversarial
      if (result.ensemble?.final_decision === 'adversarial') {
        try {
          const arePayload = {
            threatId:   result.id,
            target:     result.filename,
            severity:   result.threat_data.severity,
            confidence: result.threat_data.confidence,
            status:     'detected',
          };

          const areRes = await fetch(`${ARE_BASE}/evaluate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(arePayload),
          });

          if (areRes.ok) {
            const areData = await areRes.json();
            console.log('🤖 ARE response:', areData);

            const actions = areData.actions ?? [];
            const escalationAction = actions.find((a: any) => a.action === 'escalate');
            const isolationAction  = actions.find((a: any) => a.action === 'isolate');

            // ── Escalation: 3 sharp beeps + popup ──
            if (escalationAction) {
              try {
                const ctx = new (window.AudioContext || (window as any).webkitAudioContext)();
                for (let i = 0; i < 3; i++) {
                  const osc  = ctx.createOscillator();
                  const gain = ctx.createGain();
                  osc.connect(gain);
                  gain.connect(ctx.destination);
                  osc.type = 'square';
                  osc.frequency.value = 880;
                  gain.gain.setValueAtTime(0.35, ctx.currentTime + i * 0.35);
                  gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + i * 0.35 + 0.28);
                  osc.start(ctx.currentTime + i * 0.35);
                  osc.stop(ctx.currentTime + i * 0.35 + 0.28);
                }
              } catch { /* browser blocked audio */ }

              setEscalationAlert({
                filename:    result.filename,
                severity:    result.threat_data.severity,
                confidence:  result.threat_data.confidence,
                policy_name: escalationAction.policyName,
                threat_id:   result.id,
                timestamp:   escalationAction.timestamp,
              });
            }

            // ── Isolation: single softer beep ──
            if (isolationAction && !escalationAction) {
              try {
                const ctx  = new (window.AudioContext || (window as any).webkitAudioContext)();
                const osc  = ctx.createOscillator();
                const gain = ctx.createGain();
                osc.connect(gain);
                gain.connect(ctx.destination);
                osc.type = 'sine';
                osc.frequency.value = 520;
                gain.gain.setValueAtTime(0.25, ctx.currentTime);
                gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.6);
                osc.start(ctx.currentTime);
                osc.stop(ctx.currentTime + 0.6);
              } catch { /* silent fallback */ }
            }
          }
        } catch (areErr) {
          console.warn('⚠️ ARE call failed (non-critical):', areErr);
        }
      }
      
      // FIXED: Set current scan result (persists even when uploading new image)
      setCurrentScanResult(result);

      // Save raw image to localStorage so XAI engine can use it without re-upload
      try {
        const imgReader = new FileReader();
        imgReader.onloadend = () => {
          localStorage.setItem('phantomnet_last_image', imgReader.result as string);
        };
        imgReader.readAsDataURL(uploadedImage);
      } catch (_) {}

      // Create threat data object
      const scanEntry: ThreatData = {
        id: result.id,
        timestamp: parseLocalTS(result.timestamp),
        type: result.threat_data.type,
        severity: result.threat_data.severity,
        status: result.threat_data.status === 'clean' ? 'clean' : 'detected',
        modelTarget: result.threat_data.modelTarget,
        confidence: result.threat_data.confidence,
        attackVector: buildAttackVector(result.individual_results),
        category: result.threat_data.category || 'Unknown',
        characteristics: result.threat_data.characteristics || [],
        primaryIndicator: result.threat_data.primary_indicator || '',
      };

      // ALWAYS add to all scans feed
      setAllScans((prev) => [scanEntry, ...prev]);

      // FIXED: Only add to threat feed if it's ACTUALLY adversarial
      const isActualThreat = result.ensemble.final_decision === 'adversarial';
      
      if (isActualThreat) {
        setThreats((prev) => [scanEntry, ...prev]);
      }

    } catch (error) {
      console.error('Analysis error:', error);
      alert('Failed to analyze image. Make sure the backend server is running on port 5000.');
    } finally {
      setAnalyzing(false);
    }
  };

  // Helper function to build attack vector string
  const buildAttackVector = (results: any): string => {
    const parts = [];
    
    if (results.resnet?.status) {
      parts.push(`ResNet: ${results.resnet.status}`);
    }
    if (results.yolo?.status) {
      parts.push(`YOLOv5: ${results.yolo.status}`);
    }
    if (results.autoencoder?.status) {
      parts.push(`Autoencoder: ${results.autoencoder.status}`);
    }
    
    return parts.join(' | ') || 'Multi-Model Analysis';
  };

  // Filter threats
  const filteredThreats = threats.filter((threat) => {
    const matchesSeverity = selectedSeverity === 'all' || threat.severity === selectedSeverity;
    const matchesStatus = selectedStatus === 'all' || threat.status === selectedStatus;
    return matchesSeverity && matchesStatus;
  });

  // Filter all scans
  const filteredScans = allScans.filter((scan) => {
    const matchesSeverity = selectedSeverity === 'all' || scan.severity === selectedSeverity;
    const matchesStatus = selectedStatus === 'all' || scan.status === selectedStatus;
    return matchesSeverity && matchesStatus;
  });

  // Determine which feed to show based on active tab
  const displayedItems = activeTab === 'threats' ? filteredThreats : filteredScans;

  // Calculate stats from REAL data only
  const stats = {
    total:    allScans.length,
    threats:  threats.length,
    clean:    allScans.filter(s => s.status === 'clean').length,
    critical: threats.filter(t => t.severity === 'critical').length,
    high:     threats.filter(t => t.severity === 'high').length,
    medium:   threats.filter(t => t.severity === 'medium').length,
    low:      threats.filter(t => t.severity === 'low').length,
    detected: threats.filter(t => t.status === 'detected').length,
  };

  // Timeline data — arithmetic bucketing, no string parsing
  const timelineData = Array.from({ length: 12 }, (_, i) => {
    const bucketStart = Date.now() - (11 - i) * 3_600_000;
    const bucketEnd   = bucketStart + 3_600_000;
    const label = new Date(bucketStart).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    const hourThreats = threats.filter(t => {
      const ts = parseLocalTS(t.timestamp).getTime();
      return ts >= bucketStart && ts < bucketEnd;
    });

    return {
      time:     label,
      detected: hourThreats.filter(t => t.status === 'detected').length,
      clean:    hourThreats.filter(t => t.status === 'clean').length,
    };
  });

  // FIXED: Vector distribution with SHORT, CLEAN labels
  const threatTypeCounts: Record<string, number> = {};
  threats.forEach(threat => {
    // Make attack names SHORT and readable
    let cleanType = threat.type;
    
    // Aggressive shortening
    if (cleanType.includes('Strong Digital Perturbation')) {
      cleanType = 'Strong Perturbation';
    } else if (cleanType.includes('Moderate Digital Perturbation')) {
      cleanType = 'Moderate Perturbation';
    } else if (cleanType.includes('Digital Perturbation')) {
      cleanType = 'Perturbation';
    } else if (cleanType.includes('FGSM/PGD-Style Attack')) {
      cleanType = 'FGSM/PGD';
    } else if (cleanType.includes('DeepFool/C&W Attack')) {
      cleanType = 'DeepFool/C&W';
    } else if (cleanType.includes('Physical Adversarial Patch')) {
      cleanType = 'Physical Patch';
    } else if (cleanType.includes('Object-Based Attack')) {
      cleanType = 'Object Attack';
    }
    
    threatTypeCounts[cleanType] = (threatTypeCounts[cleanType] || 0) + 1;
  });

  const vectorDistribution = Object.entries(threatTypeCounts)
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 5); // Top 5

  const COLORS = ['#ef4444', '#f97316', '#f59e0b', '#10b981', '#3b82f6'];

  const getSeverityBadge = (severity: string) => {
    const severityStyles = {
      critical: 'border-red-500 text-red-400 bg-red-500/10',
      high: 'border-orange-500 text-orange-400 bg-orange-500/10',
      medium: 'border-yellow-500 text-yellow-400 bg-yellow-500/10',
      low: 'border-blue-500 text-blue-400 bg-blue-500/10',
    };
    return severityStyles[severity as keyof typeof severityStyles] || '';
  };

  const getStatusBadge = (status: string) => {
    const statusStyles = {
      detected:  'border-red-500 text-red-400 bg-red-500/10',
      clean:     'border-green-500 text-green-400 bg-green-500/10',
      monitoring:'border-blue-500 text-blue-400 bg-blue-500/10',
    };
    return statusStyles[status as keyof typeof statusStyles] || '';
  };

  const formatTimestamp = (timestamp: Date | string) => {
    const ts = parseLocalTS(timestamp);
    const now = new Date();
    const diff = Math.floor((now.getTime() - ts.getTime()) / 1000);
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return ts.toLocaleString();
  };

  // FIXED: Function to analyze another threat (clears current scan)
  const analyzeAnother = () => {
    setUploadedImage(null);
    setImagePreview(null);
    setCurrentScanResult(null);
    setIsolationInfo(null);
    const fileInput = document.getElementById('image-upload') as HTMLInputElement;
    if (fileInput) fileInput.value = '';
  };

  // Release an isolated file so it can be analyzed again
  const releaseIsolation = async () => {
    if (!isolationInfo) return;
    setReleasingIsolation(true);
    try {
      const res = await fetch(
        `${ARE_BASE}/isolations/by-filename/${encodeURIComponent(isolationInfo.filename)}`,
        { method: 'DELETE' }
      );
      if (res.ok) {
        setIsolationInfo(null);
        // Now load the preview since it's released
        if (uploadedImage) {
          const reader = new FileReader();
          reader.onloadend = () => setImagePreview(reader.result as string);
          reader.readAsDataURL(uploadedImage);
        }
      } else {
        alert('Failed to release isolation. Please try again.');
      }
    } catch {
      alert('Could not reach ARE backend. Make sure it is running on port 8000.');
    } finally {
      setReleasingIsolation(false);
    }
  };

  return (
    <div className="p-6 space-y-6 bg-gradient-to-br from-background via-card to-background min-h-screen">

      {/* ── ESCALATION ALERT MODAL ── */}
      {escalationAlert && (
        <>
          {/* backdrop */}
          <div
            className="fixed inset-0 z-50"
            style={{ backgroundColor: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(6px)' }}
          />
          {/* modal */}
          <div
            className="fixed z-50"
            style={{ left: '50%', top: '50%', transform: 'translate(-50%, -50%)', width: '100%', maxWidth: '480px', padding: '0 16px' }}
          >
            <div style={{
              background: 'linear-gradient(135deg, rgba(20,0,0,0.97) 0%, rgba(40,5,5,0.97) 100%)',
              border: '1px solid rgba(239,68,68,0.5)',
              borderRadius: '18px',
              padding: '32px 28px',
              boxShadow: '0 0 60px rgba(239,68,68,0.25), 0 30px 80px rgba(0,0,0,0.9)',
              color: 'white',
            }}>
              {/* Pulsing warning icon */}
              <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '20px' }}>
                <div style={{
                  width: '72px', height: '72px', borderRadius: '50%',
                  background: 'rgba(239,68,68,0.15)',
                  border: '2px solid rgba(239,68,68,0.6)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  animation: 'pulse 1.5s infinite',
                }}>
                  <AlertTriangle className="w-8 h-8 text-red-400" />
                </div>
              </div>

              <h2 style={{ textAlign: 'center', fontSize: '1.3rem', fontWeight: 700, color: '#f87171', marginBottom: '6px' }}>
                ⚠ ESCALATION TRIGGERED
              </h2>
              <p style={{ textAlign: 'center', fontSize: '0.8rem', color: 'rgba(255,255,255,0.45)', marginBottom: '24px' }}>
                This threat requires immediate human review
              </p>

              {/* Details */}
              <div style={{
                background: 'rgba(239,68,68,0.08)',
                border: '1px solid rgba(239,68,68,0.2)',
                borderRadius: '12px',
                padding: '16px',
                display: 'flex', flexDirection: 'column', gap: '10px',
                marginBottom: '24px',
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.45)' }}>File</span>
                  <span style={{ fontSize: '0.8rem', fontWeight: 600, color: '#fff', fontFamily: 'monospace' }}>
                    {escalationAlert.filename}
                  </span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.45)' }}>Severity</span>
                  <span style={{
                    fontSize: '0.75rem', fontWeight: 700, padding: '2px 10px', borderRadius: '999px',
                    background: 'rgba(239,68,68,0.2)', color: '#f87171', textTransform: 'uppercase', letterSpacing: '0.05em',
                  }}>
                    {escalationAlert.severity}
                  </span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.45)' }}>Confidence</span>
                  <span style={{ fontSize: '0.8rem', fontWeight: 600, color: '#fca5a5' }}>
                    {(escalationAlert.confidence * 100).toFixed(1)}%
                  </span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                  <span style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.45)' }}>Policy</span>
                  <span style={{ fontSize: '0.72rem', color: 'rgba(255,255,255,0.7)', lineHeight: 1.4, wordBreak: 'break-word' }}>
                    {escalationAlert.policy_name}
                  </span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.45)' }}>Threat ID</span>
                  <span style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.5)', fontFamily: 'monospace' }}>
                    {escalationAlert.threat_id}
                  </span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.45)' }}>Escalated at</span>
                  <span style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.5)' }}>
                    {parseLocalTS(escalationAlert.timestamp).toLocaleString()}
                  </span>
                </div>
              </div>

              <p style={{ fontSize: '0.78rem', color: 'rgba(255,255,255,0.4)', textAlign: 'center', marginBottom: '20px', lineHeight: 1.6 }}>
                The Autonomous Response Engine has flagged this for manual assessment. Review the threat in the ARE Actions Log and decide on further action.
              </p>

              {/* Acknowledge button */}
              <button
                onClick={() => setEscalationAlert(null)}
                style={{
                  width: '100%', padding: '11px', borderRadius: '10px',
                  background: 'rgba(239,68,68,0.85)', border: 'none',
                  color: '#fff', fontWeight: 700, fontSize: '0.9rem',
                  cursor: 'pointer', letterSpacing: '0.03em',
                }}
              >
                Acknowledge &amp; Dismiss
              </button>
            </div>
          </div>
        </>
      )}
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground mb-2">Threat Detection System</h1>
          <p className="text-muted-foreground">
            Real-time adversarial attack detection and mitigation
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Badge
            variant="outline"
            className={cn(
              'px-3 py-1.5 font-medium',
              backendStatus === 'connected'
                ? 'border-green-500 text-green-400 bg-green-500/10'
                : backendStatus === 'disconnected'
                ? 'border-red-500 text-red-400 bg-red-500/10'
                : 'border-yellow-500 text-yellow-400 bg-yellow-500/10'
            )}
          >
            <div className={cn(
              'w-2 h-2 rounded-full mr-2',
              backendStatus === 'connected' ? 'bg-green-500' :
              backendStatus === 'disconnected' ? 'bg-red-500' : 'bg-yellow-500'
            )} />
            {backendStatus === 'connected' ? 'Backend Online' :
             backendStatus === 'disconnected' ? 'Backend Offline' : 'Checking...'}
          </Badge>
          
          {/* Clear History Button */}
          {(threats.length > 0 || allScans.length > 0) && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                if (confirm('Are you sure you want to clear all scan history?')) {
                  setThreats([]);
                  setAllScans([]);
                  localStorage.removeItem('phantomnet_threats');
                  localStorage.removeItem('phantomnet_all_scans');
                }
              }}
              className="border-input text-muted-foreground hover:text-foreground hover:bg-muted hover:border-red-600"
            >
              <XCircle className="w-4 h-4 mr-2" />
              Clear History
            </Button>
          )}
        </div>
      </div>

      {/* DB sync indicator — shown only on first load before DB responds */}
      {!dbSynced && (
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg border border-blue-500/20 bg-blue-500/5 text-blue-400 text-xs w-fit">
          <Loader2 className="w-3 h-3 animate-spin" />
          Syncing scan history from database…
        </div>
      )}

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <Card className="bg-card border-border hover:border-border transition-colors">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Total Scans</p>
                <h3 className="text-2xl font-bold text-foreground mt-1">{stats.total}</h3>
              </div>
              <div className="p-3 bg-blue-500/10 rounded-lg">
                <Activity className="w-6 h-6 text-blue-500" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card border-border hover:border-red-900/50 transition-colors">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Threats</p>
                <h3 className="text-2xl font-bold text-red-400 mt-1">{stats.threats}</h3>
              </div>
              <div className="p-3 bg-red-500/10 rounded-lg">
                <ShieldAlert className="w-6 h-6 text-red-500" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card border-border hover:border-green-900/50 transition-colors">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Clean</p>
                <h3 className="text-2xl font-bold text-green-400 mt-1">{stats.clean}</h3>
              </div>
              <div className="p-3 bg-green-500/10 rounded-lg">
                <CheckCircle className="w-6 h-6 text-green-500" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card border-border hover:border-orange-900/50 transition-colors">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Critical</p>
                <h3 className="text-2xl font-bold text-orange-400 mt-1">{stats.critical}</h3>
              </div>
              <div className="p-3 bg-orange-500/10 rounded-lg">
                <AlertTriangle className="w-6 h-6 text-orange-500" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card border-border hover:border-yellow-900/50 transition-colors">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">High</p>
                <h3 className="text-2xl font-bold text-yellow-400 mt-1">{stats.high}</h3>
              </div>
              <div className="p-3 bg-yellow-500/10 rounded-lg">
                <AlertCircle className="w-6 h-6 text-yellow-500" />
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Image Upload & Analysis */}
        <div className="lg:col-span-1 space-y-6">
          <Card className="bg-card border-border">
            <CardHeader>
              <CardTitle className="text-foreground flex items-center gap-2">
                <Upload className="w-5 h-5 text-blue-500" />
                Upload & Analyze
              </CardTitle>
              <CardDescription className="text-muted-foreground">
                Upload an image to detect adversarial attacks
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="border-2 border-dashed border-border rounded-lg p-8 text-center hover:border-input transition-colors">
                {/* ISOLATION LOCKED STATE */}
                {isolationInfo ? (
                  <div className="space-y-3">
                    <div className="flex items-center justify-center w-16 h-16 mx-auto rounded-full bg-red-500/10 border border-red-500/30">
                      <Lock className="w-8 h-8 text-red-400" />
                    </div>
                    <div>
                      <p className="text-red-400 font-semibold text-sm">File Isolated</p>
                      <p className="text-foreground/80 font-mono text-xs mt-1 break-all">{isolationInfo.filename}</p>
                    </div>
                    <div className="bg-red-950/40 border border-red-800/40 rounded-lg p-3 text-left space-y-1">
                      <p className="text-xs text-muted-foreground">
                        <span className="text-foreground/80 font-medium">Policy:</span> {isolationInfo.policy_name}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        <span className="text-foreground/80 font-medium">Isolated at:</span>{' '}
                        {new Date(isolationInfo.isolated_at).toLocaleString()}
                      </p>
                      <p className="text-xs text-red-400 mt-2">
                        This file was isolated by the Autonomous Response Engine and cannot be analyzed until released.
                      </p>
                    </div>
                  </div>
                ) : imagePreview ? (
                  <div className="space-y-3">
                    <img
                      src={imagePreview}
                      alt="Preview"
                      className="max-w-full max-h-64 mx-auto rounded-lg"
                    />
                    <p className="text-sm text-muted-foreground break-all leading-snug px-2">
                      {uploadedImage?.name}
                    </p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    <ImageIcon className="w-12 h-12 text-slate-600 mx-auto" />
                    <p className="text-muted-foreground">Click to upload an image</p>
                    <p className="text-xs text-muted-foreground/70">JPG, PNG, JPEG</p>
                  </div>
                )}
                <Input
                  id="image-upload"
                  type="file"
                  accept="image/*"
                  className="hidden"
                  onChange={handleImageUpload}
                />
                {!isolationInfo && (
                  <Button
                    variant="outline"
                    className="mt-4 border-input text-foreground/80 hover:text-foreground hover:bg-muted"
                    onClick={() => document.getElementById('image-upload')?.click()}
                    type="button"
                  >
                    {imagePreview ? 'Change Image' : 'Select Image'}
                  </Button>
                )}
              </div>

              {/* ISOLATED: show Release button (analyst only) or locked notice */}
              {isolationInfo ? (
                canRelease ? (
                  <Button
                    onClick={releaseIsolation}
                    disabled={releasingIsolation}
                    className="w-full bg-red-700 hover:bg-red-600 text-foreground"
                  >
                    {releasingIsolation ? (
                      <>
                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                        Releasing...
                      </>
                    ) : (
                      <>
                        <Unlock className="w-4 h-4 mr-2" />
                        Release Isolation
                      </>
                    )}
                  </Button>
                ) : (
                  <div className="w-full flex items-center justify-center gap-2 py-2 px-4 rounded-lg border border-red-800/40 bg-red-950/20 text-red-400 text-sm font-medium">
                    <Lock className="w-4 h-4" />
                    Only a Security Analyst can release this isolation
                  </div>
                )
              ) : (
                <Button
                  onClick={analyzeImage}
                  disabled={!uploadedImage || analyzing || backendStatus !== 'connected'}
                  className="w-full bg-blue-600 hover:bg-blue-700 text-foreground disabled:opacity-50"
                >
                  {analyzing ? (
                    <>
                      <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                      Analyzing...
                    </>
                  ) : (
                    <>
                      <Activity className="w-4 h-4 mr-2" />
                      Analyze Image
                    </>
                  )}
                </Button>
              )}

              {/* FIXED: Show button to analyze another ONLY when current scan exists */}
              {currentScanResult && (
                <Button
                  onClick={analyzeAnother}
                  variant="outline"
                  className="w-full border-input text-foreground/80 hover:text-foreground hover:bg-muted"
                >
                  <RefreshCw className="w-4 h-4 mr-2" />
                  Analyze Another Image
                </Button>
              )}
            </CardContent>
          </Card>

          {/* FIXED: Current Scan Results - PERSISTS */}
          {currentScanResult && (
            <Card className="bg-card border-border">
              <CardHeader>
                <CardTitle className="text-foreground flex items-center gap-2">
                  <Activity className="w-5 h-5 text-green-500" />
                  Current Scan Results
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-4 rounded-lg bg-muted/50 border border-border">
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Decision:</span>
                      <Badge
                        variant="outline"
                        className={
                          currentScanResult.ensemble.final_decision === 'adversarial'
                            ? 'border-red-500 text-red-400 bg-red-500/10'
                            : 'border-green-500 text-green-400 bg-green-500/10'
                        }
                      >
                        {currentScanResult.ensemble.final_decision.toUpperCase()}
                      </Badge>
                    </div>

                    {/* NEW: Attack Category */}
                    {currentScanResult.threat_data.category && currentScanResult.threat_data.category !== 'None' && (
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-muted-foreground">Attack Category:</span>
                        <Badge 
                          variant="outline" 
                          className="border-purple-500 text-purple-400 bg-purple-500/10"
                        >
                          {currentScanResult.threat_data.category}
                        </Badge>
                      </div>
                    )}

                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Severity:</span>
                      <Badge variant="outline" className={getSeverityBadge(currentScanResult.threat_data.severity)}>
                        {currentScanResult.threat_data.severity.toUpperCase()}
                      </Badge>
                    </div>

                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Confidence:</span>
                      <span className="text-sm font-medium text-foreground">
                        {(currentScanResult.ensemble.confidence * 100).toFixed(1)}%
                      </span>
                    </div>

                    <div className="pt-2 border-t border-border">
                      <span className="text-sm text-muted-foreground block mb-1">Attack Type:</span>
                      <span className="text-sm font-medium text-foreground break-words">
                        {currentScanResult.threat_data.type}
                      </span>
                    </div>

                    {/* NEW: Attack Characteristics */}
                    {currentScanResult.threat_data.characteristics && currentScanResult.threat_data.characteristics.length > 0 && (
                      <div className="pt-3 border-t border-border">
                        <p className="text-xs text-muted-foreground mb-2">Characteristics:</p>
                        <div className="space-y-1">
                          {currentScanResult.threat_data.characteristics.map((char: string, idx: number) => (
                            <div key={idx} className="flex items-start gap-2">
                              <span className="text-purple-400 mt-0.5">•</span>
                              <span className="text-xs text-foreground/80">{char}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* NEW: Primary Indicator */}
                    {currentScanResult.threat_data.primary_indicator && (
                      <div className="pt-2">
                        <p className="text-xs text-muted-foreground/70 italic">
                          Primary indicator: {currentScanResult.threat_data.primary_indicator}
                        </p>
                      </div>
                    )}

                    <div className="pt-3 border-t border-border">
                      <p className="text-xs text-muted-foreground mb-2">Model Votes:</p>
                      <div className="space-y-1.5">
                        {currentScanResult.individual_results.resnet && (
                          <div className="flex items-center justify-between text-xs">
                            <span className="text-muted-foreground">ResNet-50:</span>
                            <span className={currentScanResult.individual_results.resnet.is_adversarial ? 'text-red-400' : 'text-green-400'}>
                              {currentScanResult.individual_results.resnet.status}
                            </span>
                          </div>
                        )}
                        {currentScanResult.individual_results.yolo && (
                          <div className="flex items-center justify-between text-xs">
                            <span className="text-muted-foreground">YOLOv5:</span>
                            <span className={currentScanResult.individual_results.yolo.is_adversarial ? 'text-red-400' : 'text-green-400'}>
                              {currentScanResult.individual_results.yolo.status || 'N/A'}
                            </span>
                          </div>
                        )}
                        {currentScanResult.individual_results.autoencoder && (
                          <div className="flex items-center justify-between text-xs">
                            <span className="text-muted-foreground">Autoencoder:</span>
                            <span className={currentScanResult.individual_results.autoencoder.is_adversarial ? 'text-red-400' : 'text-green-400'}>
                              {currentScanResult.individual_results.autoencoder.status}
                            </span>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </div>

        {/* Charts and Feed */}
        <div className="lg:col-span-2 space-y-6">
          {/* Filters */}
          <Card className="bg-card border-border">
            <CardContent className="pt-6">
              <div className="flex flex-wrap gap-4">
                <div className="flex gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setSelectedSeverity('all')}
                    className={cn(
                      'border-input',
                      selectedSeverity === 'all'
                        ? 'bg-blue-600 text-foreground border-blue-600'
                        : 'text-foreground/80 hover:text-foreground hover:bg-muted'
                    )}
                  >
                    All
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setSelectedSeverity('critical')}
                    className={cn(
                      'border-input',
                      selectedSeverity === 'critical'
                        ? 'bg-red-600 text-foreground border-red-600'
                        : 'text-foreground/80 hover:text-foreground hover:bg-muted'
                    )}
                  >
                    Critical
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setSelectedSeverity('high')}
                    className={cn(
                      'border-input',
                      selectedSeverity === 'high'
                        ? 'bg-orange-600 text-foreground border-orange-600'
                        : 'text-foreground/80 hover:text-foreground hover:bg-muted'
                    )}
                  >
                    High
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Charts Row */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Timeline */}
            <Card className="bg-card border-border">
              <CardHeader>
                <CardTitle className="text-foreground flex items-center gap-2">
                  <Clock className="w-5 h-5 text-blue-500" />
                  Threat Timeline
                </CardTitle>
                <CardDescription className="text-muted-foreground">
                  Last 12 hours
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={250}>
                  <LineChart data={timelineData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                    <XAxis dataKey="time" stroke="#64748b" fontSize={12} />
                    <YAxis stroke="#64748b" fontSize={12} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#1e293b',
                        border: '1px solid #334155',
                        borderRadius: '8px',
                      }}
                      labelStyle={{ color: '#e2e8f0' }}
                    />
                    <Legend />
                    <Line
                      type="monotone"
                      dataKey="detected"
                      stroke="#ef4444"
                      strokeWidth={2}
                      dot={{ fill: '#ef4444', r: 3 }}
                      name="Detected"
                    />
                  </LineChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            {/* Attack Distribution */}
            <Card className="bg-card border-border">
              <CardHeader>
                <CardTitle className="text-foreground flex items-center gap-2">
                  <Target className="w-5 h-5 text-purple-500" />
                  Attack Distribution
                </CardTitle>
                <CardDescription className="text-muted-foreground">
                  Top attack types
                </CardDescription>
              </CardHeader>
              <CardContent>
                {vectorDistribution.length > 0 ? (
                  <ResponsiveContainer width="100%" height={250}>
                    <PieChart>
                      <Pie
                        data={vectorDistribution}
                        cx="50%"
                        cy="50%"
                        labelLine={false}
                        outerRadius={80}
                        dataKey="value"
                      >
                        {vectorDistribution.map((_entry, index) => (
                          <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
                        formatter={(value: number, name: string) => {
                          const idx = vectorDistribution.findIndex(d => d.name === name);
                          const col = COLORS[idx % COLORS.length];
                          const total = vectorDistribution.reduce((s, d) => s + d.value, 0);
                          return [
                            <span style={{ color: col }}>{value} ({((value / total) * 100).toFixed(0)}%)</span>,
                            <span style={{ color: col }}>{name}</span>,
                          ];
                        }}
                      />
                      <Legend
                        content={({ payload }) => {
                          const total = vectorDistribution.reduce((s, d) => s + d.value, 0);
                          return (
                            <div style={{ display: 'flex', justifyContent: 'center', flexWrap: 'wrap', gap: '12px', marginTop: '10px' }}>
                              {payload?.map((entry: any, i: number) => {
                                const item = vectorDistribution.find(d => d.name === entry.value);
                                const pct = item ? ((item.value / total) * 100).toFixed(0) : '0';
                                return (
                                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                                    <div style={{ width: 9, height: 9, borderRadius: 2, background: entry.color, flexShrink: 0 }} />
                                    <span style={{ fontSize: '0.7rem', color: '#94a3b8' }}>{entry.value}</span>
                                    <span style={{ fontSize: '0.7rem', color: entry.color, fontWeight: 600 }}>{pct}%</span>
                                  </div>
                                );
                              })}
                            </div>
                          );
                        }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex items-center justify-center h-[250px]">
                    <p className="text-muted-foreground/70 text-sm">No data yet</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* FIXED: Tabbed Feed - Threats Only vs All Scans */}
          <Card className="bg-card border-border">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Zap className="w-5 h-5 text-yellow-500" />
                  <CardTitle className="text-foreground">
                    {activeTab === 'threats' ? 'Detected Threats Feed' : 'All Scans History'}
                  </CardTitle>
                </div>
                <div className="flex gap-2">
                  <Button
                    variant={activeTab === 'threats' ? 'default' : 'outline'}
                    size="sm"
                    onClick={() => setActiveTab('threats')}
                    className={cn(
                      activeTab === 'threats'
                        ? 'bg-red-600 text-foreground hover:bg-red-700'
                        : 'border-input text-foreground/80 hover:text-foreground hover:bg-muted'
                    )}
                  >
                    <ShieldAlert className="w-4 h-4 mr-2" />
                    Threats Only ({threats.length})
                  </Button>
                  <Button
                    variant={activeTab === 'all' ? 'default' : 'outline'}
                    size="sm"
                    onClick={() => setActiveTab('all')}
                    className={cn(
                      activeTab === 'all'
                        ? 'bg-blue-600 text-foreground hover:bg-blue-700'
                        : 'border-input text-foreground/80 hover:text-foreground hover:bg-muted'
                    )}
                  >
                    <Activity className="w-4 h-4 mr-2" />
                    All Scans ({allScans.length})
                  </Button>
                </div>
              </div>
              <CardDescription className="text-muted-foreground">
                {activeTab === 'threats' 
                  ? `Showing ${filteredThreats.length} detected threat${filteredThreats.length !== 1 ? 's' : ''}`
                  : `Showing ${filteredScans.length} scan${filteredScans.length !== 1 ? 's' : ''} (clean + adversarial)`
                }
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3 max-h-[600px] overflow-y-auto no-scrollbar">
                {displayedItems.length === 0 ? (
                  <div className="text-center py-12">
                    <Shield className="w-12 h-12 text-slate-600 mx-auto mb-3" />
                    <p className="text-muted-foreground">
                      {activeTab === 'threats' 
                        ? 'No threats detected yet' 
                        : 'No scans performed yet'
                      }
                    </p>
                    <p className="text-sm text-muted-foreground/70 mt-2">
                      Upload and analyze images to {activeTab === 'threats' ? 'detect adversarial attacks' : 'see scan history'}
                    </p>
                  </div>
                ) : (
                  displayedItems.map((item) => (
                    <div
                      key={item.id}
                      className="p-4 rounded-lg bg-muted/50 border border-border hover:border-input transition-all hover:bg-muted/70"
                    >
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1 space-y-3">
                          <div className="flex items-center gap-3 flex-wrap">
                            <span className="font-mono text-sm font-bold text-foreground/80">
                              {item.id}
                            </span>
                            <Badge
                              variant="outline"
                              className={getSeverityBadge(item.severity)}
                            >
                              {item.severity.toUpperCase()}
                            </Badge>
                            <Badge variant="outline" className={getStatusBadge(item.status)}>
                              {item.status.toUpperCase()}
                            </Badge>
                            <span className="text-xs text-muted-foreground/70 flex items-center gap-1">
                              <Clock className="w-3 h-3" />
                              {formatTimestamp(item.timestamp)}
                            </span>
                          </div>

                          <div>
                            <h3 className="text-foreground font-semibold text-lg">{item.type}</h3>
                            
                            {/* NEW: Attack Category Badge - Only show for adversarial */}
                            {item.category && item.category !== 'None' && item.category !== 'Unknown' && (
                              <div className="mt-2">
                                <Badge 
                                  variant="outline" 
                                  className="border-purple-500 text-purple-400 bg-purple-500/10 text-xs"
                                >
                                  {item.category}
                                </Badge>
                              </div>
                            )}
                            
                            <p className="text-sm text-muted-foreground mt-1">
                              <span className="font-medium text-foreground/80">Target Model:</span>{' '}
                              {item.modelTarget}
                            </p>
                            <p className="text-sm text-muted-foreground mt-1">
                              <span className="font-medium text-foreground/80">Detection:</span>{' '}
                              {item.attackVector}
                            </p>
                          </div>

                          <div className="flex items-center gap-4">
                            <div className="flex items-center gap-2">
                              <span className="text-sm text-muted-foreground">Confidence:</span>
                              <div className="flex items-center gap-2">
                                <div className="w-24 h-2 bg-muted rounded-full overflow-hidden">
                                  <div
                                    className={cn(
                                      'h-full rounded-full transition-all',
                                      item.confidence >= 0.9
                                        ? 'bg-red-500'
                                        : item.confidence >= 0.7
                                        ? 'bg-orange-500'
                                        : 'bg-yellow-500'
                                    )}
                                    style={{ width: `${item.confidence * 100}%` }}
                                  />
                                </div>
                                <span className="text-sm font-medium text-foreground">
                                  {(item.confidence * 100).toFixed(1)}%
                                </span>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}