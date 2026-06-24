/**
 * XAI Explainability Engine – xai-engine.tsx
 * PhantomNet++ · Module 3: XAI
 *
 * Reads real scan results from localStorage (written by threat-detection.tsx)
 * and calls the XAI backend (port 5001) to generate Grad-CAM / LIME / SHAP
 * explanations for the exact same image the user uploaded in the detector.
 */

import { useState, useEffect } from 'react';
import {
  Card, CardContent, CardDescription, CardHeader, CardTitle,
} from '@/components/ui/card';
import { Button }   from '@/components/ui/button';
import { Badge }    from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import {
  Download, Eye, Clock, AlertTriangle, CheckCircle,
  Shield, Zap, RefreshCw, Loader2, ServerCrash, Info,
} from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Cell,
} from 'recharts';

// ─── Constants ────────────────────────────────────────────────────────────────
const DEFAULT_XAI_URL = 'http://localhost:5001';
function getXaiUrl() {
  return localStorage.getItem('xai_backend_url') || DEFAULT_XAI_URL;
}

type Method = 'GradCAM' | 'LIME' | 'SHAP';

// ─── Types ────────────────────────────────────────────────────────────────────
interface ScanRecord {
  id: string;
  timestamp: string | Date;
  type: string;
  severity: string;
  status: string;
  confidence: number;
  modelTarget: string;
  attackVector: string;
  category?: string;
  characteristics?: string[];
  primaryIndicator?: string;
  // The raw image file is stored separately via the fileRef trick
}

interface ExplanationResult {
  id: string;
  scan_id: string;
  timestamp: string;
  method: string;
  prediction: string;
  confidence: number;
  attack_type: string;
  severity: string;
  is_adversarial: boolean;
  original_image: string;      // base64
  explanation_image: string;   // base64
  features: { name: string; importance: number }[];
  description: string;
}

interface HistoryEntry {
  id: string;
  scan_id: string;
  timestamp: string;
  method: string;
  prediction: string;
  confidence: number;
  attack_type: string;
  severity: string;
  is_adversarial: boolean;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function confidenceColor(c: number) {
  return c >= 0.8 ? '#ef4444' : c >= 0.5 ? '#f59e0b' : '#10b981';
}

function fmt(ts: string | Date) {
  const raw = typeof ts === 'string' ? ts : ts.toISOString();
  // Normalize SQLite space separator → T so new Date() parses the +05:00 offset correctly
  const d = new Date(raw.replace(/^(\d{4}-\d{2}-\d{2}) /, '$1T'));
  if (isNaN(d.getTime())) return String(raw);
  // Always display in Pakistan Standard Time (UTC+5)
  return d.toLocaleString('en-GB', {
    timeZone: 'Asia/Karachi',
    day: '2-digit', month: 'short',
    hour: '2-digit', minute: '2-digit',
    hour12: false,
  }).replace(',', '');
}

// Bar chart colour gradient: blue → teal → green
const BAR_COLORS = [
  '#3b82f6','#06b6d4','#10b981','#84cc16','#eab308','#f97316','#ef4444','#a855f7',
];

// ─── Method descriptions (shown before generating) ───────────────────────────
const METHOD_META: Record<Method, { title: string; description: string; note: string }> = {
  GradCAM: {
    title:       'Gradient-weighted Class Activation Mapping',
    description: 'Grad-CAM computes the gradient of the target class score with respect to the final convolutional layer activations. The resulting heatmap highlights image regions most responsible for the ResNet-50 prediction.',
    note:        'Powered by ResNet-50 · layer4 target layer',
  },
  LIME: {
    title:       'Local Interpretable Model-agnostic Explanations',
    description: "LIME segments the image into superpixels, then samples random masks to measure how each superpixel affects the model's confidence. Brighter regions in the overlay contributed more to the prediction.",
    note:        'Powered by ResNet-50 · 16 segments · 60 samples',
  },
  SHAP: {
    title:       'SHapley Additive exPlanations (Autoencoder Proxy)',
    description: "Each image patch is masked and re-encoded. The shift in the autoencoder's latent representation measures how much that patch contributed to the reconstruction anomaly - the main signal used in adversarial detection.",
    note:        'Powered by Trained Autoencoder · 16 patches',
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// COMPONENT
// ─────────────────────────────────────────────────────────────────────────────
export default function XAIEngine() {
  // ── State ──────────────────────────────────────────────────────────────────
  const [scans,           setScans]           = useState<ScanRecord[]>([]);
  const [backendUrl,      setBackendUrl]       = useState<string>(
    () => localStorage.getItem('xai_backend_url') || DEFAULT_XAI_URL
  );
  const [showUrlInput,    setShowUrlInput]     = useState(false);
  const [selectedScan,    setSelectedScan]     = useState<ScanRecord | null>(null);
  const [activeMethod,    setActiveMethod]     = useState<Method>('GradCAM');
  const [result,          setResult]           = useState<ExplanationResult | null>(null);
  // Keyed by scanId → method → result, persists across scan switches
  const [allResultsMap,   setAllResultsMap]     = useState<Record<string, Partial<Record<string, ExplanationResult>>>>({});
  // resultsMap for current scan — used by PDF export
  const resultsMap = selectedScan ? (allResultsMap[selectedScan.id] ?? {}) : {};
  const [pdfLoading,      setPdfLoading]        = useState(false);
  const [loading,         setLoading]          = useState(false);
  const [backendOk,       setBackendOk]        = useState<boolean | null>(null);
  const [history,         setHistory]          = useState<HistoryEntry[]>([]);

  // ── Load scans: DB (full history) merged with localStorage (current session) ─
  useEffect(() => {
    const load = async () => {
      let merged: ScanRecord[] = [];

      // 1. Fetch full history from threat detection DB
      try {
        const res = await fetch('http://localhost:5000/api/predictions?limit=100');
        if (res.ok) {
          const data = await res.json();
          merged = (data.predictions ?? []).map((p: any) => ({
            id:               p.threat_id,
            timestamp:        p.timestamp,
            // DB stores these as flat columns, not nested under threat_data
            type:             p.attack_type      ?? 'Unknown',
            severity:         p.severity         ?? 'low',
            status:           p.final_decision   === 'adversarial' ? 'detected' : 'clean',
            confidence:       p.confidence       ?? 0,
            modelTarget:      'Multi-Model Analysis',
            attackVector:     p.attack_category  ?? 'Unknown',
            category:         p.attack_category,
            characteristics:  p.characteristics,
            primaryIndicator: p.primary_indicator,
          }));
        }
      } catch (_) {}

      // 2. Merge with localStorage scans — keeps image file refs for current session
      try {
        const raw = localStorage.getItem('phantomnet_all_scans');
        if (raw) {
          const lsScans: ScanRecord[] = JSON.parse(raw);
          const dbIds = new Set(merged.map(s => s.id));
          // Prepend localStorage-only scans (they have the image file ref)
          merged = [...lsScans.filter(s => !dbIds.has(s.id)), ...merged];
        }
      } catch (_) {}

      if (merged.length > 0) {
        setScans(merged);
        setSelectedScan(prev => prev ?? merged[0]);
      }
    };

    load();
    const iv = setInterval(load, 5000);
    return () => clearInterval(iv);
  }, []);

  // ── Health check — re-runs whenever backendUrl changes ──────────────────────
  useEffect(() => {
    setBackendOk(null);
    const url = backendUrl || DEFAULT_XAI_URL;
    fetch(`${url}/api/xai/health`, {
      headers: { 'ngrok-skip-browser-warning': 'true' },
    })
      .then(r => r.ok ? r.json() : Promise.reject('not ok'))
      .then(d => setBackendOk(d?.status === 'healthy' || d?.status === 'ok'))
      .catch(() => setBackendOk(false));
  }, [backendUrl]);

  // ── Load history from XAI backend ───────────────────────────────────────────
  // ── Save backend URL (switches between localhost and Colab) ───────────────
  const saveBackendUrl = (url: string) => {
    const clean = url.trim().replace(/\/$/, '');
    localStorage.setItem('xai_backend_url', clean);
    setBackendUrl(clean);
    setShowUrlInput(false);
    setBackendOk(null);
    // Re-check health with new URL
    setBackendOk(null);
    fetch(`${clean}/api/xai/health`, {
      headers: { 'ngrok-skip-browser-warning': 'true' },
    })
      .then(r => r.ok ? r.json() : Promise.reject('not ok'))
      .then(d => setBackendOk(d?.status === 'healthy' || d?.status === 'ok'))
      .catch(() => setBackendOk(false));
  };

  const refreshHistory = () => {
    fetch(`${getXaiUrl()}/api/xai/history?limit=20`, {
      headers: { 'ngrok-skip-browser-warning': 'true' },
    })
      .then(r => r.json())
      .then(d => setHistory(d.history ?? []))
      .catch(() => {});
  };
  useEffect(() => { refreshHistory(); }, []);

  // ── When scan changes, restore cached result for current method (if any) ──
  useEffect(() => {
    if (!selectedScan) { setResult(null); return; }
    const cached = allResultsMap[selectedScan.id]?.[activeMethod];
    setResult(cached ?? null);
  }, [selectedScan]);

  // ── When method changes, restore cached result for that method ──
  useEffect(() => {
    if (!selectedScan) { setResult(null); return; }
    const cached = allResultsMap[selectedScan.id]?.[activeMethod];
    setResult(cached ?? null);
  }, [activeMethod]);


  // ── Generate explanation ────────────────────────────────────────────────────
  const generate = async () => {
    if (!selectedScan) {
      alert('Please select a scan from the history.');
      return;
    }
    if (backendOk === null) {
      alert('Still checking backend status — please wait a moment and try again.');
      return;
    }
    if (backendOk === false) {
      alert('XAI backend is offline.\n\nIf using Colab: make sure Cell 3 is running and you have pasted the ngrok URL.\nIf using local: run python3 xai_backend.py in your backend folder.');
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      const fd = new FormData();

      if (selectedScan) {
        // Try to fetch image from the threat detection DB first (works for ALL historical scans)
        let imageBlob: Blob | null = null;
        try {
          const imgRes = await fetch(`http://localhost:5000/api/image/${selectedScan.id}`);
          if (imgRes.ok) {
            imageBlob = await imgRes.blob();
          }
        } catch (_) {}

        // Fallback to localStorage (current session only)
        if (!imageBlob) {
          const b64 = localStorage.getItem('phantomnet_last_image');
          if (b64) {
            const mime    = b64.split(';')[0].split(':')[1];
            const decoded = atob(b64.split(',')[1]);
            const arr     = new Uint8Array(decoded.length);
            for (let i = 0; i < decoded.length; i++) arr[i] = decoded.charCodeAt(i);
            imageBlob = new Blob([arr], { type: mime });
          }
        }

        if (!imageBlob) {
          alert(
            'No image found for this scan.\n\n' +
            'If this is an older scan, the image file may have been deleted from disk.\n' +
            'For recent scans, go to Threat Detection, re-upload the image, and run analysis again.'
          );
          setLoading(false);
          return;
        }
        fd.append('image', imageBlob, 'scan_image.jpg');
      }

      // Attach metadata from selected scan
      fd.append('method',         activeMethod.toLowerCase());
      fd.append('scan_id',        selectedScan?.id ?? '');
      fd.append('attack_type',    selectedScan?.type ?? 'Unknown');
      fd.append('severity',       selectedScan?.severity ?? 'unknown');
      fd.append('confidence',     String(selectedScan?.confidence ?? 0));
      fd.append('is_adversarial', selectedScan?.status === 'detected' ? 'true' : 'false');

      const resp = await fetch(`${getXaiUrl()}/api/xai/explain`, {
        method: 'POST',
        headers: { 'ngrok-skip-browser-warning': 'true' },
        body: fd,
      });

      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: resp.statusText }));
        throw new Error(err.detail ?? 'Explanation failed');
      }

      const data: ExplanationResult = await resp.json();
      setResult(data);
      // Store per scan+method so switching scans shows the right results
      setAllResultsMap(prev => ({
        ...prev,
        [selectedScan.id]: {
          ...(prev[selectedScan.id] ?? {}),
          [data.method]: data,
        },
      }));
      refreshHistory();
      // ── SIEM: log explanation generated ──────────────────────────────────
      fetch('http://localhost:8003/api/siem/log', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          severity:   data.is_adversarial ? 'Warning' : 'Info',
          source:     'XAI',
          event_type: 'ExplanationGenerated',
          message:    `${data.method} explanation generated — ${data.attack_type} (${(data.confidence * 100).toFixed(1)}% confidence)`,
          metadata:   { explanation_id: data.id, scan_id: data.scan_id, method: data.method, attack_type: data.attack_type, severity: data.severity, is_adversarial: data.is_adversarial, confidence: data.confidence },
        }),
      }).catch(() => {});
    } catch (e: any) {
      console.error(e);
      alert(`Explanation error: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  // ── Export ──────────────────────────────────────────────────────────────────
  const handleExport = () => {
    if (!result) return;
    const payload = {
      explanation_id:  result.id,
      scan_id:         result.scan_id,
      timestamp:       result.timestamp,
      method:          result.method,
      prediction:      result.prediction,
      confidence:      result.confidence,
      attack_type:     result.attack_type,
      severity:        result.severity,
      is_adversarial:  result.is_adversarial,
      top_features:    result.features,
      description:     result.description,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `xai_${result.id}_${result.method}.json`;
    a.click();
    URL.revokeObjectURL(url);
    // ── SIEM: log JSON report download ───────────────────────────────────
    fetch('http://localhost:8003/api/siem/log', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        severity: 'Info', source: 'XAI', event_type: 'ReportDownloaded',
        message: `XAI JSON report downloaded: ${result.id} (${result.method})`,
        metadata: { explanation_id: result.id, method: result.method, format: 'json' },
      }),
    }).catch(() => {});
  };

  // ── PDF Report — sends all collected method results to report_backend ───────
  const handlePdfReport = async () => {
    const available = Object.values(resultsMap);
    if (available.length === 0) {
      alert('Generate at least one explanation first, then download the PDF.');
      return;
    }
    setPdfLoading(true);
    // Use the most recent result as primary, include all collected visuals
    const primary = result ?? available[available.length - 1];
    try {
      const res = await fetch('http://localhost:8004/api/report/xai/pdf', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          explanation_id:    primary.id,
          scan_id:           primary.scan_id,
          timestamp:         primary.timestamp,
          method:            `${Object.keys(resultsMap).join(' + ')}`,
          prediction:        primary.prediction,
          confidence:        primary.confidence,
          attack_type:       primary.attack_type,
          severity:          primary.severity,
          is_adversarial:    primary.is_adversarial,
          description:       Object.values(resultsMap).map(r => `${r!.method}: ${r!.description}`).join(' | '),
          features:          primary.features,
          // All method visuals
          original_image:    primary.original_image,
          explanation_image: primary.explanation_image,
          gradcam_image:     resultsMap['GradCAM']?.explanation_image ?? null,
          lime_image:        resultsMap['LIME']?.explanation_image ?? null,
          shap_image:        resultsMap['SHAP']?.explanation_image ?? null,
          all_methods:       Object.values(resultsMap).map(r => ({
            method:            r!.method,
            description:       r!.description,
            features:          r!.features,
            explanation_image: r!.explanation_image,
            original_image:    r!.original_image,
          })),
        }),
      });
      if (!res.ok) throw new Error('Report backend error');
      const blob = await res.blob();
      const a = Object.assign(document.createElement('a'), {
        href: URL.createObjectURL(blob),
        download: `xai_report_${primary.scan_id}_${new Date().toISOString().slice(0,10)}.pdf`,
      });
      a.click();
      // SIEM log
      fetch('http://localhost:8003/api/siem/log', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          severity: 'Info', source: 'XAI', event_type: 'ReportDownloaded',
          message: `XAI PDF report downloaded for ${primary.attack_type} (methods: ${Object.keys(resultsMap).join(', ')})`,
          metadata: { scan_id: primary.scan_id, methods: Object.keys(resultsMap), format: 'pdf' },
        }),
      }).catch(() => {});
    } catch {
      alert('PDF generation failed. Make sure report_backend.py is running on port 8004.');
    } finally {
      setPdfLoading(false);
    }
  };

  // ─────────────────────────────────────────────────────────────────────────
  // RENDER
  // ─────────────────────────────────────────────────────────────────────────
  const methodMeta = METHOD_META[activeMethod];
  const currentConf = result?.confidence ?? selectedScan?.confidence ?? 0;

  return (
    <div className="p-6 space-y-6">

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="flex flex-wrap justify-between items-center gap-3">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">XAI Explainability Engine</h1>
          <p className="text-muted-foreground">Interpretable AI predictions and explanations</p>
        </div>
        <div className="flex items-center gap-3 flex-wrap justify-end">
          {/* Backend status pill */}
          <div className={`flex items-center gap-1.5 text-xs px-3 py-1 rounded-full border font-medium ${
            backendOk === true  ? 'border-green-500/40 text-green-400 bg-green-500/10' :
            backendOk === false ? 'border-red-500/40   text-red-400   bg-red-500/10'   :
                                  'border-yellow-500/40 text-yellow-400 bg-yellow-500/10'
          }`}>
            <span className={`w-2 h-2 rounded-full ${
              backendOk === true  ? 'bg-green-400 animate-pulse' :
              backendOk === false ? 'bg-red-400'                 : 'bg-yellow-400'
            }`} />
            {backendOk === true ? 'XAI Backend Online' :
             backendOk === false ? 'XAI Backend Offline' : 'Checking…'}
          </div>

          {/* Backend URL toggle button */}
          <Button variant="outline" size="sm" onClick={() => setShowUrlInput(v => !v)}>
            🌐 {backendUrl.includes('localhost') ? 'localhost:5001' : 'Colab'}
          </Button>

          <Button variant="outline" onClick={refreshHistory} size="sm">
            <RefreshCw className="h-4 w-4 mr-1" /> Refresh
          </Button>

          <Button onClick={handlePdfReport} disabled={Object.keys(resultsMap).length === 0 || pdfLoading} size="sm" variant="outline" style={{ borderColor: 'rgba(239,68,68,0.4)', color: '#ef4444' }}>
            <Download className="h-4 w-4 mr-1" /> {pdfLoading ? 'Generating...' : `PDF Report${Object.keys(resultsMap).length > 1 ? ` (${Object.keys(resultsMap).length} methods)` : ''}`}
          </Button>
          <Button onClick={handleExport} disabled={!result} size="sm">
            <Download className="h-4 w-4 mr-1" /> Export JSON
          </Button>
        </div>
      </div>

      {/* ── Backend URL input panel ──────────────────────────────────────────── */}
      {showUrlInput && (
        <div className="flex items-center gap-3 p-4 rounded-lg border border-primary/30 bg-primary/5">
          <div className="flex-1 space-y-1">
            <p className="text-sm font-medium">Backend URL</p>
            <p className="text-xs text-muted-foreground">
              Use <code className="bg-muted px-1 rounded">http://localhost:5001</code> for local,
              or paste your <strong>ngrok URL</strong> from Google Colab
            </p>
          </div>
          <input
            type="text"
            defaultValue={backendUrl}
            id="backend-url-input"
            placeholder="https://xxxx.ngrok-free.app"
            className="flex-1 px-3 py-2 text-sm rounded-md border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
          />
          <Button
            size="sm"
            onClick={() => {
              const val = (document.getElementById('backend-url-input') as HTMLInputElement)?.value;
              if (val) saveBackendUrl(val);
            }}
          >
            Save & Connect
          </Button>
          <Button size="sm" variant="outline" onClick={() => saveBackendUrl(DEFAULT_XAI_URL)}>
            Reset to Local
          </Button>
        </div>
      )}

      {/* ── Offline warning ─────────────────────────────────────────────────── */}
      {backendOk === false && (
        <div className="flex items-center gap-3 p-4 rounded-lg border border-red-500/30 bg-red-500/10 text-red-400">
          <ServerCrash className="h-5 w-5 shrink-0" />
          <div className="text-sm space-y-1">
            <p>XAI backend is offline at <code className="bg-red-900/40 px-1 rounded text-xs">{backendUrl}</code></p>
            <p className="text-xs">
              Local: run <code className="bg-red-900/40 px-1 rounded">python3 xai_backend.py</code> &nbsp;|&nbsp;
              Colab: open the notebook, run all cells, paste the ngrok URL above
            </p>
          </div>
        </div>
      )}

      {/* ── Main grid ───────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* ════════════ LEFT COLUMN ════════════ */}
        <div className="lg:col-span-1 space-y-4">

          {/* Scan History (from threat detection) */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-4 w-4" /> Scan History
              </CardTitle>
              <CardDescription>From Threat Detection module</CardDescription>
            </CardHeader>
            <CardContent className="space-y-2 max-h-72 overflow-y-auto pr-1 no-scrollbar">
              {scans.length === 0 ? (
                <div className="text-sm text-muted-foreground text-center py-6">
                  No scans yet. Run the Threat Detection module first.
                </div>
              ) : scans.map(scan => (
                <div
                  key={scan.id}
                  onClick={() => { setSelectedScan(scan); }}
                  className={`p-3 rounded-lg border cursor-pointer transition-colors hover:bg-muted/50 ${
                    selectedScan?.id === scan.id ? 'border-primary bg-muted' : 'border-border'
                  }`}
                >
                  <div className="flex justify-between items-start mb-1.5">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <Badge
                        variant={scan.status === 'detected' ? 'destructive' : 'default'}
                        className="text-[10px] h-4"
                      >
                        {scan.status === 'detected' ? 'THREAT' : 'CLEAN'}
                      </Badge>
                      <span className="text-[10px] text-muted-foreground font-mono">{scan.id}</span>
                    </div>
                    <Clock className="h-3 w-3 text-muted-foreground shrink-0" />
                  </div>
                  <div className="font-medium text-sm capitalize truncate">{scan.type}</div>
                  <div className="text-[11px] text-muted-foreground">{scan.category ?? scan.modelTarget}</div>
                  <div className="flex items-center gap-2 mt-1">
                    <Progress value={scan.confidence * 100} className="h-1 flex-1" />
                    <span className="text-[11px] font-semibold" style={{ color: confidenceColor(scan.confidence) }}>
                      {(scan.confidence * 100).toFixed(0)}%
                    </span>
                  </div>
                  <div className="text-[10px] text-muted-foreground mt-0.5">{fmt(scan.timestamp)}</div>
                </div>
              ))}
            </CardContent>
          </Card>


          {/* Confidence Gauge */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm">Confidence Analysis</CardTitle>
              <CardDescription className="text-xs">Current scan confidence</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex flex-col items-center gap-4">
                <div className="relative w-32 h-32">
                  <svg className="w-32 h-32 -rotate-90" viewBox="0 0 128 128">
                    <circle cx="64" cy="64" r="52" stroke="currentColor" strokeWidth="10" fill="none" className="text-muted" />
                    <circle
                      cx="64" cy="64" r="52"
                      stroke={confidenceColor(currentConf)}
                      strokeWidth="10"
                      fill="none"
                      strokeDasharray={`${currentConf * 326.73} 326.73`}
                      className="transition-all duration-700"
                      strokeLinecap="round"
                    />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <span className="text-3xl font-bold leading-none">{(currentConf * 100).toFixed(0)}%</span>
                    <span className="text-[10px] text-muted-foreground mt-1">confidence</span>
                  </div>
                </div>

                <div className="w-full space-y-1.5 text-xs">
                  {[
                    ['Scan ID',    selectedScan?.id ?? '—'],
                    ['Attack',     selectedScan?.type ?? '—'],
                    ['Severity',   selectedScan?.severity ?? '—'],
                    ['Method',     activeMethod],
                  ].map(([label, val]) => (
                    <div key={label} className="flex justify-between">
                      <span className="text-muted-foreground">{label}</span>
                      <span className="font-medium capitalize truncate max-w-[120px] text-right">{val}</span>
                    </div>
                  ))}
                  <div className="flex justify-between pt-1">
                    <span className="text-muted-foreground">Status</span>
                    {selectedScan ? (
                      <Badge
                        variant={selectedScan.status === 'detected' ? 'destructive' : 'default'}
                        className="text-[10px] h-4"
                      >
                        {selectedScan.status === 'detected'
                          ? <><AlertTriangle className="h-2.5 w-2.5 mr-0.5" />ADVERSARIAL</>
                          : <><CheckCircle  className="h-2.5 w-2.5 mr-0.5" />CLEAN</>
                        }
                      </Badge>
                    ) : <span className="text-muted-foreground">—</span>}
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Recent Explanations (history from XAI backend) */}
          {history.length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Zap className="h-4 w-4" /> Recent Explanations
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 max-h-48 overflow-y-auto pr-1 no-scrollbar">
                {history.map(h => (
                  <div key={h.id} className="p-2 rounded border text-xs">
                    <div className="flex justify-between items-center">
                      <span className="font-mono text-[10px] text-muted-foreground">{h.id}</span>
                      <Badge variant="outline" className="text-[9px] h-3.5">{h.method}</Badge>
                    </div>
                    <div className="font-medium mt-0.5 capitalize truncate">{h.attack_type}</div>
                    <div className="flex justify-between text-muted-foreground mt-0.5">
                      <span>{(h.confidence*100).toFixed(0)}% conf</span>
                      <span>{fmt(h.timestamp)}</span>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}
        </div>

        {/* ════════════ RIGHT COLUMN ════════════ */}
        <div className="lg:col-span-2 space-y-4">

          {/* Method Selector */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle>Explanation Methods</CardTitle>
              <CardDescription>Choose interpretation technique</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Tab buttons */}
              <div className="grid grid-cols-3 gap-2">
                {(['GradCAM','LIME','SHAP'] as Method[]).map(m => (
                  <button
                    key={m}
                    onClick={() => setActiveMethod(m)}
                    className={`py-2 px-3 rounded-md text-sm font-medium transition-colors border ${
                      activeMethod === m
                        ? 'bg-primary text-primary-foreground border-primary'
                        : 'border-border hover:bg-muted/50'
                    }`}
                  >
                    {m}
                  </button>
                ))}
              </div>

              {/* Method description */}
              <div className="rounded-lg border p-4 bg-muted/30 space-y-1">
                <h4 className="font-semibold text-sm">{methodMeta.title}</h4>
                <p className="text-xs text-muted-foreground leading-relaxed">{methodMeta.description}</p>
                <p className="text-[10px] text-primary/70 mt-1">{methodMeta.note}</p>
              </div>

              {/* Generate button */}
              <Button
                onClick={generate}
                disabled={loading || backendOk !== true || !selectedScan}
                className="w-full"
                size="lg"
              >
                {loading
                  ? <><Loader2 className="h-4 w-4 mr-2 animate-spin" />Generating {activeMethod} Explanation…</>
                  : <><Zap className="h-4 w-4 mr-2" />Generate {activeMethod} Explanation</>
                }
              </Button>

              {!selectedScan && (
                <p className="text-xs text-center text-muted-foreground flex items-center justify-center gap-1">
                  <Info className="h-3 w-3" />
                  Select a scan from history to begin
                </p>
              )}
              {backendOk === null && selectedScan && (
                <p className="text-xs text-center text-yellow-500 flex items-center justify-center gap-1">
                  <Loader2 className="h-3 w-3 animate-spin" />
                  Connecting to XAI backend…
                </p>
              )}
              {backendOk === false && (
                <p className="text-xs text-center text-red-400 flex items-center justify-center gap-1">
                  <ServerCrash className="h-3 w-3" />
                  Backend offline — click the 🌐 button above to set your Colab URL
                </p>
              )}
            </CardContent>
          </Card>

          {/* Visual Explanation */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle>Visual Explanation</CardTitle>
              <CardDescription>
                {activeMethod === 'GradCAM' ? 'Heatmap overlay showing critical regions'
                 : activeMethod === 'LIME'   ? 'Superpixel attribution overlay'
                 :                             'Latent-space patch attribution'}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

                {/* Original image */}
                <div className="space-y-2">
                  <div className="text-sm font-medium">Original Image</div>
                  <div className="aspect-video rounded-lg border bg-muted flex items-center justify-center relative overflow-hidden">
                    {result?.original_image ? (
                      <img
                        src={result.original_image}
                        alt="original"
                        className="w-full h-full object-cover"
                      />
                    ) : (
                      <>
                        <div className="absolute inset-0 bg-gradient-to-br from-blue-500/10 to-purple-500/10" />
                        <Eye className="h-10 w-10 text-muted-foreground/40" />
                      </>
                    )}
                    {selectedScan && (
                      <div className="absolute bottom-2 right-2 text-[10px] bg-background/80 px-2 py-0.5 rounded font-mono">
                        {selectedScan.id}
                      </div>
                    )}
                  </div>
                </div>

                {/* Explanation image */}
                <div className="space-y-2">
                  <div className="text-sm font-medium">
                    {activeMethod === 'GradCAM' ? 'Grad-CAM Heatmap'
                     : activeMethod === 'LIME'   ? 'LIME Superpixel Map'
                     :                             'SHAP Patch Attribution'}
                  </div>
                  <div className="aspect-video rounded-lg border bg-muted flex items-center justify-center relative overflow-hidden">
                    {loading ? (
                      <div className="flex flex-col items-center gap-2 text-muted-foreground">
                        <Loader2 className="h-8 w-8 animate-spin" />
                        <span className="text-xs">Computing {activeMethod}…</span>
                      </div>
                    ) : result?.explanation_image ? (
                      <img
                        src={result.explanation_image}
                        alt={`${activeMethod} explanation`}
                        className="w-full h-full object-cover"
                      />
                    ) : (
                      <>
                        <div className={`absolute inset-0 ${
                          activeMethod === 'GradCAM'
                            ? 'bg-gradient-to-br from-red-500/20 via-yellow-500/20 to-green-500/10'
                            : activeMethod === 'LIME'
                            ? 'bg-gradient-to-br from-blue-500/20 to-cyan-500/10'
                            : 'bg-gradient-to-br from-purple-500/20 to-pink-500/10'
                        }`} />
                        <div className="text-center text-xs text-muted-foreground px-4">
                          Click "Generate {activeMethod} Explanation" to compute the real visual output
                        </div>
                      </>
                    )}
                    {result && (
                      <div className="absolute bottom-2 left-2 text-[10px] bg-background/80 px-2 py-0.5 rounded">
                        {activeMethod === 'GradCAM' ? 'Activation intensity'
                         : activeMethod === 'LIME'   ? 'Feature importance'
                         :                             'Latent shift'}
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* Colour legend */}
              {result && activeMethod === 'GradCAM' && (
                <div className="mt-3 flex items-center gap-2">
                  <span className="text-[11px] text-muted-foreground">Activation:</span>
                  <div className="flex-1 h-2 rounded-full bg-gradient-to-r from-blue-500 via-green-400 via-yellow-400 to-red-500" />
                  <span className="text-[11px] text-muted-foreground">Low</span>
                  <span className="text-[11px] text-muted-foreground">High</span>
                </div>
              )}
              {result && activeMethod === 'LIME' && (
                <div className="mt-3 flex items-center gap-2">
                  <span className="text-[11px] text-muted-foreground">Importance:</span>
                  <div className="flex-1 h-2 rounded-full bg-gradient-to-r from-muted via-green-400 to-red-500" />
                  <span className="text-[11px] text-muted-foreground">Low</span>
                  <span className="text-[11px] text-muted-foreground">High</span>
                </div>
              )}
              {result && activeMethod === 'SHAP' && (
                <div className="mt-3 flex items-center gap-2">
                  <span className="text-[11px] text-muted-foreground">Latent shift:</span>
                  <div className="flex-1 h-2 rounded-full bg-gradient-to-r from-blue-500 via-purple-400 to-red-500" />
                  <span className="text-[11px] text-muted-foreground">Low</span>
                  <span className="text-[11px] text-muted-foreground">High</span>
                </div>
              )}

              {/* Description box after generation */}
              {result && (
                <div className="mt-4 p-3 rounded-lg bg-muted/30 border text-xs text-muted-foreground leading-relaxed">
                  <span className="font-semibold text-foreground">{result.method} · </span>
                  {result.description}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Top Contributing Features */}
          {result && result.features.length > 0 && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle>Top Contributing Features</CardTitle>
                <CardDescription>Regions / patches most influential to the prediction</CardDescription>
              </CardHeader>
              <CardContent className="space-y-5">
                {/* Bar chart */}
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart
                    data={result.features}
                    layout="vertical"
                    margin={{ left: 130, right: 20, top: 4, bottom: 4 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" opacity={0.3} />
                    <XAxis type="number" domain={[0,1]} tickFormatter={v => `${(v*100).toFixed(0)}%`} tick={{ fontSize: 10 }} />
                    <YAxis type="category" dataKey="name" width={130} tick={{ fontSize: 10 }} />
                    <Tooltip formatter={(v: number) => [`${(v*100).toFixed(1)}%`, 'Importance']} />
                    <Bar dataKey="importance" name="Importance" radius={[0,3,3,0]}>
                      {result.features.map((_, i) => (
                        <Cell key={i} fill={BAR_COLORS[i % BAR_COLORS.length]} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>

                {/* Feature list with progress bars */}
                <div className="space-y-2">
                  {result.features.map((f, i) => (
                    <div
                      key={i}
                      className="flex items-center gap-3 p-2.5 rounded-lg border hover:bg-muted/50 transition-colors"
                    >
                      <div
                        className="flex items-center justify-center w-7 h-7 rounded-full text-foreground text-xs font-bold shrink-0"
                        style={{ backgroundColor: BAR_COLORS[i % BAR_COLORS.length] }}
                      >
                        {i + 1}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-medium truncate">{f.name}</div>
                        <div className="flex items-center gap-2 mt-1">
                          <Progress value={f.importance * 100} className="h-1.5 flex-1" />
                          <span className="text-xs text-muted-foreground w-10 text-right shrink-0">
                            {(f.importance * 100).toFixed(1)}%
                          </span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Scan details card (characteristics from threat detection) */}
          {selectedScan && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Info className="h-4 w-4" /> Scan Details from Threat Detection
                </CardTitle>
              </CardHeader>
              <CardContent className="text-xs space-y-2">
                <div className="grid grid-cols-2 gap-x-4 gap-y-1.5">
                  {[
                    ['Scan ID',       selectedScan.id],
                    ['Attack Type',   selectedScan.type],
                    ['Category',      selectedScan.category ?? '—'],
                    ['Severity',      selectedScan.severity],
                    ['Status',        selectedScan.status],
                    ['Confidence',    `${(selectedScan.confidence * 100).toFixed(1)}%`],
                    ['Model Target',  selectedScan.modelTarget],
                    ['Attack Vector', selectedScan.attackVector],
                  ].map(([k,v]) => (
                    <div key={k} className="flex gap-1">
                      <span className="text-muted-foreground shrink-0">{k}:</span>
                      <span className="font-medium capitalize truncate">{v}</span>
                    </div>
                  ))}
                </div>
                {selectedScan.characteristics && selectedScan.characteristics.length > 0 && (
                  <div className="pt-2 border-t">
                    <div className="text-muted-foreground mb-1">Characteristics:</div>
                    <ul className="space-y-0.5">
                      {selectedScan.characteristics.map((c,i) => (
                        <li key={i} className="flex items-start gap-1">
                          <span className="text-primary mt-0.5">•</span>
                          <span>{c}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {selectedScan.primaryIndicator && (
                  <div className="pt-2 border-t">
                    <span className="text-muted-foreground">Primary Indicator: </span>
                    <span className="font-medium">{selectedScan.primaryIndicator}</span>
                  </div>
                )}
              </CardContent>
            </Card>
          )}

        </div>
      </div>
    </div>
  );
}