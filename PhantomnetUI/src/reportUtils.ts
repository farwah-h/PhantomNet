/**
 * reportUtils.ts — PhantomNet++ Report Download Helper
 *
 * Shared utility imported by threat-detection.tsx, xai-engine.tsx,
 * and attack-simulation.tsx to generate PDF + JSON reports.
 *
 * All calls go to report_backend.py on port 8004.
 */

const REPORT_BASE = 'http://localhost:8004/api/report';

// ── Generic download trigger ───────────────────────────────────────────────────
async function downloadBlob(url: string, payload: object, filename: string, mime: string) {
  const res = await fetch(url, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(`Report backend error: ${res.status}`);
  const blob = await res.blob();
  const a    = Object.assign(document.createElement('a'), {
    href:     URL.createObjectURL(blob),
    download: filename,
  });
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(a.href);
}

// ── JSON download (no backend needed — just serialize) ────────────────────────
function downloadJSON(data: object, filename: string) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const a    = Object.assign(document.createElement('a'), {
    href:     URL.createObjectURL(blob),
    download: filename,
  });
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(a.href);
}

// ── Timestamp helper ──────────────────────────────────────────────────────────
function nowStr() {
  return new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
}

// =============================================================================
// THREAT DETECTION REPORTS
// =============================================================================

export interface ThreatReportData {
  threat_id:           string;
  filename:            string;
  timestamp:           string;
  final_decision:      string;
  confidence:          number;
  severity:            string;
  attack_type:         string;
  attack_category?:    string;
  posture?:            string;
  model_contributions?: any[];
  votes?:              Record<string, number>;
  weights_used?:       Record<string, number>;
  image_b64?:          string;   // base64 of the uploaded image
}

export async function downloadThreatPDF(data: ThreatReportData): Promise<void> {
  await downloadBlob(
    `${REPORT_BASE}/threat/pdf`,
    data,
    `phantomnet_threat_${data.threat_id}_${nowStr()}.pdf`,
    'application/pdf',
  );
}

export function downloadThreatJSON(data: ThreatReportData): void {
  const payload = {
    report_type:  'threat_detection',
    report_id:    `RPT-TD-${Math.random().toString(36).slice(2, 10).toUpperCase()}`,
    generated_at: new Date().toISOString(),
    data,
  };
  downloadJSON(payload, `phantomnet_threat_${data.threat_id}_${nowStr()}.json`);
}

// =============================================================================
// XAI EXPLANATION REPORTS
// =============================================================================

export interface XAIReportData {
  explanation_id:    string;
  scan_id:           string;
  timestamp:         string;
  method:            string;
  prediction:        string;
  confidence:        number;
  attack_type:       string;
  severity:          string;
  is_adversarial:    boolean;
  description:       string;
  features?:         { name: string; importance: number }[];
  original_image?:   string;    // base64
  explanation_image?: string;   // base64
}

export async function downloadXAIPDF(data: XAIReportData): Promise<void> {
  await downloadBlob(
    `${REPORT_BASE}/xai/pdf`,
    data,
    `phantomnet_xai_${data.explanation_id}_${nowStr()}.pdf`,
    'application/pdf',
  );
}

export function downloadXAIJSON(data: XAIReportData): void {
  // Strip base64 images from JSON — they bloat the file
  const payload = {
    report_type:  'xai_explanation',
    report_id:    `RPT-XAI-${Math.random().toString(36).slice(2, 10).toUpperCase()}`,
    generated_at: new Date().toISOString(),
    data: {
      ...data,
      original_image:    data.original_image    ? '[base64 image omitted]' : null,
      explanation_image: data.explanation_image ? '[base64 image omitted]' : null,
    },
  };
  downloadJSON(payload, `phantomnet_xai_${data.explanation_id}_${nowStr()}.json`);
}

// =============================================================================
// ATTACK SIMULATION REPORTS
// =============================================================================

export interface SimulationReportData {
  sim_id:       string;
  timestamp:    string;
  attack_type:  string;
  strength?:    number;
  success_rate: number;
  confidence:   number;
  before_image?: string;   // base64
  after_image?:  string;   // base64
  confusion_matrix?:        { actual: string; predicted: string; count: number }[];
  top_misclassifications?:  { class: string; count: number; percentage: number }[];
}

export async function downloadSimulationPDF(data: SimulationReportData): Promise<void> {
  await downloadBlob(
    `${REPORT_BASE}/simulation/pdf`,
    data,
    `phantomnet_simulation_${data.sim_id}_${nowStr()}.pdf`,
    'application/pdf',
  );
}

export function downloadSimulationJSON(data: SimulationReportData): void {
  const payload = {
    report_type:  'attack_simulation',
    report_id:    `RPT-SIM-${Math.random().toString(36).slice(2, 10).toUpperCase()}`,
    generated_at: new Date().toISOString(),
    data: {
      ...data,
      before_image: data.before_image ? '[base64 image omitted]' : null,
      after_image:  data.after_image  ? '[base64 image omitted]' : null,
    },
  };
  downloadJSON(payload, `phantomnet_simulation_${data.sim_id}_${nowStr()}.json`);
}