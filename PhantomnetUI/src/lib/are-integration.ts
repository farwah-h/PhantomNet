/**
 * ARE Integration Bridge — are-integration.ts
 * PhantomNet++
 *
 * Drop this file into your project.  Call `triggerARE(threatPayload)` from your
 * Threat Detection component immediately after the model returns its analysis.
 *
 * This bridges Threat Detection → Autonomous Response Engine automatically.
 */

const ARE_BASE = "http://localhost:8000/api/are";

// ── Types ──────────────────────────────────────────────────────────────────

export interface ThreatPayload {
  /** Unique ID for this threat event, e.g. "THR-" + Date.now() */
  threatId: string;
  /** Human-readable target label, e.g. "Agent-Alpha" or the image filename */
  target: string;
  /** "critical" | "high" | "medium" | "low" */
  severity: "critical" | "high" | "medium" | "low";
  /** 0.0 – 1.0  detection confidence from your CV model */
  confidence: number;
  /** "detected" | "mitigated" | "investigating" */
  status?: string;
  /** Optional — pass these if your model returns them */
  modelAccuracy?: number;
  modelRobustness?: number;
  agentDeviation?: number;
  agentConfidence?: number;
  agentAnomalyScore?: number;
}

export interface AREResult {
  threatId: string;
  policiesChecked: number;
  actionsTriggered: number;
  actions: Array<{
    id: string;
    policyName: string;
    action: string;
    target: string;
    details: string;
    result: string;
    executionTime: number;
    timestamp: string;
  }>;
  updatedStats: {
    totalIsolations: number;
    totalModelSwitches: number;
    totalEscalations: number;
    successRate: number;
  };
}

// ── Main integration function ──────────────────────────────────────────────

/**
 * Call this from Threat Detection after you have the model's output.
 *
 * Example (inside your ThreatDetection component):
 *
 *   import { triggerARE } from "@/lib/are-integration";
 *
 *   const result = await runModel(imageFile);          // your existing call
 *   const areResult = await triggerARE({
 *     threatId:   "THR-" + Date.now(),
 *     target:     imageFile.name,
 *     severity:   result.severity,                     // from your model
 *     confidence: result.confidence,                   // from your model
 *     status:     "detected",
 *     modelAccuracy:   result.modelAccuracy,           // optional
 *     modelRobustness: result.modelRobustness,         // optional
 *     agentDeviation:  result.agentDeviation,          // optional
 *   });
 *
 *   console.log(`${areResult.actionsTriggered} policies fired`);
 */
export async function triggerARE(payload: ThreatPayload): Promise<AREResult | null> {
  try {
    const res = await fetch(`${ARE_BASE}/evaluate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      console.error("[ARE] evaluate failed:", res.status, await res.text());
      return null;
    }

    const data: AREResult = await res.json();
    console.log(
      `[ARE] Threat ${payload.threatId} → ${data.policiesChecked} policies checked, ` +
      `${data.actionsTriggered} actions triggered`
    );
    return data;
  } catch (err) {
    console.error("[ARE] Network error calling /evaluate:", err);
    return null;
  }
}

// ── Severity mapper ────────────────────────────────────────────────────────

/**
 * Helper: map a raw confidence score to a severity label.
 * Adjust thresholds to match your model's output range.
 *
 *   confidence >= 0.90  → "critical"
 *   confidence >= 0.70  → "high"
 *   confidence >= 0.50  → "medium"
 *   else                → "low"
 */
export function confidenceToSeverity(
  confidence: number
): ThreatPayload["severity"] {
  if (confidence >= 0.9) return "critical";
  if (confidence >= 0.7) return "high";
  if (confidence >= 0.5) return "medium";
  return "low";
}