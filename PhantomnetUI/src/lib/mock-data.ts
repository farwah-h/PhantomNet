// // Mock data for PhantomNet++ Dashboard

// export interface ThreatData {
//   id: string;
//   timestamp: Date;
//   type: string;
//   severity: 'low' | 'medium' | 'high' | 'critical';
//   status: 'detected' | 'mitigated' | 'monitoring';
//   modelTarget: string;
//   confidence: number;
//   attackVector: string;
  
//   // NEW FIELDS for attack categorization
//   category?: string;           // Attack category (e.g., "Physical Perturbation", "Digital Perturbation")
//   characteristics?: string[];  // List of attack characteristics
//   primaryIndicator?: string;   // Primary detection indicator
// }

// export interface ModelMetrics {
//   id: string;
//   name: string;
//   type: string;
//   accuracy: number;
//   robustness: number;
//   latency: number;
//   status: 'active' | 'standby' | 'compromised';
//   deployedAt: Date;
// }

// export interface AgentStatus {
//   id: string;
//   name: string;
//   status: 'online' | 'offline' | 'degraded';
//   uptime: number;
//   tasksProcessed: number;
//   lastHeartbeat: Date;
//   prediction?: string;
//   confidence?: number;
// }

// export interface SIEMLog {
//   id: string;
//   timestamp: Date;
//   level: 'info' | 'warning' | 'error' | 'critical';
//   module: string;
//   message: string;
//   details?: any;
// }

// export interface AttackSimulation {
//   id: string;
//   name: string;
//   type: 'patch' | 'occlusion' | 'wearable' | 'noise';
//   status: 'running' | 'completed' | 'failed' | 'queued';
//   targetModel: string;
//   successRate: number;
//   createdAt: Date;
// }

// export interface XAIExplanation {
//   id: string;
//   predictionId: string;
//   method: 'LIME' | 'SHAP' | 'GradCAM';
//   imageUrl: string;
//   heatmapUrl?: string;
//   prediction: string;
//   confidence: number;
//   topFeatures: { name: string; importance: number }[];
// }

// // Mock Threats
// export const mockThreats: ThreatData[] = [
//   {
//     id: 'THR-001',
//     timestamp: new Date(Date.now() - 1000 * 60 * 5),
//     type: 'Adversarial Patch',
//     severity: 'critical',
//     status: 'mitigated',
//     modelTarget: 'YOLOv5',
//     confidence: 0.94,
//     attackVector: 'Physical patch on traffic sign'
//   },
//   {
//     id: 'THR-002',
//     timestamp: new Date(Date.now() - 1000 * 60 * 15),
//     type: 'Occlusion Attack',
//     severity: 'high',
//     status: 'detected',
//     modelTarget: 'ResNet-50',
//     confidence: 0.87,
//     attackVector: 'Partial object obstruction'
//   },
//   {
//     id: 'THR-003',
//     timestamp: new Date(Date.now() - 1000 * 60 * 30),
//     type: 'Adversarial Glasses',
//     severity: 'medium',
//     status: 'monitoring',
//     modelTarget: 'FaceNet',
//     confidence: 0.72,
//     attackVector: 'Wearable perturbation'
//   },
//   {
//     id: 'THR-004',
//     timestamp: new Date(Date.now() - 1000 * 60 * 45),
//     type: 'FGSM Attack',
//     severity: 'high',
//     status: 'mitigated',
//     modelTarget: 'ResNet-50',
//     confidence: 0.91,
//     attackVector: 'Digital perturbation'
//   },
//   {
//     id: 'THR-005',
//     timestamp: new Date(Date.now() - 1000 * 60 * 60),
//     type: 'PGD Attack',
//     severity: 'critical',
//     status: 'mitigated',
//     modelTarget: 'YOLOv5',
//     confidence: 0.96,
//     attackVector: 'Iterative gradient attack'
//   }
// ];

// // Mock Models
// export const mockModels: ModelMetrics[] = [
//   {
//     id: 'MDL-001',
//     name: 'YOLOv5-Robust',
//     type: 'Object Detection',
//     accuracy: 94.5,
//     robustness: 87.2,
//     latency: 23,
//     status: 'active',
//     deployedAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 7)
//   },
//   {
//     id: 'MDL-002',
//     name: 'ResNet-50-Adv',
//     type: 'Classification',
//     accuracy: 92.1,
//     robustness: 84.5,
//     latency: 18,
//     status: 'active',
//     deployedAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 5)
//   },
//   {
//     id: 'MDL-003',
//     name: 'FaceNet-Defense',
//     type: 'Face Recognition',
//     accuracy: 96.8,
//     robustness: 91.3,
//     latency: 15,
//     status: 'active',
//     deployedAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 3)
//   },
//   {
//     id: 'MDL-004',
//     name: 'CRDA-Quantized',
//     type: 'Edge Classification',
//     accuracy: 89.4,
//     robustness: 93.1,
//     latency: 8,
//     status: 'standby',
//     deployedAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 2)
//   }
// ];

// // Mock Agents
// export const mockAgents: AgentStatus[] = [
//   {
//     id: 'AGT-001',
//     name: 'Agent Alpha',
//     status: 'online',
//     uptime: 99.8,
//     tasksProcessed: 15847,
//     lastHeartbeat: new Date(Date.now() - 1000 * 5),
//     prediction: 'car',
//     confidence: 0.94
//   },
//   {
//     id: 'AGT-002',
//     name: 'Agent Beta',
//     status: 'online',
//     uptime: 99.6,
//     tasksProcessed: 14562,
//     lastHeartbeat: new Date(Date.now() - 1000 * 3),
//     prediction: 'car',
//     confidence: 0.91
//   },
//   {
//     id: 'AGT-003',
//     name: 'Agent Gamma',
//     status: 'online',
//     uptime: 98.9,
//     tasksProcessed: 13998,
//     lastHeartbeat: new Date(Date.now() - 1000 * 7),
//     prediction: 'car',
//     confidence: 0.89
//   },
//   {
//     id: 'AGT-004',
//     name: 'Agent Delta',
//     status: 'degraded',
//     uptime: 87.2,
//     tasksProcessed: 11234,
//     lastHeartbeat: new Date(Date.now() - 1000 * 45),
//     prediction: 'truck',
//     confidence: 0.56
//   },
//   {
//     id: 'AGT-005',
//     name: 'Agent Epsilon',
//     status: 'online',
//     uptime: 99.9,
//     tasksProcessed: 16123,
//     lastHeartbeat: new Date(Date.now() - 1000 * 2),
//     prediction: 'car',
//     confidence: 0.97
//   }
// ];

// // Mock SIEM Logs
// export const mockSIEMLogs: SIEMLog[] = [
//   {
//     id: 'LOG-001',
//     timestamp: new Date(Date.now() - 1000 * 60 * 2),
//     level: 'critical',
//     module: 'IVM',
//     message: 'Adversarial attack detected on YOLOv5 model',
//     details: { attackType: 'patch', confidence: 0.94 }
//   },
//   {
//     id: 'LOG-002',
//     timestamp: new Date(Date.now() - 1000 * 60 * 5),
//     level: 'warning',
//     module: 'ARE',
//     message: 'Agent Delta showing anomalous behavior',
//     details: { agentId: 'AGT-004', deviation: 0.35 }
//   },
//   {
//     id: 'LOG-003',
//     timestamp: new Date(Date.now() - 1000 * 60 * 8),
//     level: 'info',
//     module: 'DAG',
//     message: 'Simulation SIM-023 completed successfully',
//     details: { successRate: 0.78 }
//   },
//   {
//     id: 'LOG-004',
//     timestamp: new Date(Date.now() - 1000 * 60 * 12),
//     level: 'error',
//     module: 'SRC',
//     message: 'Failed to establish secure connection with Agent Zeta',
//     details: { error: 'TLS handshake timeout' }
//   },
//   {
//     id: 'LOG-005',
//     timestamp: new Date(Date.now() - 1000 * 60 * 20),
//     level: 'info',
//     module: 'XAI',
//     message: 'Generated Grad-CAM explanation for prediction #1847',
//     details: { predictionId: 'PRED-1847', method: 'GradCAM' }
//   }
// ];

// // Mock Attack Simulations
// export const mockSimulations: AttackSimulation[] = [
//   {
//     id: 'SIM-001',
//     name: 'Traffic Sign Patch Attack',
//     type: 'patch',
//     status: 'completed',
//     targetModel: 'YOLOv5-Robust',
//     successRate: 78.4,
//     createdAt: new Date(Date.now() - 1000 * 60 * 60 * 2)
//   },
//   {
//     id: 'SIM-002',
//     name: 'Face Occlusion Test',
//     type: 'occlusion',
//     status: 'running',
//     targetModel: 'FaceNet-Defense',
//     successRate: 45.2,
//     createdAt: new Date(Date.now() - 1000 * 60 * 30)
//   },
//   {
//     id: 'SIM-003',
//     name: 'Adversarial Glasses v2',
//     type: 'wearable',
//     status: 'queued',
//     targetModel: 'FaceNet-Defense',
//     successRate: 0,
//     createdAt: new Date(Date.now() - 1000 * 60 * 5)
//   },
//   {
//     id: 'SIM-004',
//     name: 'Gaussian Noise Test',
//     type: 'noise',
//     status: 'completed',
//     targetModel: 'ResNet-50-Adv',
//     successRate: 23.7,
//     createdAt: new Date(Date.now() - 1000 * 60 * 60 * 5)
//   }
// ];

// // Mock XAI Explanations
// export const mockXAIExplanations: XAIExplanation[] = [
//   {
//     id: 'XAI-001',
//     predictionId: 'PRED-1847',
//     method: 'GradCAM',
//     imageUrl: '/placeholder-car.jpg',
//     heatmapUrl: '/placeholder-heatmap.jpg',
//     prediction: 'car',
//     confidence: 0.94,
//     topFeatures: [
//       { name: 'Front bumper region', importance: 0.89 },
//       { name: 'Wheel area', importance: 0.76 },
//       { name: 'Windshield', importance: 0.65 }
//     ]
//   },
//   {
//     id: 'XAI-002',
//     predictionId: 'PRED-1848',
//     method: 'SHAP',
//     imageUrl: '/placeholder-person.jpg',
//     prediction: 'person',
//     confidence: 0.87,
//     topFeatures: [
//       { name: 'Upper body silhouette', importance: 0.92 },
//       { name: 'Head region', importance: 0.84 },
//       { name: 'Leg position', importance: 0.71 }
//     ]
//   }
// ];

// // Dashboard metrics
// export const getDashboardMetrics = () => {
//   const totalThreats = mockThreats.length;
//   const mitigatedThreats = mockThreats.filter(t => t.status === 'mitigated').length;
//   const activeThreats = mockThreats.filter(t => t.status === 'detected').length;
//   const criticalThreats = mockThreats.filter(t => t.severity === 'critical').length;

//   const avgModelAccuracy = mockModels.reduce((sum, m) => sum + m.accuracy, 0) / mockModels.length;
//   const avgRobustness = mockModels.reduce((sum, m) => sum + m.robustness, 0) / mockModels.length;

//   const activeAgents = mockAgents.filter(a => a.status === 'online').length;
//   const totalAgents = mockAgents.length;

//   return {
//     totalThreats,
//     mitigatedThreats,
//     activeThreats,
//     criticalThreats,
//     mitigationRate: ((mitigatedThreats / totalThreats) * 100).toFixed(1),
//     avgModelAccuracy: avgModelAccuracy.toFixed(1),
//     avgRobustness: avgRobustness.toFixed(1),
//     activeAgents,
//     totalAgents,
//     agentUptime: ((activeAgents / totalAgents) * 100).toFixed(1)
//   };
// };

// // Time series data for charts
// export const getTimeSeriesData = () => {
//   const hours = 24;
//   const now = Date.now();

//   return Array.from({ length: hours }, (_, i) => ({
//     time: new Date(now - (hours - i) * 60 * 60 * 1000).toLocaleTimeString('en-US', { hour: '2-digit' }),
//     threats: Math.floor(Math.random() * 15) + 5,
//     mitigated: Math.floor(Math.random() * 12) + 3,
//     accuracy: 85 + Math.random() * 10,
//     latency: 15 + Math.random() * 15
//   }));
// };

// // Response Policy Rules
// export interface ResponsePolicy {
//   id: string;
//   name: string;
//   condition: string;
//   action: 'isolate' | 'switch_model' | 'escalate' | 'monitor';
//   priority: number;
//   enabled: boolean;
//   lastTriggered?: Date;
// }

// export const mockResponsePolicies: ResponsePolicy[] = [
//   {
//     id: 'POL-001',
//     name: 'Critical Threat Isolation',
//     condition: 'threat.severity === "critical" && threat.confidence > 0.9',
//     action: 'isolate',
//     priority: 1,
//     enabled: true,
//     lastTriggered: new Date(Date.now() - 1000 * 60 * 5)
//   },
//   {
//     id: 'POL-002',
//     name: 'Agent Anomaly Detection',
//     condition: 'agent.deviation > 0.3 && agent.confidence < 0.7',
//     action: 'switch_model',
//     priority: 2,
//     enabled: true,
//     lastTriggered: new Date(Date.now() - 1000 * 60 * 15)
//   },
//   {
//     id: 'POL-003',
//     name: 'High Threat Escalation',
//     condition: 'threat.severity === "high" && threat.status === "detected"',
//     action: 'escalate',
//     priority: 3,
//     enabled: true,
//     lastTriggered: new Date(Date.now() - 1000 * 60 * 30)
//   },
//   {
//     id: 'POL-004',
//     name: 'Model Performance Degradation',
//     condition: 'model.accuracy < 0.85 || model.robustness < 0.8',
//     action: 'switch_model',
//     priority: 4,
//     enabled: false
//   }
// ];

// // Autonomous Actions Log
// export interface AutonomousAction {
//   id: string;
//   timestamp: Date;
//   policyId: string;
//   policyName: string;
//   action: 'isolate' | 'switch_model' | 'escalate' | 'monitor';
//   target: string;
//   result: 'success' | 'failed' | 'pending';
//   details: string;
// }

// export const mockAutonomousActions: AutonomousAction[] = [
//   {
//     id: 'ACT-001',
//     timestamp: new Date(Date.now() - 1000 * 60 * 5),
//     policyId: 'POL-001',
//     policyName: 'Critical Threat Isolation',
//     action: 'isolate',
//     target: 'Agent Delta (AGT-004)',
//     result: 'success',
//     details: 'Agent isolated due to adversarial attack detection with 94% confidence'
//   },
//   {
//     id: 'ACT-002',
//     timestamp: new Date(Date.now() - 1000 * 60 * 15),
//     policyId: 'POL-002',
//     policyName: 'Agent Anomaly Detection',
//     action: 'switch_model',
//     target: 'YOLOv5 → CRDA-Quantized',
//     result: 'success',
//     details: 'Model switched due to anomalous behavior (deviation: 0.35)'
//   },
//   {
//     id: 'ACT-003',
//     timestamp: new Date(Date.now() - 1000 * 60 * 30),
//     policyId: 'POL-003',
//     policyName: 'High Threat Escalation',
//     action: 'escalate',
//     target: 'Security Team',
//     result: 'success',
//     details: 'Escalated occlusion attack on ResNet-50 (severity: high)'
//   },
//   {
//     id: 'ACT-004',
//     timestamp: new Date(Date.now() - 1000 * 60 * 45),
//     policyId: 'POL-001',
//     policyName: 'Critical Threat Isolation',
//     action: 'isolate',
//     target: 'Agent Beta (AGT-002)',
//     result: 'failed',
//     details: 'Failed to isolate agent due to communication timeout'
//   },
//   {
//     id: 'ACT-005',
//     timestamp: new Date(Date.now() - 1000 * 60 * 60),
//     policyId: 'POL-002',
//     policyName: 'Agent Anomaly Detection',
//     action: 'switch_model',
//     target: 'ResNet-50 → FaceNet-Defense',
//     result: 'success',
//     details: 'Switched to robust model due to FGSM attack pattern'
//   }
// ];

// // Agent Anomaly Data
// export interface AgentAnomaly {
//   agentId: string;
//   agentName: string;
//   anomalyScore: number;
//   status: 'normal' | 'warning' | 'critical';
//   lastChecked: Date;
// }

// export const mockAgentAnomalies: AgentAnomaly[] = [
//   {
//     agentId: 'AGT-001',
//     agentName: 'Agent Alpha',
//     anomalyScore: 0.12,
//     status: 'normal',
//     lastChecked: new Date(Date.now() - 1000 * 5)
//   },
//   {
//     agentId: 'AGT-002',
//     agentName: 'Agent Beta',
//     anomalyScore: 0.18,
//     status: 'normal',
//     lastChecked: new Date(Date.now() - 1000 * 3)
//   },
//   {
//     agentId: 'AGT-003',
//     agentName: 'Agent Gamma',
//     anomalyScore: 0.25,
//     status: 'normal',
//     lastChecked: new Date(Date.now() - 1000 * 7)
//   },
//   {
//     agentId: 'AGT-004',
//     agentName: 'Agent Delta',
//     anomalyScore: 0.78,
//     status: 'critical',
//     lastChecked: new Date(Date.now() - 1000 * 45)
//   },
//   {
//     agentId: 'AGT-005',
//     agentName: 'Agent Epsilon',
//     anomalyScore: 0.09,
//     status: 'normal',
//     lastChecked: new Date(Date.now() - 1000 * 2)
//   }
// ];

// // Response Statistics
// export interface ResponseStats {
//   totalIsolations: number;
//   totalModelSwitches: number;
//   totalEscalations: number;
//   successRate: number;
//   avgResponseTime: number;
// }

// export const mockResponseStats: ResponseStats = {
//   totalIsolations: 47,
//   totalModelSwitches: 23,
//   totalEscalations: 12,
//   successRate: 94.2,
//   avgResponseTime: 1.3
// };

// // Extended SIEM Logs with more variety
// export const generateSIEMLogs = (count: number = 50): SIEMLog[] => {
//   const modules = ['DAG', 'IVM', 'ARE', 'XAI', 'SRC', 'LSE', 'DUI', 'FMO'];
//   const levels: ('info' | 'warning' | 'error' | 'critical')[] = ['info', 'warning', 'error', 'critical'];
//   const messages = [
//     { level: 'info' as const, templates: [
//       'Simulation {id} completed successfully',
//       'Agent {agent} heartbeat received',
//       'Model {model} deployed successfully',
//       'XAI explanation generated for prediction {pred}',
//       'Secure connection established with {agent}',
//       'Log rotation completed',
//       'Checkpoint saved for model {model}'
//     ]},
//     { level: 'warning' as const, templates: [
//       'Agent {agent} showing anomalous behavior',
//       'Model {model} accuracy below threshold',
//       'High latency detected on {agent}',
//       'Unusual traffic pattern detected',
//       'Memory usage approaching limit on {module}',
//       'Connection retry attempt {num} for {agent}'
//     ]},
//     { level: 'error' as const, templates: [
//       'Failed to establish connection with {agent}',
//       'Model {model} prediction timeout',
//       'Data validation failed for input {id}',
//       'Configuration load error in {module}',
//       'Agent {agent} unresponsive',
//       'Database query timeout'
//     ]},
//     { level: 'critical' as const, templates: [
//       'Adversarial attack detected on {model}',
//       'System integrity check failed',
//       'Agent {agent} compromised',
//       'Emergency shutdown initiated for {module}',
//       'Data breach attempt detected',
//       'Critical resource exhaustion on {module}'
//     ]}
//   ];

//   const logs: SIEMLog[] = [];
//   for (let i = 0; i < count; i++) {
//     const level = levels[Math.floor(Math.random() * levels.length)];
//     const module = modules[Math.floor(Math.random() * modules.length)];
//     const messageGroup = messages.find(m => m.level === level)!;
//     const template = messageGroup.templates[Math.floor(Math.random() * messageGroup.templates.length)];

//     const message = template
//       .replace('{id}', `SIM-${String(Math.floor(Math.random() * 999)).padStart(3, '0')}`)
//       .replace('{agent}', `Agent ${String.fromCharCode(65 + Math.floor(Math.random() * 5))}`)
//       .replace('{model}', ['YOLOv5', 'ResNet-50', 'FaceNet', 'CRDA'][Math.floor(Math.random() * 4)])
//       .replace('{pred}', `PRED-${Math.floor(Math.random() * 9999)}`)
//       .replace('{module}', module)
//       .replace('{num}', String(Math.floor(Math.random() * 5) + 1));

//     logs.push({
//       id: `LOG-${String(i + 1).padStart(3, '0')}`,
//       timestamp: new Date(Date.now() - Math.random() * 1000 * 60 * 60 * 24),
//       level,
//       module,
//       message,
//       details: level === 'critical' || level === 'error' ? {
//         stack: 'Error stack trace here...',
//         context: { source: module, thread: Math.floor(Math.random() * 10) }
//       } : undefined
//     });
//   }

//   return logs.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
// };

