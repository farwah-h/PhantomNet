import { useState } from 'react';
import {
  Play,
  Plus,
  Activity,
  Zap,
  Target,
  Loader2
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Slider } from '@/components/ui/slider';

// --- INTERFACES MATCHING BACKEND ---

interface SimulationFormData {
  name: string;
  type: string; 
  targetModel: string;
  patchSize: number;
  brightness: number;
  noiseLevel: number; 
  occlusionArea: number;
}

interface SimulationResult {
  id: string;
  beforeImage: string; // Base64 string
  afterImage: string;  // Base64 string
  successRate: number;
  confidence: number;
  confusionMatrix: {
    predicted: string;
    actual: string;
    count: number;
  }[];
  topMisclassifications: {
    class: string;
    count: number;
    percentage: number;
  }[];
}

export default function AttackSimulationPage() {
  const [open, setOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false); 
  
  // Stores the real result from the Python Backend
  const [simulationResult, setSimulationResult] = useState<SimulationResult | null>(null);
  const [pdfLoading, setPdfLoading] = useState(false);
  
  // Controls the results dialog visibility
  const [selectedResult, setSelectedResult] = useState<string | null>(null);

  const [formData, setFormData] = useState<SimulationFormData>({
    name: '',
    type: 'patch',
    targetModel: '',
    patchSize: 50,
    brightness: 50,
    noiseLevel: 30,
    occlusionArea: 40,
  });

  // Default Mock Result (Fallback if API fails)
  const mockResult: SimulationResult = {
    id: 'SIM-DEMO',
    beforeImage: '', 
    afterImage: '',
    successRate: 0,
    confidence: 0,
    confusionMatrix: [],
    topMisclassifications: [],
  };

  // --- API INTEGRATION ---

  const handleCreateSimulation = async () => {
    setIsLoading(true);
    
    try {
      console.log('Sending attack to backend...');

      // 1. Call the Python Backend
      const response = await fetch('http://localhost:8001/api/simulation/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: formData.name,
          type: formData.type,
          targetModel: formData.targetModel,
          patchSize: formData.patchSize,
          brightness: formData.brightness,
          noiseLevel: formData.noiseLevel,
          occlusionArea: formData.occlusionArea
        })
      });

      if (!response.ok) {
        throw new Error('Backend connection failed. Is main.py running?');
      }

      // 2. Receive the processed data (with Base64 images)
      const result = await response.json();
      console.log("Received result:", result);

      // 3. Update State
      setSimulationResult(result);
      setSelectedResult(result.id); // Triggers the Results Dialog to open
      setOpen(false); // Closes the Create Dialog

      // Reset form
      setFormData({
        name: '',
        type: 'patch',
        targetModel: '',
        patchSize: 50,
        brightness: 50,
        noiseLevel: 30,
        occlusionArea: 40,
      });

    } catch (error) {
      console.error("Backend Error:", error);
      alert("Failed to connect to backend. Make sure 'python main.py' is running!");
    } finally {
      setIsLoading(false);
    }
  };

  // Current result to display (Real API result OR Mock fallback)

  const handleSimPdfReport = async () => {
    if (!simulationResult) return;
    setPdfLoading(true);
    try {
      const res = await fetch('http://localhost:8004/api/report/simulation/pdf', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sim_id:       simulationResult.id,
          timestamp:    new Date().toISOString(),
          attack_type:  formData.type,
          strength:     formData.noiseLevel / 10,
          success_rate: simulationResult.successRate,
          confidence:   simulationResult.confidence,
          before_image: simulationResult.beforeImage,
          after_image:  simulationResult.afterImage,
          confusion_matrix: simulationResult.confusionMatrix,
          top_misclassifications: simulationResult.topMisclassifications,
        }),
      });
      if (!res.ok) throw new Error();
      const blob = await res.blob();
      const a = Object.assign(document.createElement('a'), {
        href: URL.createObjectURL(blob),
        download: `phantomnet_sim_${simulationResult.id}.pdf`,
      });
      a.click();
    } catch {
      alert('PDF generation failed. Start report_backend.py on port 8004.');
    } finally { setPdfLoading(false); }
  };

  const handleSimJsonReport = () => {
    if (!simulationResult) return;
    const payload = {
      report_type: 'attack_simulation',
      generated_at: new Date().toISOString(),
      sim_id:       simulationResult.id,
      attack_type:  formData.type,
      strength:     formData.noiseLevel / 10,
      success_rate: simulationResult.successRate,
      confidence:   simulationResult.confidence,
      confusion_matrix: simulationResult.confusionMatrix,
      top_misclassifications: simulationResult.topMisclassifications,
      before_image: '[base64 omitted]',
      after_image:  '[base64 omitted]',
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const a = Object.assign(document.createElement('a'), {
      href: URL.createObjectURL(blob),
      download: `phantomnet_sim_${simulationResult.id}.json`,
    });
    a.click();
    // ── SIEM: log report download ──────────────────────────────────────────
    fetch('http://localhost:8003/api/siem/log', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        severity: 'Info', source: 'DAG', event_type: 'ReportDownloaded',
        message: `Attack simulation JSON report downloaded: ${simulationResult.id} (${formData.type})`,
        metadata: { sim_id: simulationResult.id, attack_type: formData.type, format: 'json' },
      }),
    }).catch(() => {});
  };

  const currentResult = simulationResult || mockResult;

  return (
    <div className="min-h-screen bg-background p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Attack Simulation (DAG)</h1>
          <p className="text-muted-foreground mt-1">
            Test model robustness against adversarial attacks (Connected to Backend)
          </p>
        </div>

        <Dialog open={open} onOpenChange={setOpen}>
          <DialogTrigger asChild>
            <Button size="lg">
              <Plus className="w-4 h-4 mr-2" />
              New Simulation
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto no-scrollbar bg-slate-900 dark:bg-slate-900 border-slate-700 dark:border-slate-700 text-white [&_label]:text-slate-200 [&_p]:text-slate-400">
            <DialogHeader>
              <DialogTitle className="text-white">Create Attack Simulation</DialogTitle>
              <DialogDescription className="text-slate-400">
                Configure and launch a new adversarial attack on the Python Backend.
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-6 py-4">
              {/* Simulation Name */}
              <div className="space-y-2">
                <Label htmlFor="name" className="text-slate-200">Simulation Name</Label>
                <Input
                  id="name"
                  placeholder="e.g., Test Run 1"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  className="bg-slate-800 border-slate-600 text-white placeholder:text-slate-500 focus:border-blue-500"
                />
              </div>

              {/* Attack Type Selection */}
              <div className="space-y-2">
                <Label htmlFor="attack-type" className="text-slate-200">Attack Type</Label>
                <Select
                  value={formData.type}
                  onValueChange={(value) =>
                    setFormData({ ...formData, type: value })
                  }
                >
                  <SelectTrigger id="attack-type" className="bg-slate-800 border-slate-600 text-white">
                    <SelectValue placeholder="Select attack type" />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-800 border-slate-600">
                    <SelectItem value="fgsm" className="text-white focus:bg-slate-700">FGSM (Gradient Attack)</SelectItem>
                    <SelectItem value="pgd" className="text-white focus:bg-slate-700">PGD (Iterative Attack)</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {/* Target Model */}
              <div className="space-y-2">
                <Label htmlFor="target-model" className="text-slate-200">Target Model</Label>
                <Select
                  value={formData.targetModel}
                  onValueChange={(value) => setFormData({ ...formData, targetModel: value })}
                >
                  <SelectTrigger id="target-model" className="bg-slate-800 border-slate-600 text-white">
                    <SelectValue placeholder="Select target model" />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-800 border-slate-600">
                    <SelectItem value="resnet50" className="text-white focus:bg-slate-700">ResNet-50</SelectItem>
                    <SelectItem value="vgg16" className="text-white focus:bg-slate-700">VGG-16</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {/* Dynamic Parameters based on Attack Type */}
              <div className="space-y-4">
                <h4 className="font-semibold text-white">Attack Parameters</h4>

                {/* PATCH Slider */}
                {formData.type === 'patch' && (
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Label htmlFor="patch-size" className="text-slate-200">Patch Size (% of Image)</Label>
                      <span className="text-sm text-slate-400">{formData.patchSize}%</span>
                    </div>
                    <input
                      id="patch-size"
                      type="range"
                      min={10} max={100} step={5}
                      value={formData.patchSize}
                      onChange={(e) => setFormData({ ...formData, patchSize: Number(e.target.value) })}
                      className="w-full h-2 rounded-full appearance-none cursor-pointer"
                      style={{
                        background: `linear-gradient(to right, #3b82f6 0%, #3b82f6 ${((formData.patchSize - 10) / 90) * 100}%, #334155 ${((formData.patchSize - 10) / 90) * 100}%, #334155 100%)`,
                        accentColor: '#3b82f6',
                      }}
                    />
                  </div>
                )}

                {/* FGSM / PGD Slider (Uses noiseLevel param) */}
                {(formData.type === 'fgsm' || formData.type === 'pgd') && (
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Label htmlFor="noise-level" className="text-slate-200">Attack Strength (Epsilon)</Label>
                      <span className="text-sm text-slate-400">{formData.noiseLevel}%</span>
                    </div>
                    <input
                      id="noise-level"
                      type="range"
                      min={0} max={100} step={5}
                      value={formData.noiseLevel}
                      onChange={(e) => setFormData({ ...formData, noiseLevel: Number(e.target.value) })}
                      className="w-full h-2 rounded-full appearance-none cursor-pointer"
                      style={{
                        background: `linear-gradient(to right, #3b82f6 0%, #3b82f6 ${formData.noiseLevel}%, #334155 ${formData.noiseLevel}%, #334155 100%)`,
                        accentColor: '#3b82f6',
                      }}
                    />
                    <p className="text-xs text-slate-400">
                      Higher strength increases success rate but makes the attack more visible.
                    </p>
                  </div>
                )}
              </div>
            </div>

            <DialogFooter>
              <Button variant="outline" onClick={() => setOpen(false)} disabled={isLoading}
                className="border-slate-600 text-slate-300 hover:bg-slate-700 hover:text-white">
                Cancel
              </Button>
              <Button 
                onClick={handleCreateSimulation} 
                disabled={!formData.name || !formData.targetModel || isLoading}
                className="bg-blue-600 hover:bg-blue-700 text-white"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    Running Attack...
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4 mr-2" />
                    Launch Simulation
                  </>
                )}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Status Card (Replaces the old list) */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Activity className="w-5 h-5 text-primary" />
            Backend Status
          </CardTitle>
          <CardDescription>
             System is ready. Click "New Simulation" to launch a real attack.
          </CardDescription>
        </CardHeader>
      </Card>

      {/* Results Dialog - DISPLAYS REAL DATA */}
      <Dialog open={selectedResult !== null} onOpenChange={() => setSelectedResult(null)}>
        <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto no-scrollbar bg-slate-900 border-slate-700 text-white">
          <DialogHeader>
            <DialogTitle className="text-white" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px' }}>
              <span>Results: {currentResult.id}</span>
              <div style={{ display: 'flex', gap: '6px' }}>
                <button onClick={handleSimPdfReport} disabled={!simulationResult || pdfLoading}
                  style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', padding: '4px 10px', fontSize: '11px', borderRadius: '6px', border: '1px solid rgba(239,68,68,0.4)', background: 'rgba(239,68,68,0.08)', color: simulationResult ? '#ef4444' : '#64748b', cursor: simulationResult ? 'pointer' : 'not-allowed' }}>
                  {pdfLoading ? 'Generating...' : 'PDF Report'}
                </button>
                <button onClick={handleSimJsonReport} disabled={!simulationResult}
                  style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', padding: '4px 10px', fontSize: '11px', borderRadius: '6px', border: '1px solid rgba(59,130,246,0.4)', background: 'rgba(59,130,246,0.08)', color: simulationResult ? '#3b82f6' : '#64748b', cursor: simulationResult ? 'pointer' : 'not-allowed' }}>
                  JSON Report
                </button>
              </div>
            </DialogTitle>
            <DialogDescription className="text-slate-400">
              Real-time analysis from ResNet-50
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-6 py-4">
            {/* Before/After Comparison */}
            <div>
              <h4 className="font-semibold mb-3 flex items-center gap-2">
                <Zap className="w-4 h-4" />
                Before/After Comparison
              </h4>
              <div className="grid grid-cols-2 gap-4">
                {/* Original Image */}
                <div className="space-y-2">
                  <Label>Original Image</Label>
                  <div className="border rounded-lg aspect-video bg-muted flex items-center justify-center overflow-hidden relative bg-black/5">
                    {currentResult.beforeImage ? (
                      <img 
                        src={currentResult.beforeImage} 
                        alt="Original" 
                        className="w-full h-full object-contain" 
                      />
                    ) : (
                      <span className="text-muted-foreground">No Data</span>
                    )}
                  </div>
                  <p className="text-sm text-muted-foreground">
                    Actual Class: <span className="font-medium text-foreground">
                      {currentResult.confusionMatrix?.[0]?.actual || 'Unknown'}
                    </span>
                  </p>
                </div>

                {/* Adversarial Image */}
                <div className="space-y-2">
                  <Label>Adversarial Image</Label>
                  <div className="border rounded-lg aspect-video bg-muted flex items-center justify-center overflow-hidden relative bg-black/5">
                    {currentResult.afterImage ? (
                      <img 
                        src={currentResult.afterImage} 
                        alt="Attacked" 
                        className="w-full h-full object-contain" 
                      />
                    ) : (
                      <span className="text-muted-foreground">No Data</span>
                    )}
                  </div>
                  <p className="text-sm text-muted-foreground">
                    Prediction: <span className="font-medium text-destructive">
                       {currentResult.confusionMatrix?.[0]?.predicted || 'Unknown'}
                    </span>
                    {' '}({(currentResult.confidence * 100).toFixed(1)}%)
                  </p>
                </div>
              </div>
            </div>

            {/* Success Metrics */}
            <div>
              <h4 className="font-semibold mb-3 flex items-center gap-2">
                <Target className="w-4 h-4" />
                Success Metrics
              </h4>
              <div className="grid grid-cols-3 gap-4">
                <Card>
                  <CardHeader className="pb-3">
                    <CardDescription>Attack Success</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="text-3xl font-bold">{currentResult.successRate}%</div>
                    <Progress value={currentResult.successRate} className="mt-2 h-2" />
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="pb-3">
                    <CardDescription>Model Confidence</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="text-3xl font-bold">
                      {(currentResult.confidence * 100).toFixed(1)}%
                    </div>
                    <Progress value={currentResult.confidence * 100} className="mt-2 h-2" />
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="pb-3">
                    <CardDescription>Test Status</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="text-3xl font-bold">
                        {currentResult.successRate > 0 ? "Fooled" : "Resisted"}
                    </div>
                    <p className="text-sm text-muted-foreground mt-2">
                      Single Image Test
                    </p>
                  </CardContent>
                </Card>
              </div>
            </div>

            {/* Confusion Matrix Details */}
            <div>
              <h4 className="font-semibold mb-3">Prediction Details</h4>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Predicted Class (Model Output)</TableHead>
                    <TableHead>Actual Class (Ground Truth)</TableHead>
                    <TableHead className="text-right">Count</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {currentResult.confusionMatrix?.map((item, index) => (
                    <TableRow key={index}>
                      <TableCell className="font-medium text-destructive">{item.predicted}</TableCell>
                      <TableCell className="text-green-600">{item.actual}</TableCell>
                      <TableCell className="text-right">{item.count}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setSelectedResult(null)}>
              Close Results
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}