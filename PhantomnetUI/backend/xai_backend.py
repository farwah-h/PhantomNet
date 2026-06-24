"""
XAI Explainability Engine Backend
PhantomNet++ - Module 3: XAI (Explainable AI Engine)

Runs on port 5001 (alongside threat detection on port 5000)

Endpoints:
  POST /api/xai/explain      - Generate explanation for an uploaded image
  GET  /api/xai/history      - Return recent explanations from in-memory store
  GET  /api/xai/health       - Health check
"""

import io
import os
import sys
import uuid
import base64
import json
import numpy as np
from datetime import datetime, timedelta, timezone
from pathlib import Path
from collections import deque
from typing import Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from PIL import Image

import torch
import torch.nn as nn
import torch.nn.functional as F
from torchvision import models, transforms
import requests
import uvicorn
from src_client import src_send

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# Path to YOUR trained autoencoder (same as threat_detection_backend.py)
AUTOENCODER_MODEL_PATH = Path(__file__).parent / "models" / "autoencoder.pth"

# ── SIEM logging helper ───────────────────────────────────────────────────────
SIEM_URL = "http://localhost:8003/api/siem/log"

def siem_log(severity: str, event_type: str, message: str, metadata: dict = {}):
    """Fire-and-forget SIEM log. Never raises."""
    try:
        requests.post(SIEM_URL, json={
            "severity": severity, "source": "XAI",
            "event_type": event_type, "message": message,
            "metadata": metadata,
        }, timeout=2)
    except Exception:
        pass

# In-memory history store (last 50 explanations)
explanation_history: deque = deque(maxlen=50)

# ─────────────────────────────────────────────────────────────────────────────
# AUTOENCODER ARCHITECTURE  (must match threat_detection_backend.py exactly)
# ─────────────────────────────────────────────────────────────────────────────
class ImprovedAutoencoder(nn.Module):
    def __init__(self, latent_dim=512):
        super().__init__()
        self.enc1 = nn.Sequential(nn.Conv2d(3,32,4,2,1),  nn.BatchNorm2d(32),  nn.LeakyReLU(0.2,True))
        self.enc2 = nn.Sequential(nn.Conv2d(32,64,4,2,1), nn.BatchNorm2d(64),  nn.LeakyReLU(0.2,True))
        self.enc3 = nn.Sequential(nn.Conv2d(64,128,4,2,1),nn.BatchNorm2d(128), nn.LeakyReLU(0.2,True))
        self.enc4 = nn.Sequential(nn.Conv2d(128,256,4,2,1),nn.BatchNorm2d(256),nn.LeakyReLU(0.2,True))
        self.fc_encoder = nn.Linear(256*4*4, latent_dim)
        self.fc_decoder = nn.Linear(latent_dim, 256*4*4)
        self.dec1 = nn.Sequential(nn.ConvTranspose2d(256,128,4,2,1),    nn.BatchNorm2d(128),    nn.ReLU(True))
        self.dec2 = nn.Sequential(nn.ConvTranspose2d(128+128,64,4,2,1), nn.BatchNorm2d(64),     nn.ReLU(True))
        self.dec3 = nn.Sequential(nn.ConvTranspose2d(64+64,32,4,2,1),   nn.BatchNorm2d(32),     nn.ReLU(True))
        self.dec4 = nn.Sequential(nn.ConvTranspose2d(32+32,3,4,2,1),    nn.Tanh())

    def forward(self, x):
        e1=self.enc1(x); e2=self.enc2(e1); e3=self.enc3(e2); e4=self.enc4(e3)
        e4f=e4.view(e4.size(0),-1); latent=self.fc_encoder(e4f)
        d=self.fc_decoder(latent).view(-1,256,4,4)
        d=self.dec1(d); d=self.dec2(torch.cat([d,e3],1)); d=self.dec3(torch.cat([d,e2],1)); d=self.dec4(torch.cat([d,e1],1))
        return d, latent

# ─────────────────────────────────────────────────────────────────────────────
# LOAD MODELS
# ─────────────────────────────────────────────────────────────────────────────
print(f"🚀 XAI Backend loading models on {DEVICE}...")

# ResNet50 (for Grad-CAM feature maps)
print("📦 Loading ResNet50 for Grad-CAM...")
try:
    weights       = models.ResNet50_Weights.DEFAULT
    resnet_model  = models.resnet50(weights=weights).to(DEVICE)
    resnet_model.eval()
    resnet_labels = weights.meta["categories"]
    preprocess_resnet = transforms.Compose([
        transforms.Resize(256),
        transforms.CenterCrop(224),
        transforms.ToTensor(),
        transforms.Normalize([0.485,0.456,0.406],[0.229,0.224,0.225]),
    ])
    print("✅ ResNet50 loaded")
except Exception as e:
    print(f"❌ ResNet50 failed: {e}")
    resnet_model = None

# Autoencoder (for reconstruction-based SHAP proxy)
print("📦 Loading Autoencoder...")
autoencoder_model = None
try:
    ae_path = Path(AUTOENCODER_MODEL_PATH)
    if ae_path.exists():
        autoencoder_model = ImprovedAutoencoder(latent_dim=512)
        ckpt = torch.load(ae_path, map_location=DEVICE, weights_only=False)
        autoencoder_model.load_state_dict(ckpt['model_state_dict'])
        autoencoder_model.eval()
        autoencoder_model.to(DEVICE)
        print("✅ Autoencoder loaded")
    else:
        print(f"⚠️  Autoencoder weights not found at {AUTOENCODER_MODEL_PATH}")
except Exception as e:
    print(f"❌ Autoencoder failed: {e}")

print("="*60)
print(f"  ResNet50:    {'✅' if resnet_model    else '❌'}")
print(f"  Autoencoder: {'✅' if autoencoder_model else '❌'}")
print("="*60)

# ─────────────────────────────────────────────────────────────────────────────
# PREPROCESSING HELPERS
# ─────────────────────────────────────────────────────────────────────────────
preprocess_ae = transforms.Compose([
    transforms.Resize((64,64)),
    transforms.ToTensor(),
    transforms.Normalize([0.485,0.456,0.406],[0.229,0.224,0.225]),
])

def pil_to_base64(img: Image.Image, size=(224,224)) -> str:
    img = img.resize(size, Image.BILINEAR)
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=90)
    return "data:image/jpeg;base64," + base64.b64encode(buf.getvalue()).decode()

def tensor_to_pil(t: torch.Tensor) -> Image.Image:
    """De-normalise a (1,3,H,W) or (3,H,W) tensor → PIL RGB."""
    if t.dim() == 4: t = t.squeeze(0)
    mean = torch.tensor([0.485,0.456,0.406]).view(3,1,1).to(t.device)
    std  = torch.tensor([0.229,0.224,0.225]).view(3,1,1).to(t.device)
    t = torch.clamp(t * std + mean, 0, 1)
    return transforms.ToPILImage()(t.cpu())

# ─────────────────────────────────────────────────────────────────────────────
# GRAD-CAM  (real implementation using ResNet50's last conv layer)
# ─────────────────────────────────────────────────────────────────────────────
class GradCAM:
    def __init__(self, model: nn.Module, target_layer: nn.Module):
        self.model        = model
        self.gradients    = None
        self.activations  = None
        self._hooks = [
            target_layer.register_forward_hook(self._save_activation),
            target_layer.register_backward_hook(self._save_gradient),
        ]

    def _save_activation(self, _, __, output):
        self.activations = output.detach()

    def _save_gradient(self, _, grad_in, grad_out):
        self.gradients = grad_out[0].detach()

    def remove_hooks(self):
        for h in self._hooks: h.remove()

    def generate(self, input_tensor: torch.Tensor, class_idx: Optional[int] = None):
        """Return (cam_numpy HxW in [0,1], pred_class_idx, pred_confidence)."""
        self.model.zero_grad()
        output = self.model(input_tensor)
        probs  = F.softmax(output, dim=1)

        if class_idx is None:
            class_idx = output.argmax(dim=1).item()

        score = output[0, class_idx]
        score.backward()

        # Global average pooling of gradients → weights
        weights = self.gradients.mean(dim=(2,3), keepdim=True)   # (1, C, 1, 1)
        cam     = (weights * self.activations).sum(dim=1, keepdim=True)  # (1,1,H,W)
        cam     = F.relu(cam)

        # Resize to input size and normalise
        cam = F.interpolate(cam, size=input_tensor.shape[2:], mode='bilinear', align_corners=False)
        cam = cam.squeeze().cpu().numpy()
        cam = (cam - cam.min()) / (cam.max() - cam.min() + 1e-8)

        confidence = probs[0, class_idx].item()
        return cam, class_idx, confidence


def cam_to_heatmap_pil(cam: np.ndarray, original_pil: Image.Image, alpha=0.5) -> Image.Image:
    """Overlay a Grad-CAM heatmap on the original image → returns PIL."""
    import colorsys

    original_resized = original_pil.resize((224, 224), Image.BILINEAR)
    orig_arr = np.array(original_resized).astype(np.float32)

    # Jet colormap without matplotlib
    h, w = cam.shape
    heat_rgb = np.zeros((h, w, 3), dtype=np.float32)
    for i in range(h):
        for j in range(w):
            v = cam[i, j]                  # 0-1
            # Blue→Cyan→Green→Yellow→Red
            if v < 0.25:
                r, g, b = 0, v*4, 1
            elif v < 0.5:
                r, g, b = 0, 1, 1-(v-0.25)*4
            elif v < 0.75:
                r, g, b = (v-0.5)*4, 1, 0
            else:
                r, g, b = 1, 1-(v-0.75)*4, 0
            heat_rgb[i, j] = [r*255, g*255, b*255]

    blended = (1-alpha) * orig_arr + alpha * heat_rgb
    blended = np.clip(blended, 0, 255).astype(np.uint8)
    return Image.fromarray(blended)


# ─────────────────────────────────────────────────────────────────────────────
# LIME  (superpixel-based feature importance using real model)
# ─────────────────────────────────────────────────────────────────────────────
def lime_explain(pil_image: Image.Image, model: nn.Module, preprocess, n_segments=16, n_samples=50):
    """
    Lightweight LIME:
      1. Segment image into superpixels
      2. Sample random binary masks
      3. Measure confidence change when each segment is masked
      4. Return per-segment importance + coloured overlay
    """
    img_arr = np.array(pil_image.resize((224, 224))).astype(np.float32) / 255.0
    h, w, _ = img_arr.shape

    # Simple grid superpixels (4×4 = 16 segments)
    rows = cols = int(np.sqrt(n_segments))
    seg_map = np.zeros((h, w), dtype=np.int32)
    rh, rw = h // rows, w // cols
    for r in range(rows):
        for c in range(cols):
            r0, r1 = r*rh, (r+1)*rh if r<rows-1 else h
            c0, c1 = c*rw, (c+1)*rw if c<cols-1 else w
            seg_map[r0:r1, c0:c1] = r*cols + c

    n_segs = rows * cols

    # Baseline prediction (no mask)
    baseline_tensor = preprocess(pil_image).unsqueeze(0).to(DEVICE)
    with torch.no_grad():
        base_out  = model(baseline_tensor)
        base_prob = F.softmax(base_out, dim=1)
        base_cls  = base_out.argmax(dim=1).item()
        base_conf = base_prob[0, base_cls].item()

    # Mean colour of image (used to fill masked segments)
    mean_color = img_arr.mean(axis=(0, 1))

    importances = np.zeros(n_segs)

    for _ in range(n_samples):
        mask = np.random.randint(0, 2, n_segs)
        masked = img_arr.copy()
        for seg_id in range(n_segs):
            if mask[seg_id] == 0:
                masked[seg_map == seg_id] = mean_color

        pil_masked = Image.fromarray((masked * 255).astype(np.uint8))
        t = preprocess(pil_masked).unsqueeze(0).to(DEVICE)
        with torch.no_grad():
            out   = model(t)
            probs = F.softmax(out, dim=1)
            conf  = probs[0, base_cls].item()

        delta = base_conf - conf    # positive → segment mattered
        for seg_id in range(n_segs):
            if mask[seg_id] == 1:
                importances[seg_id] += delta

    importances /= (n_samples * 0.5 + 1e-8)      # normalise
    importances  = np.clip(importances, 0, None)
    if importances.max() > 0:
        importances /= importances.max()

    # Build coloured overlay
    overlay = img_arr.copy()
    for seg_id in range(n_segs):
        imp = importances[seg_id]
        seg_mask = seg_map == seg_id
        # Tint: green (low) → red (high)
        tint = np.array([imp, 1-imp, 0], dtype=np.float32)
        overlay[seg_mask] = 0.55 * overlay[seg_mask] + 0.45 * tint

    overlay_pil = Image.fromarray((np.clip(overlay, 0, 1) * 255).astype(np.uint8))

    # Top features: rank segments by importance
    seg_labels  = [f"Region {i+1}" for i in range(n_segs)]
    top_indices = np.argsort(importances)[::-1][:8]
    features = [
        {"name": seg_labels[i], "importance": float(round(importances[i], 3))}
        for i in top_indices if importances[i] > 0.01
    ]

    return overlay_pil, features


# ─────────────────────────────────────────────────────────────────────────────
# SHAP  (autoencoder latent-dimension attribution)
# ─────────────────────────────────────────────────────────────────────────────
def shap_explain(pil_image: Image.Image, n_patches=16):
    """
    Autoencoder-based SHAP proxy:
      • Encode the image → latent vector z
      • Encode mean-masked patches → z_masked
      • Attribution per patch ≈ || z - z_masked ||
      • Visualise as coloured patch overlay
    """
    if autoencoder_model is None:
        return None, []

    img_64 = pil_image.resize((64, 64))
    img_arr = np.array(img_64).astype(np.float32) / 255.0

    # Full latent
    t_full = preprocess_ae(img_64).unsqueeze(0).to(DEVICE)
    with torch.no_grad():
        _, z_full = autoencoder_model(t_full)
    z_full = z_full.squeeze().cpu().numpy()

    rows = cols = int(np.sqrt(n_patches))
    ph, pw = 64 // rows, 64 // cols
    mean_color = img_arr.mean(axis=(0,1))

    importances = np.zeros(n_patches)
    for i in range(n_patches):
        r, c = divmod(i, cols)
        r0, r1 = r*ph, (r+1)*ph
        c0, c1 = c*pw, (c+1)*pw

        masked = img_arr.copy()
        masked[r0:r1, c0:c1] = mean_color
        pil_masked = Image.fromarray((masked*255).astype(np.uint8))
        t_m = preprocess_ae(pil_masked).unsqueeze(0).to(DEVICE)

        with torch.no_grad():
            _, z_m = autoencoder_model(t_m)
        z_m = z_m.squeeze().cpu().numpy()
        importances[i] = float(np.linalg.norm(z_full - z_m))

    if importances.max() > 0:
        importances /= importances.max()

    # Build 224×224 overlay
    img_224 = np.array(pil_image.resize((224,224))).astype(np.float32) / 255.0
    scale_h, scale_w = 224//rows, 224//cols
    overlay = img_224.copy()

    for i in range(n_patches):
        r, c  = divmod(i, cols)
        r0 = r*scale_h; r1 = (r+1)*scale_h
        c0 = c*scale_w; c1 = (c+1)*scale_w
        imp  = importances[i]
        # Colormap: blue (low) → red (high)
        tint = np.array([imp, 0.2, 1-imp], dtype=np.float32)
        overlay[r0:r1, c0:c1] = 0.5*overlay[r0:r1, c0:c1] + 0.5*tint

    overlay_pil = Image.fromarray((np.clip(overlay,0,1)*255).astype(np.uint8))

    # Feature list
    top = np.argsort(importances)[::-1][:8]
    features = [
        {"name": f"Patch ({i//cols+1},{i%cols+1})", "importance": float(round(importances[i], 3))}
        for i in top if importances[i] > 0.01
    ]
    return overlay_pil, features


# ─────────────────────────────────────────────────────────────────────────────
# APP
# ─────────────────────────────────────────────────────────────────────────────
app = FastAPI(title="XAI Engine API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────────────────────────────────────
# HEALTH
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/api/xai/health")
async def health():
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone(timedelta(hours=5))),
        "models": {
            "resnet": resnet_model is not None,
            "autoencoder": autoencoder_model is not None,
        },
        "device": str(DEVICE),
        "methods_available": {
            "gradcam": resnet_model is not None,
            "lime":    resnet_model is not None,
            "shap":    autoencoder_model is not None,
        }
    }

# ─────────────────────────────────────────────────────────────────────────────
# MAIN EXPLAIN ENDPOINT
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/xai/explain")
async def explain(
    image:          UploadFile = File(...),
    method:         str        = Form("gradcam"),          # gradcam | lime | shap
    scan_id:        str        = Form(""),                 # THR-XXXX from threat detection
    attack_type:    str        = Form("Unknown"),
    severity:       str        = Form("unknown"),
    confidence:     float      = Form(0.0),
    is_adversarial: str        = Form("false"),            # "true" / "false"
):
    method = method.lower().strip()
    if method not in ("gradcam", "lime", "shap"):
        raise HTTPException(status_code=400, detail="method must be gradcam | lime | shap")

    # ── Load image ──────────────────────────────────────────────────────────
    raw = await image.read()
    try:
        pil_image = Image.open(io.BytesIO(raw)).convert("RGB")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Cannot read image: {e}")

    original_b64 = pil_to_base64(pil_image)

    # ── ResNet prediction (always run, used by GradCAM & LIME) ───────────────
    pred_label      = "unknown"
    pred_confidence = confidence
    pred_class_idx  = None

    if resnet_model is not None:
        t = preprocess_resnet(pil_image).unsqueeze(0).to(DEVICE)
        with torch.no_grad():
            out   = resnet_model(t)
            probs = F.softmax(out, dim=1)
            idx   = out.argmax(1).item()
            pred_label      = resnet_labels[idx]
            pred_confidence = probs[0, idx].item()
            pred_class_idx  = idx

    # ── Generate explanation ─────────────────────────────────────────────────
    explanation_b64 = None
    features        = []

    if method == "gradcam":
        if resnet_model is None:
            raise HTTPException(status_code=503, detail="ResNet not loaded – GradCAM unavailable")

        gcam = GradCAM(resnet_model, resnet_model.layer4[-1])
        t    = preprocess_resnet(pil_image).unsqueeze(0).to(DEVICE)
        t.requires_grad_()
        cam, pred_class_idx, pred_confidence = gcam.generate(t, pred_class_idx)
        gcam.remove_hooks()

        heat_pil        = cam_to_heatmap_pil(cam, pil_image, alpha=0.55)
        explanation_b64 = pil_to_base64(heat_pil)

        # Feature importance from top activating regions (3×3 grid labels)
        h, w = cam.shape
        labels_grid = [
            "Top-left region", "Top-center region", "Top-right region",
            "Mid-left region",  "Center region",     "Mid-right region",
            "Bot-left region",  "Bot-center region", "Bot-right region",
        ]
        gh, gw = h//3, w//3
        region_scores = []
        for r in range(3):
            for c in range(3):
                region_scores.append(float(cam[r*gh:(r+1)*gh, c*gw:(c+1)*gw].mean()))

        # Sort by score
        paired = sorted(zip(region_scores, labels_grid), reverse=True)
        total  = sum(s for s, _ in paired) + 1e-8
        features = [
            {"name": lbl, "importance": round(s / total, 3)}
            for s, lbl in paired[:7] if s > 0
        ]

        description = (
            "Gradient-weighted Class Activation Mapping (Grad-CAM) uses gradients "
            "flowing into the final convolutional layer to produce a heatmap highlighting "
            "the image regions most influential for this prediction."
        )

    elif method == "lime":
        if resnet_model is None:
            raise HTTPException(status_code=503, detail="ResNet not loaded – LIME unavailable")

        overlay_pil, features = lime_explain(pil_image, resnet_model, preprocess_resnet,
                                              n_segments=16, n_samples=60)
        explanation_b64 = pil_to_base64(overlay_pil)
        description = (
            "LIME (Local Interpretable Model-agnostic Explanations) approximates the "
            "model locally by masking image superpixels and measuring the drop in "
            "prediction confidence, revealing which regions matter most."
        )

    elif method == "shap":
        if autoencoder_model is None:
            raise HTTPException(status_code=503, detail="Autoencoder not loaded – SHAP unavailable")

        overlay_pil, features = shap_explain(pil_image, n_patches=16)
        if overlay_pil is None:
            raise HTTPException(status_code=500, detail="SHAP generation failed")
        explanation_b64 = pil_to_base64(overlay_pil)
        pred_label = attack_type   # for SHAP, label comes from threat detection
        description = (
            "SHAP (SHapley Additive exPlanations) – here implemented via autoencoder "
            "latent-space attribution. Each image patch is masked and the shift in the "
            "latent representation measures how much that patch contributed to the "
            "reconstruction anomaly (and thus, the adversarial decision)."
        )

    # ── Build response ───────────────────────────────────────────────────────
    explanation_id = f"EXP-{str(uuid.uuid4())[:6].upper()}"
    record = {
        "id":              explanation_id,
        "scan_id":         scan_id or f"PRED-{np.random.randint(1000,9999)}",
        "timestamp":       datetime.now(timezone(timedelta(hours=5))),
        "method":          method.upper() if method != "gradcam" else "GradCAM",
        "prediction":      pred_label,
        "confidence":      round(float(pred_confidence), 4),
        "attack_type":     attack_type,
        "severity":        severity,
        "is_adversarial":  is_adversarial.lower() == "true",
        "original_image":  original_b64,
        "explanation_image": explanation_b64,
        "features":        features,
        "description":     description,
    }

    explanation_history.appendleft(record)

    # ── SIEM: log explanation generated ─────────────────────────────────────
    siem_log(
        severity   = "Warning" if is_adversarial else "Info",
        event_type = "ExplanationGenerated",
        message    = f"{method.upper()} explanation generated: {attack_type} ({confidence*100:.1f}% confidence)",
        metadata   = {
            "explanation_id": explanation_id,
            "scan_id":        scan_id,
            "method":         method,
            "attack_type":    attack_type,
            "severity":       severity,
            "is_adversarial": is_adversarial,
            "confidence":     round(confidence, 4),
        }
    )

    # ── SRC: log image retrieval from IVM and explanation result ─────────────
    # XAI received the image that originated from IVM's threat detection scan
    src_send(
        source      = "IVM",
        destination = "XAI",
        event_type  = "ImageTransferForExplanation",
        message     = (
            f"Scan image for {scan_id} transferred from IVM to XAI "
            f"for {method.upper()} explanation"
        ),
        metadata    = {
            "scan_id":    scan_id,
            "method":     method,
            "attack_type": attack_type,
        },
    )
    src_send(
        source      = "XAI",
        destination = "IVM",
        event_type  = "ExplanationResult",
        message     = (
            f"XAI {method.upper()} explanation complete for {scan_id} — "
            f"{attack_type} ({confidence*100:.1f}% confidence, {'adversarial' if is_adversarial else 'clean'})"
        ),
        metadata    = {
            "explanation_id": explanation_id,
            "scan_id":        scan_id,
            "method":         method,
            "attack_type":    attack_type,
            "is_adversarial": is_adversarial,
            "confidence":     round(confidence, 4),
        },
    )

    # Don't return base64 images in history (too heavy); only in immediate response
    return record


# ─────────────────────────────────────────────────────────────────────────────
# HISTORY  (no images in list, just metadata)
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/api/xai/history")
async def history(limit: int = 20):
    slim = []
    for rec in list(explanation_history)[:limit]:
        slim.append({k: v for k, v in rec.items()
                     if k not in ("original_image", "explanation_image")})
    return {"history": slim, "total": len(explanation_history)}


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5001, reload=False)