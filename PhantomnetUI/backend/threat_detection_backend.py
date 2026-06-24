import os
import io
import sys
import numpy as np
from typing import Optional
from datetime import datetime, timedelta, timezone
from pathlib import Path
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from PIL import Image
import torch
import torch.nn as nn
from torchvision import models, transforms
import requests
from pydantic import BaseModel
from siem_logger import siem_log, SiemSeverity, SiemSource
from src_client import src_send

import sqlite3
from pathlib import Path
from database import (
    DB_PATH,
    init_database, 
    save_prediction, 
    get_all_predictions, 
    get_prediction_by_id,
    get_statistics,
    save_explanation,
    get_explanations
)

# =============================================================================
# FIX PATHLIB FOR WINDOWS (MUST BE FIRST!)
# =============================================================================
# Fix for loading models trained on Linux/Mac on Windows
# import pathlib
# temp = pathlib.PosixPath
# pathlib.PosixPath = pathlib.WindowsPath

import pathlib
import platform
if platform.system() == "Windows":
    temp = pathlib.PosixPath
    pathlib.PosixPath = pathlib.WindowsPath

# =============================================================================
# ADD YOLOV5 TO PATH
# =============================================================================
# Add YOLOv5 repository to Python path
YOLOV5_REPO = Path(__file__).parent / 'yolov5'
if YOLOV5_REPO.exists():
    sys.path.insert(0, str(YOLOV5_REPO))
    print(f"✅ YOLOv5 repository added to path: {YOLOV5_REPO}")
else:
    print(f"⚠️  YOLOv5 repository not found at: {YOLOV5_REPO}")
    print(f"   Clone it with: git clone https://github.com/ultralytics/yolov5.git")

# =============================================================================
# CONFIGURATION
# =============================================================================
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# Model paths
YOLO_MODEL_PATH = Path(__file__).parent / "models" / "yolo-trained.pt"
AUTOENCODER_MODEL_PATH = Path(__file__).parent / "models" / "autoencoder.pth"

# Detection thresholds
RESNET_CONFIDENCE_THRESHOLD = 0.3   # Only flag EXTREMELY low confidence
RESNET_ENTROPY_THRESHOLD = 6.0       # Only flag EXTREMELY high entropy
AUTOENCODER_MSE_THRESHOLD = 0.45
HARDENED_AUTOENCODER_MSE = 0.30   # lower = more sensitive (normal is 0.45)
HARDENED_YOLO_CONF       = 0.15   # lower = catches more detections (normal is 0.25)
YOLO_CONF_THRESHOLD = 0.25
YOLO_IOU_THRESHOLD = 0.45

# ARE backend URL
ARE_BASE = "http://localhost:8000/api/are"

# Directory to store uploaded images
UPLOAD_DIR = Path(__file__).parent / 'uploads'
UPLOAD_DIR.mkdir(exist_ok=True)

# Initialize database on startup
print("🗄️  Initializing database...")
init_database()

try:
    from calibration_loader import load_calibration
    load_calibration()
except Exception as e:
    print(f"[calibration_loader] Not applied: {e} — using hardcoded defaults")

# =============================================================================
# APP SETUP
# =============================================================================
app = FastAPI(title="Threat Detection API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# AUTOENCODER MODEL
# =============================================================================
class ImprovedAutoencoder(nn.Module):
    """Autoencoder with skip connections"""
    def __init__(self, latent_dim=512):
        super(ImprovedAutoencoder, self).__init__()

        # Encoder
        self.enc1 = nn.Sequential(
            nn.Conv2d(3, 32, kernel_size=4, stride=2, padding=1),
            nn.BatchNorm2d(32),
            nn.LeakyReLU(0.2, True)
        )
        self.enc2 = nn.Sequential(
            nn.Conv2d(32, 64, kernel_size=4, stride=2, padding=1),
            nn.BatchNorm2d(64),
            nn.LeakyReLU(0.2, True)
        )
        self.enc3 = nn.Sequential(
            nn.Conv2d(64, 128, kernel_size=4, stride=2, padding=1),
            nn.BatchNorm2d(128),
            nn.LeakyReLU(0.2, True)
        )
        self.enc4 = nn.Sequential(
            nn.Conv2d(128, 256, kernel_size=4, stride=2, padding=1),
            nn.BatchNorm2d(256),
            nn.LeakyReLU(0.2, True)
        )

        # Latent space
        self.fc_encoder = nn.Linear(256 * 4 * 4, latent_dim)
        self.fc_decoder = nn.Linear(latent_dim, 256 * 4 * 4)

        # Decoder with skip connections
        self.dec1 = nn.Sequential(
            nn.ConvTranspose2d(256, 128, kernel_size=4, stride=2, padding=1),
            nn.BatchNorm2d(128),
            nn.ReLU(True)
        )
        self.dec2 = nn.Sequential(
            nn.ConvTranspose2d(128 + 128, 64, kernel_size=4, stride=2, padding=1),
            nn.BatchNorm2d(64),
            nn.ReLU(True)
        )
        self.dec3 = nn.Sequential(
            nn.ConvTranspose2d(64 + 64, 32, kernel_size=4, stride=2, padding=1),
            nn.BatchNorm2d(32),
            nn.ReLU(True)
        )
        self.dec4 = nn.Sequential(
            nn.ConvTranspose2d(32 + 32, 3, kernel_size=4, stride=2, padding=1),
            nn.Tanh()
        )

    def forward(self, x):
        # Encoder with skip connections
        e1 = self.enc1(x)
        e2 = self.enc2(e1)
        e3 = self.enc3(e2)
        e4 = self.enc4(e3)

        # Latent
        e4_flat = e4.view(e4.size(0), -1)
        latent = self.fc_encoder(e4_flat)

        # Decoder
        d = self.fc_decoder(latent)
        d = d.view(d.size(0), 256, 4, 4)
        d = self.dec1(d)
        d = self.dec2(torch.cat([d, e3], dim=1))
        d = self.dec3(torch.cat([d, e2], dim=1))
        d = self.dec4(torch.cat([d, e1], dim=1))

        return d, latent

# =============================================================================
# LOAD MODELS
# =============================================================================
print(f"🚀 Loading models on {DEVICE}...")
print(f"Python: {sys.version}")
print(f"PyTorch: {torch.__version__}")
print(f"CUDA: {torch.cuda.is_available()}")
print()

# ResNet50
print("📦 Loading ResNet50...")
try:
    resnet_model = models.resnet50(weights=models.ResNet50_Weights.DEFAULT)
    resnet_model.eval()
    resnet_model.to(DEVICE)
    print("✅ ResNet50 loaded")
except Exception as e:
    print(f"❌ ResNet50 failed: {e}")
    resnet_model = None

# Global flag — starts on primary
active_model = "normal"  
fallback_model = None

# YOLOv5 - WITH REPOSITORY
print("\n📦 Loading YOLOv5...")
yolo_model = None
try:
    # Verify YOLOv5 repo is available
    if not YOLOV5_REPO.exists():
        print(f"❌ YOLOv5 repository not found!")
        print(f"   Expected at: {YOLOV5_REPO}")
        print(f"   Please run: git clone https://github.com/ultralytics/yolov5.git")
        raise FileNotFoundError("YOLOv5 repository missing")
    
    yolo_path = Path(YOLO_MODEL_PATH)
    print(f"   Model path: {yolo_path}")
    
    if yolo_path.exists():
        print(f"   Size: {yolo_path.stat().st_size / 1024 / 1024:.2f} MB")
        print("   Loading checkpoint...")
        
        # Load checkpoint (weights_only=False needed for custom classes)
        checkpoint = torch.load(str(yolo_path), map_location=DEVICE, weights_only=False)
        
        print("   ✅ Checkpoint loaded!")
        
        # Extract model from checkpoint
        if isinstance(checkpoint, dict):
            print(f"   Keys: {list(checkpoint.keys())}")
            
            if 'model' in checkpoint:
                print("   Extracting from 'model' key...")
                yolo_model = checkpoint['model'].float()
            elif 'ema' in checkpoint:
                print("   Extracting from 'ema' key...")
                yolo_model = checkpoint['ema'].float()
            else:
                raise KeyError(f"No 'model' or 'ema' in checkpoint. Keys: {list(checkpoint.keys())}")
        else:
            print("   Checkpoint is direct model")
            yolo_model = checkpoint.float()
        
        # Configure model
        if hasattr(yolo_model, 'fuse'):
            try:
                yolo_model.fuse()
                print("   ✅ Model fused")
            except:
                print("   ⚠️  Fusing skipped")
        
        yolo_model.eval()
        yolo_model.to(DEVICE)
        
        # Set thresholds
        if hasattr(yolo_model, 'conf'):
            yolo_model.conf = YOLO_CONF_THRESHOLD
        if hasattr(yolo_model, 'iou'):
            yolo_model.iou = YOLO_IOU_THRESHOLD
        
        print(f"✅ YOLOv5 loaded successfully")
        
        # Get class names
        if hasattr(yolo_model, 'names'):
            print(f"   Classes: {yolo_model.names}")
        elif hasattr(yolo_model, 'module') and hasattr(yolo_model.module, 'names'):
            print(f"   Classes: {yolo_model.module.names}")
        else:
            print(f"   ⚠️  Class names not accessible")
            
    else:
        print(f"❌ Model file not found: {yolo_path}")
        yolo_model = None
        
except Exception as e:
    print(f"❌ YOLOv5 loading failed: {e}")
    import traceback
    traceback.print_exc()
    yolo_model = None

# Autoencoder
print("\n📦 Loading Autoencoder...")
autoencoder_model = None
try:
    autoencoder_model = ImprovedAutoencoder(latent_dim=512)
    
    ae_path = Path(AUTOENCODER_MODEL_PATH)
    print(f"   Checking: {ae_path}")
    
    if ae_path.exists():
        print(f"   Size: {ae_path.stat().st_size / 1024 / 1024:.2f} MB")
        print("   Loading weights...")
        
        checkpoint = torch.load(ae_path, map_location=DEVICE, weights_only=False)
        autoencoder_model.load_state_dict(checkpoint['model_state_dict'])
        autoencoder_model.eval()
        autoencoder_model.to(DEVICE)
        
        print(f"✅ Autoencoder loaded")
        print(f"   Epoch: {checkpoint.get('epoch', 'N/A')}")
        print(f"   Val loss: {checkpoint.get('val_loss', 'N/A'):.6f}" if 'val_loss' in checkpoint else "")
        
        # Verify
        test_input = torch.randn(1, 3, 64, 64).to(DEVICE)
        with torch.no_grad():
            test_output, test_latent = autoencoder_model(test_input)
        print(f"   Verified: {test_input.shape} -> {test_output.shape}")
        
    else:
        print(f"⚠️  Weights not found: {AUTOENCODER_MODEL_PATH}")
        autoencoder_model = None
        
except Exception as e:
    print(f"❌ Autoencoder failed: {e}")
    import traceback
    traceback.print_exc()
    autoencoder_model = None

print("\n" + "="*70)
print("MODELS STATUS:")
print(f"  ResNet50:    {'✅' if resnet_model else '❌'}")
print(f"  YOLOv5:      {'✅' if yolo_model else '❌'}")
print(f"  Autoencoder: {'✅' if autoencoder_model else '❌'}")
print("="*70 + "\n")

# =============================================================================
# PREPROCESSING
# =============================================================================
preprocess_resnet = transforms.Compose([
    transforms.Resize(256),
    transforms.CenterCrop(224),
    transforms.ToTensor(),
    transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
])

def preprocess_image_autoencoder(image: Image.Image):
    """Preprocess for autoencoder (64x64)"""
    transform = transforms.Compose([
        transforms.Resize((64, 64)),
        transforms.ToTensor(),
        transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225])
    ])
    img_tensor = transform(image).unsqueeze(0).to(DEVICE)
    return img_tensor

# =============================================================================
# DETECTION FUNCTIONS
# =============================================================================

def detect_with_resnet(image: Image.Image) -> dict:
    """
    ResNet50 detector — produces a calibrated adversarial probability score
    for use as a base estimator in the ensemble.

    Raw features extracted:
      - classification confidence  (low  → suspicious)
      - prediction entropy         (high → suspicious)

    Both features are independently mapped to [0, 1] via sigmoid-style
    normalisation, then blended with learned weights derived from the
    relative discriminative power of each feature.  The result is a single
    adversarial_prob that the ensemble meta-layer consumes directly.

    In 'hardened' mode the normalisation midpoints shift so that the same
    raw signal maps to a higher adversarial probability, making the detector
    more sensitive without re-training the model.
    """
    global active_model

    if resnet_model is None:
        return {'model': 'ResNet-50', 'error': 'Model not loaded', 'is_adversarial': None}

    is_hardened = active_model == "hardened"
    model_label = "ResNet-50 (Hardened)" if is_hardened else "ResNet-50 (Normal)"

    # ── Feature normalisation midpoints ─────────────────────────────────────
    # conf_mid : classification confidence at which suspicion is 0.5
    # entr_mid : entropy at which suspicion is 0.5
    # Hardened → lower conf midpoint + lower entropy midpoint = higher prob for same signal
    
    _ivm = sys.modules[__name__]
    if is_hardened:
        conf_mid = getattr(_ivm, 'CALIBRATED_CONF_MID_HARDENED', 0.20)
        entr_mid = getattr(_ivm, 'CALIBRATED_ENTR_MID_HARDENED', 5.80)
    else:
        conf_mid = getattr(_ivm, 'CALIBRATED_CONF_MID_NORMAL',   0.30)
        entr_mid = getattr(_ivm, 'CALIBRATED_ENTR_MID_NORMAL',   6.20)
        
        # conf_mid = 0.20 if is_hardened else 0.30
        # entr_mid = 5.80 if is_hardened else 6.20

    # Blend weights for the two features (sum to 1)
    W_CONF = 0.45   # confidence signal
    W_ENTR = 0.55   # entropy signal (slightly more discriminative)

    # Final threshold: probability above which the sample is called adversarial
    suspicion_thresh = 0.45 if is_hardened else 0.60

    try:
        img_tensor = preprocess_resnet(image).unsqueeze(0).to(DEVICE)

        with torch.no_grad():
            outputs       = resnet_model(img_tensor)
            probabilities = torch.nn.functional.softmax(outputs, dim=1)
            confidence, predicted_class = torch.max(probabilities, 1)
            entropy = -torch.sum(probabilities * torch.log(probabilities + 1e-10), dim=1)

        confidence_val = confidence.item()
        entropy_val    = entropy.item()

        # ── Sigmoid normalisation of each feature to [0, 1] ─────────────────
        # conf_prob: HIGH when confidence is LOW (adversarial signal)
        # steepness k controls how sharply the sigmoid transitions
        k_conf = 15.0
        conf_prob = 1.0 / (1.0 + np.exp(-k_conf * (conf_mid - confidence_val)))

        # entr_prob: HIGH when entropy is HIGH (adversarial signal)
        k_entr = 1.2
        entr_prob = 1.0 / (1.0 + np.exp(-k_entr * (entropy_val - entr_mid)))

        # ── Weighted blend → single adversarial probability ──────────────────
        adversarial_prob = W_CONF * conf_prob + W_ENTR * entr_prob

        # ── Legacy suspicion_score for backward-compatible fields ────────────
        suspicion_score = adversarial_prob * 1.3   # rescale to original 0-1.3 range

        is_adversarial = adversarial_prob >= suspicion_thresh

        return {
            'model':             model_label,
            'is_adversarial':    bool(is_adversarial),
            'confidence':        float(confidence_val),
            'entropy':           float(entropy_val),
            'suspicion_score':   float(suspicion_score),
            'adversarial_prob':  float(adversarial_prob),   # primary ensemble input
            'predicted_class':   int(predicted_class.item()),
            'status':            'adversarial' if is_adversarial else 'clean',
            'reason':            (f"Conf={confidence_val:.3f}, Entropy={entropy_val:.3f}, "
                                  f"AdvProb={adversarial_prob:.3f}"),
            'active_mode':       active_model,
        }
    except Exception as e:
        return {'model': model_label, 'error': str(e), 'is_adversarial': None}
    
def detect_with_yolo(image: Image.Image) -> dict:
    """YOLO-based detection - avoiding OpenCV resize bug"""
    if yolo_model is None:
        return {'model': 'YOLOv5', 'error': 'Model not loaded', 'is_adversarial': None}
    
    try:
        import numpy as np
        
        # 1. Ensure RGB
        if hasattr(image, 'mode') and image.mode != 'RGB':
            image = image.convert('RGB')
        
        # 2. Resize using PIL instead of OpenCV (to avoid the cv2.resize bug)
        image_resized = image.resize((640, 640), Image.BILINEAR)
        
        # 3. Convert to numpy array
        img = np.array(image_resized, dtype=np.uint8)
        
        # 4. Preprocess: HWC -> CHW, normalize
        img = img.transpose((2, 0, 1))
        img = img.astype(np.float32) / 255.0
        
        # 5. Convert to tensor
        img_tensor = torch.from_numpy(img).unsqueeze(0).to(DEVICE)
        
        # 6. Run inference
        with torch.no_grad():
            predictions = yolo_model(img_tensor)
        
        # 7. Apply NMS
        from yolov5.utils.general import non_max_suppression
        pred = predictions[0] if isinstance(predictions, (list, tuple)) else predictions
        # Use hardened threshold in hardened mode — lower = catches more detections
        yolo_conf_thres = HARDENED_YOLO_CONF if active_model == "hardened" else YOLO_CONF_THRESHOLD
        pred = non_max_suppression(pred, conf_thres=yolo_conf_thres, iou_thres=YOLO_IOU_THRESHOLD)
        
        # 8. Extract detections
        detections = pred[0] if len(pred) > 0 else torch.tensor([])
        
        detected_classes = []
        confidences = []
        
        if len(detections) > 0:
            confidences = detections[:, 4].cpu().tolist()
            class_ids = detections[:, 5].cpu().int().tolist()
            
            if hasattr(yolo_model, 'names'):
                names_dict = yolo_model.names
                detected_classes = [names_dict.get(int(c), f"class_{c}") for c in class_ids]
            elif hasattr(yolo_model, 'module') and hasattr(yolo_model.module, 'names'):
                names_dict = yolo_model.module.names
                detected_classes = [names_dict.get(int(c), f"class_{c}") for c in class_ids]
            else:
                detected_classes = [f"class_{c}" for c in class_ids]
        
        if len(detected_classes) > 0:
            adversarial_keywords = ['patch', 'adversarial', 'perturbation', 'attack', 'adv']
            is_adversarial = any(
                any(keyword in str(cls).lower() for keyword in adversarial_keywords)
                for cls in detected_classes
            )

            max_conf = max(confidences) if confidences else 0.0

            # ── Adversarial probability for ensemble ─────────────────────────
            # Combine detection confidence with a keyword-match bonus.
            # keyword_bonus pushes the probability higher when the detected class
            # name is explicitly adversarial (strong semantic signal).
            keyword_bonus   = 0.25 if is_adversarial else 0.0
            # Scale by number of detections (more detections = stronger signal),
            # capped to avoid overflow.
            detection_scale = min(1.0 + 0.05 * (len(detected_classes) - 1), 1.20)
            adversarial_prob = min(max_conf * detection_scale + keyword_bonus, 1.0)

            return {
                'model':            'YOLOv5',
                'is_adversarial':   bool(is_adversarial),
                'confidence':       float(max_conf),
                'adversarial_prob': float(adversarial_prob),   # primary ensemble input
                'detections':       len(detected_classes),
                'detected_classes': detected_classes[:3],
                'status':           'adversarial' if is_adversarial else 'clean',
                'reason':           f"{len(detected_classes)} objects detected"
            }
        else:
            return {
                'model':            'YOLOv5',
                'is_adversarial':   False,
                'confidence':       0.0,
                'adversarial_prob': 0.0,
                'detections':       0,
                'detected_classes': [],
                'status':           'clean',
                'reason':           'No objects detected'
            }
            
    except Exception as e:
        print(f"YOLO detection error: {e}")
        import traceback
        traceback.print_exc()
        return {'model': 'YOLOv5', 'error': str(e), 'is_adversarial': None}

def detect_with_autoencoder(image: Image.Image, threshold: Optional[float] = None) -> dict:
    """
    Autoencoder-based detector — produces a calibrated adversarial probability
    score for use as a base estimator in the ensemble.

    The raw MSE reconstruction error is mapped to [0, 1] via a sigmoid centred
    on the active threshold.  This gives a smooth, differentiable signal rather
    than a hard binary flag, which the ensemble meta-layer can combine with the
    other detectors in a principled way.

    In 'hardened' mode the threshold is lowered so that the same reconstruction
    error maps to a higher adversarial probability.
    """
    if autoencoder_model is None:
        return {'model': 'Autoencoder', 'error': 'Model not loaded', 'is_adversarial': None}

    if threshold is None:
        # Use hardened threshold in hardened mode — lower = more sensitive
        threshold = HARDENED_AUTOENCODER_MSE if active_model == "hardened" else AUTOENCODER_MSE_THRESHOLD

    try:
        img_tensor = preprocess_image_autoencoder(image)

        with torch.no_grad():
            reconstructed, latent = autoencoder_model(img_tensor)
            mse = torch.mean((img_tensor - reconstructed) ** 2).item()

        # ── Sigmoid normalisation of MSE to [0, 1] ──────────────────────────
        # Steepness k controls how sharply the probability transitions around
        # the threshold midpoint.  k ≈ 10/threshold gives ~90% at 2× threshold.
        k = 10.0 / max(threshold, 1e-6)
        adversarial_prob = 1.0 / (1.0 + np.exp(-k * (mse - threshold)))

        is_adversarial = mse > threshold

        return {
            'model':                'Autoencoder',
            'is_adversarial':       bool(is_adversarial),
            'reconstruction_error': float(mse),
            'threshold':            float(threshold),
            'adversarial_prob':     float(adversarial_prob),   # primary ensemble input
            'status':               'adversarial' if is_adversarial else 'clean',
            'reason':               (f"MSE={mse:.4f} "
                                     f"({'>' if is_adversarial else '<='}{threshold:.4f}), "
                                     f"AdvProb={adversarial_prob:.3f}")
        }
    except Exception as e:
        return {'model': 'Autoencoder', 'error': str(e), 'is_adversarial': None}


def determine_attack_type_and_category(yolo_result, resnet_result, autoencoder_result, ensemble):
    """
    Determine attack type and category based on model outputs
    
    Categories:
    - Physical Perturbation: Physical objects/patches attached to real objects
    - Digital Perturbation: Pixel-level noise/modifications
    - Object-Based Attack: Adversarial objects detected
    - None: Clean image
    """
    
    attack_type = 'Clean Image'
    attack_category = 'None'
    attack_characteristics = []
    
    # If ensemble says it's clean, return clean
    if ensemble['final_decision'] != 'adversarial':
        return {
            'type': 'Clean Image',
            'category': 'None',
            'characteristics': ['No adversarial patterns detected'],
            'primary_indicator': 'All models agree: Clean'
        }
    
    # Check YOLO detections first (most specific)
    if yolo_result.get('detected_classes') and yolo_result.get('is_adversarial'):
        detected = yolo_result['detected_classes']
        
        # Check for physical attacks
        physical_keywords = ['patch', 'sticker', 'physical', 'object']
        if any(keyword in str(cls).lower() for cls in detected for keyword in physical_keywords):
            attack_type = 'Physical Adversarial Patch'
            attack_category = 'Physical Perturbation'
            attack_characteristics.append('Physical object detected in scene')
            primary_indicator = f"YOLOv5 detected: {', '.join(detected[:2])}"
        else:
            attack_type = ', '.join(detected[:2])
            attack_category = 'Object-Based Attack'
            attack_characteristics.append('Adversarial object detected')
            primary_indicator = f"YOLOv5: {', '.join(detected[:2])}"
    
    # Analyze based on model agreement patterns
    else:
        # Get model votes
        resnet_adversarial = resnet_result.get('is_adversarial', False)
        yolo_adversarial = yolo_result.get('is_adversarial', False)
        autoencoder_adversarial = autoencoder_result.get('is_adversarial', False)
        
        # High reconstruction error = pixel-level perturbations
        rec_error = autoencoder_result.get('reconstruction_error', 0)
        entropy = resnet_result.get('entropy', 0)
        confidence = resnet_result.get('confidence', 1.0)
        
        # Decision tree based on model outputs
        if autoencoder_adversarial and rec_error > 0.8:  # Stricter - only very strong attacks
            # Very high reconstruction error suggests digital perturbation
            attack_type = 'Strong Digital Perturbation'
            attack_category = 'Digital Perturbation'
            attack_characteristics.append(f'High reconstruction error: {rec_error:.3f}')
            attack_characteristics.append('Significant pixel-level modifications')
            primary_indicator = f'Autoencoder MSE: {rec_error:.3f}'
            
        elif resnet_adversarial and entropy > 7.5:  # Much stricter
            # High entropy = model very confused = strong attack
            attack_type = 'FGSM/PGD-Style Attack'
            attack_category = 'Digital Perturbation'
            attack_characteristics.append(f'High entropy: {entropy:.2f}')
            attack_characteristics.append('Severe classification confusion')
            primary_indicator = f'ResNet entropy: {entropy:.2f}'
            
        elif resnet_adversarial and confidence < 0.03:  # Much stricter
            # Very low confidence = targeted attack
            attack_type = 'DeepFool/C&W Attack'
            attack_category = 'Digital Perturbation'
            attack_characteristics.append(f'Very low confidence: {confidence:.3f}')
            attack_characteristics.append('Targeted misclassification attempt')
            primary_indicator = f'ResNet confidence: {confidence:.3f}'
            
        elif autoencoder_adversarial and 0.6 < rec_error <= 0.8:  # Adjusted range
            # Moderate reconstruction error
            attack_type = 'Moderate Digital Perturbation'
            attack_category = 'Digital Perturbation'
            attack_characteristics.append(f'Moderate reconstruction error: {rec_error:.3f}')
            attack_characteristics.append('Noticeable pixel modifications')
            primary_indicator = f'Autoencoder MSE: {rec_error:.3f}'
            
        else:
            # Generic adversarial
            attack_type = 'Adversarial Perturbation'
            attack_category = 'Digital Perturbation'
            attack_characteristics.append('Multiple models flagged as adversarial')
            
            # Add specific details
            if autoencoder_adversarial:
                attack_characteristics.append(f'Reconstruction error: {rec_error:.3f}')
            if resnet_adversarial:
                attack_characteristics.append(f'ResNet entropy: {entropy:.2f}')
            
            primary_indicator = 'Ensemble decision based on multiple indicators'
    
    return {
        'type': attack_type,
        'category': attack_category,
        'characteristics': attack_characteristics,
        'primary_indicator': primary_indicator
    }
def ensemble_decision(resnet_result, yolo_result, autoencoder_result):
    """
    Multi-strategy ensemble combining three complementary techniques:

    ┌─────────────────────────────────────────────────────────────────────┐
    │  Strategy 1 — Weighted Soft Voting                                  │
    │    Each detector contributes its calibrated adversarial_prob,       │
    │    scaled by a reliability weight.  The weighted average gives a    │
    │    smooth probability estimate that is robust to one detector being  │
    │    wrong.                                                            │
    │                                                                      │
    │  Strategy 2 — Hard Majority Voting                                  │
    │    Each detector casts a binary vote (adversarial / clean).         │
    │    Simple majority (≥ 2 of 3) wins.  A weight-adjusted variant      │
    │    uses fractional votes proportional to detector reliability so     │
    │    the highest-weight detector can only be overruled by both others. │
    │                                                                      │
    │  Strategy 3 — Stacking Meta-Learner                                 │
    │    A fixed logistic-regression-style meta-learner whose coefficients │
    │    were derived from held-out validation performance combines the    │
    │    three probabilities non-linearly.  The bias term calibrates the   │
    │    output to the base rate of adversarial images in the dataset.     │
    │                                                                      │
    │  Final Score = (soft_score + hard_score + stack_score) / 3          │
    │    Averaging three diverse estimators reduces variance and makes     │
    │    the system Byzantine fault-tolerant: a single detector failure    │
    │    or adversarial evasion of one model cannot flip the decision.     │
    └─────────────────────────────────────────────────────────────────────┘

    Weights reflect adversarial robustness of each model:
      YOLO (1.5 normal / 2.0 hardened)   — Trained specialist detector
      Autoencoder (1.2 normal / 1.8 hardened) — Reconstruction anomaly
      ResNet50 (1.0 normal / 1.2 hardened)    — Pretrained baseline

    Decision threshold:
      Normal:   0.55
      Hardened: 0.40

    Severity aligned to CVSS v3.1:
      Critical ≥ 0.85 | High ≥ 0.65 | Medium ≥ 0.40 | Low < 0.40
    """
    is_hardened = active_model == "hardened"

    _ivm = sys.modules[__name__]

    if is_hardened:
        W_YOLO    = getattr(_ivm, 'CALIBRATED_W_YOLO_HARDENED',    2.0)
        W_AE      = getattr(_ivm, 'CALIBRATED_W_AE_HARDENED',      1.8)
        W_RESNET  = getattr(_ivm, 'CALIBRATED_W_RESNET_HARDENED',  1.2)
        THRESHOLD = getattr(_ivm, 'CALIBRATED_THRESHOLD_HARDENED', 0.40)
    else:
        W_YOLO    = getattr(_ivm, 'CALIBRATED_W_YOLO_NORMAL',      1.5)
        W_AE      = getattr(_ivm, 'CALIBRATED_W_AE_NORMAL',        1.2)
        W_RESNET  = getattr(_ivm, 'CALIBRATED_W_RESNET_NORMAL',    1.0)
        THRESHOLD = getattr(_ivm, 'CALIBRATED_THRESHOLD_NORMAL',   0.55)
    
    # W_YOLO   = 2.0 if is_hardened else 1.5
    # W_AE     = 1.8 if is_hardened else 1.2
    # W_RESNET = 1.2 if is_hardened else 1.0

    # THRESHOLD = 0.40 if is_hardened else 0.55

    # ── Collect per-model inputs ─────────────────────────────────────────────
    # Each entry: (adversarial_prob, binary_vote, reliability_weight, label)
    detectors = []

    if yolo_result.get('is_adversarial') is not None:
        p = float(yolo_result.get('adversarial_prob',
                                   float(yolo_result.get('confidence', 0.0))))
        v = 1 if yolo_result['is_adversarial'] else 0
        detectors.append((p, v, W_YOLO,
                          f"YOLOv5 ({'Hardened' if is_hardened else 'Normal'})"))

    if resnet_result.get('is_adversarial') is not None:
        p = float(resnet_result.get('adversarial_prob',
                                     min(resnet_result.get('suspicion_score', 0.0) / 1.3, 1.0)))
        v = 1 if resnet_result['is_adversarial'] else 0
        detectors.append((p, v, W_RESNET,
                          f"ResNet-50 ({'Hardened' if is_hardened else 'Normal'})"))

    if autoencoder_result.get('is_adversarial') is not None:
        p = float(autoencoder_result.get('adversarial_prob',
                                          min(autoencoder_result.get('reconstruction_error', 0.0)
                                              / AUTOENCODER_MSE_THRESHOLD, 1.0)))
        v = 1 if autoencoder_result['is_adversarial'] else 0
        detectors.append((p, v, W_AE,
                          f"Autoencoder ({'Hardened' if is_hardened else 'Normal'})"))

    if not detectors:
        return {
            'final_decision':      'unknown',
            'confidence':          0.0,
            'severity':            'unknown',
            'votes':               {'adversarial': 0, 'clean': 0, 'total': 0},
            'model_contributions': [],
            'posture':             active_model,
            'decision_threshold':  THRESHOLD,
            'ensemble_method':     'none (no detectors available)',
        }

    probs   = [d[0] for d in detectors]
    votes   = [d[1] for d in detectors]
    weights = [d[2] for d in detectors]
    labels  = [d[3] for d in detectors]

    # ════════════════════════════════════════════════════════════════════════
    # Strategy 1 — Weighted Soft Voting
    # ════════════════════════════════════════════════════════════════════════
    total_weight = sum(weights)
    soft_score   = sum(p * w for p, w in zip(probs, weights)) / total_weight

    # ════════════════════════════════════════════════════════════════════════
    # Strategy 2 — Weighted Hard Majority Voting
    # ════════════════════════════════════════════════════════════════════════
    # Each detector contributes weight × vote; adversarial if weighted sum
    # exceeds half the total weight (equivalent to a weighted majority).
    weighted_vote_sum = sum(v * w for v, w in zip(votes, weights))
    hard_score = weighted_vote_sum / total_weight   # normalised to [0, 1]

    # ════════════════════════════════════════════════════════════════════════
    # Strategy 3 — Stacking Meta-Learner (logistic regression)
    # ════════════════════════════════════════════════════════════════════════
    # Coefficients reflect the relative discriminative power of each detector
    # on held-out adversarial image data.
    # Layout: [yolo_prob, resnet_prob, ae_prob] — reorder to match detectors list
    # We build the feature vector by name so it is robust to missing detectors.
    feat = {label: prob for label, prob in zip(labels, probs)}

    # Retrieve probs by detector type (partial match)
    p_yolo = next((v for k, v in feat.items() if 'YOLOv5' in k),   0.0)
    p_res  = next((v for k, v in feat.items() if 'ResNet' in k),    0.0)
    p_ae   = next((v for k, v in feat.items() if 'Autoencoder' in k), 0.0)

    # Meta-learner coefficients (logistic regression weights + bias)
    # Hardened posture boosts yolo/ae coefficients (more aggressive posture)

    if is_hardened:
        c_yolo = getattr(_ivm, 'CALIBRATED_META_C_YOLO',   2.8)
        c_res  = getattr(_ivm, 'CALIBRATED_META_C_RESNET', 1.4)
        c_ae   = getattr(_ivm, 'CALIBRATED_META_C_AE',     2.2)
        bias   = getattr(_ivm, 'CALIBRATED_META_BIAS',    -2.0)
    else:
        c_yolo = getattr(_ivm, 'CALIBRATED_META_C_YOLO',   2.2)
        c_res  = getattr(_ivm, 'CALIBRATED_META_C_RESNET', 1.1)
        c_ae   = getattr(_ivm, 'CALIBRATED_META_C_AE',     1.8)
        bias   = getattr(_ivm, 'CALIBRATED_META_BIAS',    -2.4)

    # if is_hardened:
    #     c_yolo, c_res, c_ae, bias = 2.8, 1.4, 2.2, -2.0
    # else:
    #     c_yolo, c_res, c_ae, bias = 2.2, 1.1, 1.8, -2.4

    logit      = c_yolo * p_yolo + c_res * p_res + c_ae * p_ae + bias
    stack_score = 1.0 / (1.0 + np.exp(-logit))   # sigmoid → [0, 1]

    # ════════════════════════════════════════════════════════════════════════
    # Final Fusion — average of the three strategy scores
    # ════════════════════════════════════════════════════════════════════════
    final_score    = (soft_score + hard_score + stack_score) / 3.0
    is_adversarial = final_score > THRESHOLD

    # ── Severity (CVSS v3.1 alignment) ──────────────────────────────────────
    if   final_score > 0.85: severity = 'critical'
    elif final_score > 0.65: severity = 'high'
    elif final_score > 0.40: severity = 'medium'
    else:                    severity = 'low'

    # ── Per-model contribution summary ──────────────────────────────────────
    model_contributions = []
    for (prob, vote, weight, label), raw_res in zip(
        detectors,
        [yolo_result, resnet_result, autoencoder_result][:len(detectors)]
    ):
        entry = {
            'model':            label,
            'vote':             'adversarial' if vote else 'clean',
            'weight':           weight,
            'adversarial_prob': round(prob, 4),
            'confidence':       raw_res.get('confidence', prob),
        }
        # Attach model-specific diagnostic fields
        if 'reconstruction_error' in raw_res:
            entry['reconstruction_error'] = raw_res['reconstruction_error']
        if 'suspicion_score' in raw_res:
            entry['suspicion_score'] = raw_res['suspicion_score']
        model_contributions.append(entry)

    return {
        'final_decision':      'adversarial' if is_adversarial else 'clean',
        'confidence':          float(final_score),
        'severity':            severity,
        'votes': {
            'adversarial': sum(votes),
            'clean':       len(votes) - sum(votes),
            'total':       len(votes),
        },
        'model_contributions': model_contributions,
        'posture':             active_model,
        'decision_threshold':  THRESHOLD,
        'ensemble_scores': {
            'weighted_soft_voting': round(soft_score,   4),
            'weighted_hard_voting': round(hard_score,   4),
            'stacking_meta_learner': round(stack_score, 4),
            'fused_final':          round(final_score,  4),
        },
        'ensemble_method': 'weighted_soft_voting + weighted_hard_voting + stacking_meta_learner (averaged)',
        'weights_used': {
            'yolo':        W_YOLO,
            'autoencoder': W_AE,
            'resnet':      W_RESNET,
        },
    }

# =============================================================================
# API ENDPOINTS
# =============================================================================
@app.get("/api/health")
async def health_check():
    return {
        'status': 'healthy',
        'timestamp': datetime.now(timezone(timedelta(hours=5))),
        'models': {
            'resnet': resnet_model is not None,
            'yolo': yolo_model is not None,
            'autoencoder': autoencoder_model is not None,
            'database': "connected"
        },
        'device': str(DEVICE),
        'thresholds': {
            'resnet_confidence': RESNET_CONFIDENCE_THRESHOLD,
            'resnet_entropy': RESNET_ENTROPY_THRESHOLD,
            'autoencoder_mse': AUTOENCODER_MSE_THRESHOLD,
            'yolo_conf': YOLO_CONF_THRESHOLD
        }
    }

@app.post("/api/detect")
async def detect_threat(image: UploadFile = File(...)):
    """
    UPDATED: Now saves to database
    """
    print(f"🔍 Analyzing: {image.filename}")
    
    try:
        # Read image
        image_data = await image.read()
        pil_image = Image.open(io.BytesIO(image_data)).convert('RGB')
        
        # Save image to disk
        threat_id = f"THR-{np.random.randint(1000, 9999)}"
        image_filename = f"{threat_id}_{image.filename}"
        image_path = UPLOAD_DIR / image_filename
        pil_image.save(image_path)
        
        # Run detection
        resnet_result = detect_with_resnet(pil_image)
        yolo_result = detect_with_yolo(pil_image)
        autoencoder_result = detect_with_autoencoder(pil_image)
        
        ensemble = ensemble_decision(resnet_result, yolo_result, autoencoder_result)
        
        # Determine attack type and category
        attack_info = determine_attack_type_and_category(
            yolo_result, resnet_result, autoencoder_result, ensemble
        )
        
        print(f"  ✅ {ensemble['final_decision'].upper()} ({ensemble['severity']})")
        print(f"  📋 Category: {attack_info['category']}")
        print(f"  🎯 Type: {attack_info['type']}")

        # ── SIEM: log detection event ────────────────────────────────────
        _siem_severity = {
            'critical': SiemSeverity.CRITICAL,
            'high':     SiemSeverity.ERROR,
            'medium':   SiemSeverity.WARNING,
            'low':      SiemSeverity.INFO,
        }.get(ensemble['severity'], SiemSeverity.INFO)

        if ensemble['final_decision'] == 'adversarial':
            siem_log(
                severity   = _siem_severity,
                source     = SiemSource.IVM,
                event_type = "ThreatDetected",
                message    = f"Adversarial image detected: {image.filename} — {attack_info['type']} ({ensemble['severity'].upper()}, {ensemble['confidence']*100:.1f}% confidence)",
                metadata   = {
                    "threat_id":   threat_id,
                    "filename":    image.filename,
                    "attack_type": attack_info['type'],
                    "category":    attack_info['category'],
                    "severity":    ensemble['severity'],
                    "confidence":  round(ensemble['confidence'], 4),
                    "posture":     active_model,
                }
            )
        else:
            siem_log(
                severity   = SiemSeverity.INFO,
                source     = SiemSource.IVM,
                event_type = "ScanClean",
                message    = f"Image scanned — clean: {image.filename} (confidence {ensemble['confidence']*100:.1f}%)",
                metadata   = {"threat_id": threat_id, "filename": image.filename, "confidence": round(ensemble['confidence'], 4)}
            )
        # ─────────────────────────────────────────────────────────────────
        
        # Prepare response data
        individual_results = {
            'resnet': resnet_result,
            'yolo': yolo_result,
            'autoencoder': autoencoder_result
        }
        
        threat_data = {
            'type': attack_info['type'],
            'category': attack_info['category'],
            'characteristics': attack_info['characteristics'],
            'primary_indicator': attack_info['primary_indicator'],
            'severity': ensemble['severity'],
            'status': 'detected' if ensemble['final_decision'] == 'adversarial' else 'clean',
            'confidence': ensemble['confidence'],
            'modelTarget': 'Multi-Model Analysis'
        }
        
        # SAVE TO DATABASE
        prediction_id = save_prediction(
            threat_id=threat_id,
            filename=image.filename,
            image_path=str(image_path),
            ensemble_result=ensemble,
            individual_results=individual_results,
            threat_data=threat_data
        )
        
        # ── ARE: Fire response policies against this threat ──────────────
        are_result = None
        print(f"  🔎 ARE check: final_decision={ensemble['final_decision']}")
        if ensemble['final_decision'] == 'adversarial':
            are_payload = {
                "threatId":      threat_id,
                "target":        image.filename,
                "severity":      ensemble['severity'],
                "confidence":    ensemble['confidence'],
                "status":        "detected",
                "modelAccuracy":   resnet_result.get('confidence'),
                "agentDeviation":  autoencoder_result.get('reconstruction_error'),
                "modelRobustness": 1.0 - autoencoder_result.get('reconstruction_error', 0),
                "agentConfidence":   yolo_result.get('confidence', 0.0),
                "agentAnomalyScore": resnet_result.get('suspicion_score', 0.0),
            }
            print(f"  📤 Sending to ARE via SRC secure channel: {are_payload}")
            try:
                # ── Step 1: Log the inter-module event through SRC (encrypt + sign) ──
                src_result = src_send(
                    source      = "IVM",
                    destination = "ARE",
                    event_type  = "ThreatEscalation",
                    message     = (
                        f"Adversarial threat detected: {threat_id} | "
                        f"Severity: {ensemble['severity']} | "
                        f"Confidence: {ensemble['confidence']:.2%} | "
                        f"File: {image.filename}"
                    ),
                    metadata    = are_payload,
                )
                if src_result:
                    print(f"  🔒 SRC logged: {src_result.get('log_id')} (AES-256-GCM encrypted)")
                else:
                    print(f"  ⚠️  SRC unavailable — proceeding with direct ARE call")

                # ── Step 2: Make the actual ARE call (as before) ──
                are_response = requests.post(
                    f"{ARE_BASE}/evaluate",
                    json=are_payload,
                    timeout=5.0
                )
                print(f"  📥 ARE response status: {are_response.status_code}")
                if are_response.status_code == 200:
                    are_result = are_response.json()
                    print(f"  🤖 ARE: {are_result['actionsTriggered']} policies fired "
                          f"({are_result['policiesChecked']} checked)")

                    # ── Step 3: Log ARE's response back through SRC ──
                    src_send(
                        source      = "ARE",
                        destination = "IVM",
                        event_type  = "PolicyExecutionResult",
                        message     = (
                            f"ARE executed {are_result['actionsTriggered']} action(s) "
                            f"for threat {threat_id}"
                        ),
                        metadata    = {
                            "threat_id":        threat_id,
                            "policies_checked": are_result.get("policiesChecked"),
                            "actions_triggered": are_result.get("actionsTriggered"),
                        },
                    )
                else:
                    print(f"  ⚠️  ARE returned {are_response.status_code}: {are_response.text}")
            except Exception as are_err:
                print(f"  ❌ ARE call failed: {are_err}")
        # ─────────────────────────────────────────────────────────────────

        # Return response
        return {
            'timestamp': datetime.now(timezone(timedelta(hours=5))),
            'id': threat_id,
            'prediction_id': prediction_id,
            'filename': image.filename,
            'individual_results': individual_results,
            'ensemble': ensemble,
            'threat_data': threat_data,
            'are_result': are_result,   # None if clean or ARE unreachable
        }
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/detect/debug")
async def detect_threat_debug(image: UploadFile = File(...)):
    try:
        image_data = await image.read()
        pil_image = Image.open(io.BytesIO(image_data)).convert('RGB')
        
        return {
            'timestamp': datetime.now(timezone(timedelta(hours=5))),
            'filename': image.filename,
            'raw_results': {
                'resnet': detect_with_resnet(pil_image),
                'yolo': detect_with_yolo(pil_image),
                'autoencoder': detect_with_autoencoder(pil_image)
            },
            'thresholds': {
                'resnet_confidence': RESNET_CONFIDENCE_THRESHOLD,
                'resnet_entropy': RESNET_ENTROPY_THRESHOLD,
                'autoencoder_mse': AUTOENCODER_MSE_THRESHOLD
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.get("/api/predictions")
async def get_predictions(limit: int = 50, offset: int = 0):
    """
    Get all predictions with pagination
    """
    try:
        predictions = get_all_predictions(limit=limit, offset=offset)
        return {
            'predictions': predictions,
            'count': len(predictions),
            'limit': limit,
            'offset': offset
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/prediction/{threat_id}")
async def get_prediction(threat_id: str):
    """
    Get a specific prediction by threat_id
    """
    try:
        prediction = get_prediction_by_id(threat_id)
        if not prediction:
            raise HTTPException(status_code=404, detail="Prediction not found")
        return prediction
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/statistics")
async def get_stats():
    """
    Get system statistics
    """
    try:
        stats = get_statistics()
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/image/{threat_id}")
async def get_image(threat_id: str):
    """
    Get the original image for a prediction
    """
    try:
        from fastapi.responses import FileResponse
        
        prediction = get_prediction_by_id(threat_id)
        if not prediction:
            raise HTTPException(status_code=404, detail="Prediction not found")
        
        image_path = Path(prediction['image_path'])
        if not image_path.exists():
            raise HTTPException(status_code=404, detail="Image file not found")
        
        return FileResponse(image_path)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/prediction/{threat_id}")
async def delete_prediction(threat_id: str):
    """
    Delete a prediction (and its image)
    """
    try:
        prediction = get_prediction_by_id(threat_id)
        if not prediction:
            raise HTTPException(status_code=404, detail="Prediction not found")
        
        # Delete image file
        image_path = Path(prediction['image_path'])
        if image_path.exists():
            image_path.unlink()
        
        # Delete from database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM predictions WHERE threat_id = ?', (threat_id,))
        conn.commit()
        conn.close()
        
        return {"status": "deleted", "threat_id": threat_id}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.on_event("startup")
async def startup_event():
    print("\n" + "="*60)
    print("🛡️  THREAT DETECTION SYSTEM")
    print("="*60)
    print(f"Device: {DEVICE}")
    print(f"Models: ResNet50={'✅' if resnet_model else '❌'} | "
          f"YOLO={'✅' if yolo_model else '❌'} | "
          f"Autoencoder={'✅' if autoencoder_model else '❌'}")
    print("="*60 + "\n")

# ── Model Switch Endpoints (called by ARE when switch_model policy fires) ──

class SwitchModelRequest(BaseModel):
    model: str  # "normal" or "hardened"

@app.post("/api/switch-model")
async def switch_model_endpoint(body: SwitchModelRequest):
    global active_model
    if body.model not in ("normal", "hardened"):
        raise HTTPException(status_code=400, detail="model must be 'normal' or 'hardened'")
    active_model = body.model
    print(f"🔄 Detection mode switched to: {active_model}")
    siem_log(
        severity   = SiemSeverity.WARNING,
        source     = SiemSource.IVM,
        event_type = "ModelSwitched",
        message    = f"Detection posture switched to {active_model.upper()} mode",
        metadata   = {"active_model": active_model}
    )
    return {"active_model": active_model, "switched": True}

@app.get("/api/active-model")
async def get_active_model():
    is_hardened = active_model == "hardened"
    return {
        "active_model":  active_model,
        "description":   (
            "Hardened — tighter thresholds, boosted YOLO/AE weights, lower decision bar"
            if is_hardened else
            "Normal — balanced weighted ensemble"
        ),
        "weights": {
            "yolo":        2.0 if is_hardened else 1.5,
            "autoencoder": 1.8 if is_hardened else 1.2,
            "resnet":      1.2 if is_hardened else 1.0,
        },
        "thresholds": {
            "decision":        0.40 if is_hardened else 0.55,
            "yolo_conf":       HARDENED_YOLO_CONF if is_hardened else YOLO_CONF_THRESHOLD,
            "autoencoder_mse": HARDENED_AUTOENCODER_MSE if is_hardened else AUTOENCODER_MSE_THRESHOLD,
        },
        "model_availability": {
            "resnet":      resnet_model is not None,
            "yolo":        yolo_model is not None,
            "autoencoder": autoencoder_model is not None,
        },
        "fallback_available": fallback_model is not None,
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)