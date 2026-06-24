"""
calibration_pipeline.py — PhantomNet++ Ensemble Calibration Pipeline
=====================================================================
Learns all ensemble weights, meta-learner coefficients, and decision
thresholds from your actual dataset instead of using hardcoded values.

DATASET STRUCTURE EXPECTED:
    clean_dir/              ← Tiny ImageNet train folder
        n01234567/          ← class subfolders (ImageNet style)
            images/
                *.JPEG

    adversarial_dir/        ← Your DAG output folder (dag-sprint3/output)
        00_Clean_Baseline/              ← treated as ADVERSARIAL (YOLO fires on these)
        01_AdvGAN_Patches_Small/        ← adversarial label=1
        02_Physical_Perspective_Distortion/
        03_Physical_Rain_Simulation/
        04_Combined_Occlusion_Attacks/
        05_3D_Adversarial_Objects/
        06_AdvGAN_Patches_Large/

HOW TO RUN (on your local machine, NOT inside Docker):
    python calibration_pipeline.py \
        --clean_dir  "D:/Uni/fyp/tiny-imagenet-200/train" \
        --adv_dir    "D:/Uni/fyp/GANS-FYP-/dag-sprint3/output" \
        --model_dir  "D:/Uni/fyp/GANS-FYP-/phantomnetui/backend" \
        --db_path    "D:/Uni/fyp/GANS-FYP-/phantomnetui/backend/db/phantomnet.db" \
        --device     "cpu"

    After it finishes:
        docker compose up --build ivm -d

SAFETY CHECK:
    If 5-fold CV AUROC < --min_auroc (default 0.75),
    the pipeline will NOT save to DB and tells you to keep hardcoded values.
    The calibration_report.txt is always written regardless.
"""

import os, sys, sqlite3, argparse, random, warnings
import numpy as np
from pathlib import Path
from datetime import datetime
from PIL import Image

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────────────────────────────────────
# WINDOWS POSIXPATH FIX — MUST BE BEFORE ANY torch.load CALL
# ─────────────────────────────────────────────────────────────────────────────
import platform, pathlib
if platform.system() == "Windows":
    pathlib.PosixPath = pathlib.WindowsPath

# ─────────────────────────────────────────────────────────────────────────────
# ARGUMENT PARSING
# ─────────────────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(description="PhantomNet++ Calibration Pipeline")
parser.add_argument("--clean_dir",  required=True,  help="Tiny ImageNet train folder")
parser.add_argument("--adv_dir",    required=True,  help="DAG output folder (dag-sprint3/output)")
parser.add_argument("--model_dir",  default=".",    help="Folder with models/ and yolov5/ inside")
parser.add_argument("--db_path",    required=True,  help="Full path to phantomnet.db")
parser.add_argument("--device",     default="cpu",  help="cpu or cuda")
parser.add_argument("--max_clean",  default=1700,   type=int,   help="Max clean images (default 1700)")
parser.add_argument("--min_auroc",  default=0.75,   type=float, help="Min CV AUROC to save to DB")
parser.add_argument("--seed",       default=42,     type=int,   help="Random seed")
args = parser.parse_args()

random.seed(args.seed)
np.random.seed(args.seed)

# ─────────────────────────────────────────────────────────────────────────────
# IMPORTS
# ─────────────────────────────────────────────────────────────────────────────
print("=" * 65)
print("  PhantomNet++ Ensemble Calibration Pipeline")
print("=" * 65)
print(f"\n[INFO] Python   : {sys.version.split()[0]}")

try:
    import torch
    import torch.nn as nn
    from torchvision import models, transforms
    print(f"[INFO] PyTorch  : {torch.__version__}")
    print(f"[INFO] CUDA     : {torch.cuda.is_available()}")
except ImportError:
    print("[ERROR] PyTorch not installed. Run: pip install torch torchvision")
    sys.exit(1)

try:
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import roc_auc_score, roc_curve, f1_score, classification_report
    from sklearn.model_selection import StratifiedKFold, cross_val_score
    print(f"[INFO] sklearn  : OK")
except ImportError:
    print("[ERROR] scikit-learn not installed. Run: pip install scikit-learn")
    sys.exit(1)

DEVICE = torch.device(args.device if args.device in ["cpu", "cuda"] else "cpu")
print(f"[INFO] Device   : {DEVICE}")
print(f"[INFO] DB path  : {args.db_path}")
print(f"[INFO] Min CV AUROC to save: {args.min_auroc}\n")

# ─────────────────────────────────────────────────────────────────────────────
# ADD YOLOV5 TO PATH + IMPORT NMS AT MODULE LEVEL (not inside function)
# ─────────────────────────────────────────────────────────────────────────────
model_dir   = Path(args.model_dir)
yolov5_repo = model_dir / "yolov5"

if yolov5_repo.exists():
    sys.path.insert(0, str(yolov5_repo))
    print(f"[INFO] YOLOv5 repo: {yolov5_repo}")
else:
    print(f"[WARN] YOLOv5 repo not found at {yolov5_repo} — YOLO will be skipped")

# Import NMS at module level — NOT inside extract_yolo()
NMS_AVAILABLE = False
try:
    from yolov5.utils.general import non_max_suppression
    NMS_AVAILABLE = True
    print(f"[INFO] NMS import : OK")
except Exception as e:
    print(f"[WARN] NMS import failed: {e} — YOLO will be skipped during extraction")

IMG_EXTENSIONS = ["*.jpg", "*.jpeg", "*.JPEG", "*.JPG", "*.png", "*.PNG", "*.bmp", "*.webp"]

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — COLLECT IMAGE PATHS
# ALL subfolders in adv_dir are treated as ADVERSARIAL (label=1)
# including 00_Clean_Baseline — YOLO fires on those too
# Clean images come ONLY from Tiny ImageNet
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "─"*65)
print("STEP 1 — Collecting image paths")
print("─"*65)

def collect_images(folder: Path) -> list:
    """Collect all images, handles both lowercase and uppercase extensions."""
    imgs = []
    for ext in IMG_EXTENSIONS:
        imgs.extend(folder.rglob(ext))
    return imgs

# ── Clean images — Tiny ImageNet ONLY ────────────────────────────────────────
clean_dir = Path(args.clean_dir)
if not clean_dir.exists():
    print(f"[ERROR] Clean dir not found: {clean_dir}"); sys.exit(1)

all_clean_paths = collect_images(clean_dir)
print(f"[INFO] Tiny ImageNet clean images found: {len(all_clean_paths):,}")

if len(all_clean_paths) == 0:
    print(f"[ERROR] No clean images found in {clean_dir}")
    print(f"        Make sure the path is correct and contains .JPEG/.jpg files")
    sys.exit(1)

# ── Adversarial images — ALL subfolders in adv_dir ───────────────────────────
adv_dir = Path(args.adv_dir)
if not adv_dir.exists():
    print(f"[ERROR] Adversarial dir not found: {adv_dir}"); sys.exit(1)

adv_paths, attack_type_map = [], {}

for subfolder in sorted(adv_dir.iterdir()):
    if not subfolder.is_dir(): continue
    imgs = collect_images(subfolder)
    adv_paths.extend(imgs)
    for p in imgs:
        attack_type_map[str(p)] = subfolder.name
    print(f"  [ADVERSARIAL] {subfolder.name:42s} → {len(imgs):4d}")

if len(adv_paths) == 0:
    print("[ERROR] No adversarial images found."); sys.exit(1)

# ── Balance: sample clean to ~2:1 ratio ──────────────────────────────────────
n_adv = len(adv_paths)
all_clean_combined = all_clean_paths.copy()
random.shuffle(all_clean_combined)
sampled_clean = all_clean_combined[:min(args.max_clean, len(all_clean_combined))]

print(f"\n[INFO] Sampled clean : {len(sampled_clean)}"
      f"  |  Adversarial: {n_adv}"
      f"  |  Ratio: {len(sampled_clean)/n_adv:.1f}:1")

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — LOAD MODELS
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "─"*65)
print("STEP 2 — Loading models")
print("─"*65)

class ImprovedAutoencoder(nn.Module):
    """Exact copy of architecture in threat_detection_backend.py"""
    def __init__(self, latent_dim=512):
        super().__init__()
        self.enc1 = nn.Sequential(nn.Conv2d(3,   32,  4,2,1), nn.BatchNorm2d(32),  nn.LeakyReLU(0.2,True))
        self.enc2 = nn.Sequential(nn.Conv2d(32,  64,  4,2,1), nn.BatchNorm2d(64),  nn.LeakyReLU(0.2,True))
        self.enc3 = nn.Sequential(nn.Conv2d(64,  128, 4,2,1), nn.BatchNorm2d(128), nn.LeakyReLU(0.2,True))
        self.enc4 = nn.Sequential(nn.Conv2d(128, 256, 4,2,1), nn.BatchNorm2d(256), nn.LeakyReLU(0.2,True))
        self.fc_encoder = nn.Linear(256*4*4, latent_dim)
        self.fc_decoder = nn.Linear(latent_dim, 256*4*4)
        self.dec1 = nn.Sequential(nn.ConvTranspose2d(256,     128,4,2,1), nn.BatchNorm2d(128), nn.ReLU(True))
        self.dec2 = nn.Sequential(nn.ConvTranspose2d(128+128, 64, 4,2,1), nn.BatchNorm2d(64),  nn.ReLU(True))
        self.dec3 = nn.Sequential(nn.ConvTranspose2d(64+64,   32, 4,2,1), nn.BatchNorm2d(32),  nn.ReLU(True))
        self.dec4 = nn.Sequential(nn.ConvTranspose2d(32+32,   3,  4,2,1), nn.Tanh())

    def forward(self, x):
        e1=self.enc1(x); e2=self.enc2(e1); e3=self.enc3(e2); e4=self.enc4(e3)
        latent = self.fc_encoder(e4.view(e4.size(0),-1))
        d = self.fc_decoder(latent).view(-1,256,4,4)
        d = self.dec1(d)
        d = self.dec2(torch.cat([d,e3],1))
        d = self.dec3(torch.cat([d,e2],1))
        d = self.dec4(torch.cat([d,e1],1))
        return d, latent

# ── ResNet-50 ─────────────────────────────────────────────────────────────────
resnet_model = None
try:
    resnet_model = models.resnet50(weights=models.ResNet50_Weights.DEFAULT)
    resnet_model.eval().to(DEVICE)
    print("[OK]   ResNet-50 loaded")
except Exception as e:
    print(f"[WARN] ResNet-50 failed: {e}")

# ── YOLOv5 ───────────────────────────────────────────────────────────────────
yolo_model = None
yolo_pt    = model_dir / "models" / "yolo-trained.pt"
try:
    if not yolov5_repo.exists():
        raise FileNotFoundError("YOLOv5 repo missing")
    if not yolo_pt.exists():
        raise FileNotFoundError(f"Weights not found: {yolo_pt}")
    if not NMS_AVAILABLE:
        raise ImportError("NMS not available — skipping YOLO load")
    ckpt = torch.load(str(yolo_pt), map_location=DEVICE, weights_only=False)
    yolo_model = (ckpt.get('model') or ckpt.get('ema') if isinstance(ckpt, dict) else ckpt).float()
    yolo_model.eval().to(DEVICE)
    print(f"[OK]   YOLOv5 loaded  classes={getattr(yolo_model, 'names', {})}")
except Exception as e:
    print(f"[WARN] YOLOv5 skipped: {e}")

# ── Autoencoder ───────────────────────────────────────────────────────────────
ae_model = None
ae_pt = model_dir / "models" / "autoencoder.pth"
try:
    if not ae_pt.exists():
        raise FileNotFoundError(f"Weights not found: {ae_pt}")
    ae_model = ImprovedAutoencoder(512)
    ckpt = torch.load(ae_pt, map_location=DEVICE, weights_only=False)
    if isinstance(ckpt, dict) and 'model_state_dict' in ckpt:
        ae_model.load_state_dict(ckpt['model_state_dict'])
        print(f"[OK]   Autoencoder loaded  epoch={ckpt.get('epoch','?')}  "
              f"val_loss={ckpt.get('val_loss',0):.5f}")
    elif isinstance(ckpt, dict) and 'state_dict' in ckpt:
        ae_model.load_state_dict(ckpt['state_dict'])
        print(f"[OK]   Autoencoder loaded (state_dict key)")
    else:
        ae_model.load_state_dict(ckpt)
        print(f"[OK]   Autoencoder loaded (raw)")
    ae_model.eval().to(DEVICE)
except Exception as e:
    print(f"[WARN] Autoencoder skipped: {e}")

n_loaded = sum(m is not None for m in [resnet_model, yolo_model, ae_model])
print(f"\n[INFO] Models loaded: {n_loaded}/3")
if n_loaded == 0:
    print("[ERROR] No models loaded. Cannot calibrate."); sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — TRANSFORMS
# ─────────────────────────────────────────────────────────────────────────────
tf_resnet = transforms.Compose([
    transforms.Resize(256), transforms.CenterCrop(224), transforms.ToTensor(),
    transforms.Normalize([0.485,0.456,0.406],[0.229,0.224,0.225])
])
tf_ae = transforms.Compose([
    transforms.Resize((64,64)), transforms.ToTensor(),
    transforms.Normalize([0.485,0.456,0.406],[0.229,0.224,0.225])
])

# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — FEATURE EXTRACTION FUNCTIONS
# NMS is imported at module level above — not inside this function
# ─────────────────────────────────────────────────────────────────────────────
def extract_resnet(img):
    if resnet_model is None: return None
    try:
        t = tf_resnet(img).unsqueeze(0).to(DEVICE)
        with torch.no_grad():
            probs   = torch.softmax(resnet_model(t), 1)
            conf, _ = torch.max(probs, 1)
            entr    = -torch.sum(probs * torch.log(probs + 1e-10), 1)
        c, e   = conf.item(), entr.item()
        conf_p = 1.0 / (1.0 + np.exp(-15.0 * (0.30 - c)))
        entr_p = 1.0 / (1.0 + np.exp(-1.2  * (e   - 6.20)))
        return {"confidence": c, "entropy": e,
                "adversarial_prob": 0.45*conf_p + 0.55*entr_p}
    except Exception:
        return None

def extract_yolo(img):
    if yolo_model is None or not NMS_AVAILABLE: return None
    try:
        img_r = img.resize((640, 640), Image.BILINEAR)
        arr   = np.array(img_r, dtype=np.float32).transpose(2, 0, 1) / 255.0
        t     = torch.from_numpy(arr).unsqueeze(0).to(DEVICE)
        with torch.no_grad():
            preds = yolo_model(t)
        pred = preds[0] if isinstance(preds, (list, tuple)) else preds
        det  = non_max_suppression(pred, conf_thres=0.25, iou_thres=0.45)[0]
        if len(det) > 0:
            confs    = det[:, 4].cpu().tolist()
            max_conf = max(confs)
            adv_prob = min(max_conf * min(1.0 + 0.05*(len(confs)-1), 1.2), 1.0)
            return {"adversarial_prob": adv_prob}
        return {"adversarial_prob": 0.0}
    except Exception as e:
        print(f"\n  [YOLO ERROR] {e}")
        return None

def extract_ae(img):
    if ae_model is None: return None
    try:
        t = tf_ae(img).unsqueeze(0).to(DEVICE)
        with torch.no_grad():
            rec, _ = ae_model(t)
            mse    = torch.mean((t - rec) ** 2).item()
        k = 10.0 / 0.45
        return {"mse": mse,
                "adversarial_prob": 1.0 / (1.0 + np.exp(-k * (mse - 0.45)))}
    except Exception:
        return None

# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 — RUN INFERENCE ON ALL IMAGES
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "─"*65)
print("STEP 5 — Extracting features (will take a few minutes on CPU)")
print("─"*65)

all_paths = [(p, 0) for p in sampled_clean] + [(p, 1) for p in adv_paths]
random.shuffle(all_paths)
records, errors, total = [], 0, len(all_paths)

for idx, (path, label) in enumerate(all_paths):
    if idx % 50 == 0:
        pct = idx / total * 100
        bar = "█" * int(pct/5) + "░" * (20 - int(pct/5))
        print(f"  [{bar}] {pct:5.1f}%  {idx}/{total}  errors:{errors}", end="\r")

    try:
        img = Image.open(path).convert("RGB")
    except Exception:
        errors += 1; continue

    r, y, ae = extract_resnet(img), extract_yolo(img), extract_ae(img)

    if r is None and y is None and ae is None:
        errors += 1; continue

    records.append({
        "label":   label,
        "r_conf":  r["confidence"]       if r  else np.nan,
        "r_entr":  r["entropy"]           if r  else np.nan,
        "r_prob":  r["adversarial_prob"]  if r  else np.nan,
        "y_prob":  y["adversarial_prob"]  if y  else np.nan,
        "ae_mse":  ae["mse"]              if ae else np.nan,
        "ae_prob": ae["adversarial_prob"] if ae else np.nan,
    })

print(f"\n[INFO] Done: {len(records)} valid / {errors} skipped\n")

if len(records) < 50:
    print("[ERROR] Too few records. Check model paths."); sys.exit(1)

# Build arrays — NaN filled with neutral 0.5
labels   = np.array([r["label"]   for r in records])
r_probs  = np.array([r["r_prob"]  if not np.isnan(r["r_prob"])  else 0.5  for r in records])
y_probs  = np.array([r["y_prob"]  if not np.isnan(r["y_prob"])  else 0.5  for r in records])
ae_probs = np.array([r["ae_prob"] if not np.isnan(r["ae_prob"]) else 0.5  for r in records])
ae_mses  = np.array([r["ae_mse"]  if not np.isnan(r["ae_mse"])  else 0.45 for r in records])
r_confs  = np.array([r["r_conf"]  if not np.isnan(r["r_conf"])  else 0.3  for r in records])
r_entrs  = np.array([r["r_entr"]  if not np.isnan(r["r_entr"])  else 6.2  for r in records])

y_valid = sum(1 for r in records if not np.isnan(r["y_prob"]))
n_adv_actual   = int(labels.sum())
n_clean_actual = int((1-labels).sum())

print(f"[INFO] Label split  → clean: {n_clean_actual}  adversarial: {n_adv_actual}")
print(f"[INFO] YOLO results → {y_valid}/{len(records)} images had real YOLO output "
      f"({'✅ YOLO working' if y_valid > len(records)*0.8 else '⚠️  YOLO mostly silent — check NMS'})")

# ─────────────────────────────────────────────────────────────────────────────
# STEP 6 — AUROC-DERIVED ENSEMBLE WEIGHTS
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "─"*65)
print("STEP 6 — AUROC-derived ensemble weights")
print("─"*65)

auroc_scores = {}
if resnet_model:
    auroc_scores["resnet"]      = roc_auc_score(labels, r_probs)
    print(f"  ResNet-50   AUROC: {auroc_scores['resnet']:.4f}")
if yolo_model and NMS_AVAILABLE:
    auroc_scores["yolo"]        = roc_auc_score(labels, y_probs)
    flag = "  ⚠️  still low — check clean image detections" if auroc_scores["yolo"] < 0.55 else ""
    print(f"  YOLOv5      AUROC: {auroc_scores['yolo']:.4f}{flag}")
if ae_model:
    auroc_scores["autoencoder"] = roc_auc_score(labels, ae_probs)
    print(f"  Autoencoder AUROC: {auroc_scores['autoencoder']:.4f}")

total_auroc = sum(auroc_scores.values())
W_RESNET = auroc_scores.get("resnet",      0.333) / total_auroc
W_YOLO   = auroc_scores.get("yolo",        0.333) / total_auroc
W_AE     = auroc_scores.get("autoencoder", 0.333) / total_auroc
print(f"\n  W_YOLO={W_YOLO:.4f}  W_AE={W_AE:.4f}  W_RESNET={W_RESNET:.4f}")

# ─────────────────────────────────────────────────────────────────────────────
# STEP 7 — META-LEARNER + 5-FOLD CV SAFETY CHECK
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "─"*65)
print("STEP 7 — Stacking meta-learner + 5-fold CV safety check")
print("─"*65)

feat_cols, X_list = [], []
if yolo_model and NMS_AVAILABLE: feat_cols.append("yolo");        X_list.append(y_probs)
if resnet_model:                 feat_cols.append("resnet");      X_list.append(r_probs)
if ae_model:                     feat_cols.append("autoencoder"); X_list.append(ae_probs)

X = np.column_stack(X_list)
print(f"  Feature matrix : {X.shape}  features: {feat_cols}")

meta_clf = LogisticRegression(
    class_weight="balanced",
    max_iter=1000,
    random_state=args.seed,
    C=1.0
)

skf       = StratifiedKFold(n_splits=5, shuffle=True, random_state=args.seed)
cv_aurocs = cross_val_score(meta_clf, X, labels, cv=skf, scoring="roc_auc")
cv_mean, cv_std = cv_aurocs.mean(), cv_aurocs.std()

print(f"\n  5-fold CV AUROC: {cv_mean:.4f} ± {cv_std:.4f}")
for i, s in enumerate(cv_aurocs): print(f"    Fold {i+1}: {s:.4f}")

print(f"\n  Minimum required: {args.min_auroc}")
if cv_mean < args.min_auroc:
    print(f"\n{'!'*65}")
    print(f"  ⛔ SAFETY CHECK FAILED")
    print(f"  CV AUROC {cv_mean:.4f} < minimum {args.min_auroc}")
    print(f"  Dataset may be too small to learn reliable weights.")
    print(f"  Hardcoded values will remain active.")
    print(f"  (calibration_report.txt is still written for your supervisor)")
    print(f"{'!'*65}")
    SAVE_TO_DB = False
else:
    print(f"  ✅ SAFETY CHECK PASSED")
    SAVE_TO_DB = True

meta_clf.fit(X, labels)
coef = meta_clf.coef_[0]
bias = meta_clf.intercept_[0]
print(f"\n  Coefficients: " + "  ".join(f"{n}={c:.4f}" for n, c in zip(feat_cols, coef)))
print(f"  Bias        : {bias:.4f}")

c_yolo = coef[feat_cols.index("yolo")]        if "yolo"        in feat_cols else 0.0
c_res  = coef[feat_cols.index("resnet")]      if "resnet"      in feat_cols else 0.0
c_ae   = coef[feat_cols.index("autoencoder")] if "autoencoder" in feat_cols else 0.0

# ─────────────────────────────────────────────────────────────────────────────
# STEP 8 — DECISION THRESHOLD (MAX F1 ON ROC CURVE)
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "─"*65)
print("STEP 8 — Decision threshold (max F1)")
print("─"*65)

def ensemble_scores(y_p, r_p, ae_p, wy, wr, wae, cy, cr, cae, b):
    tw   = wy + wr + wae
    soft = (y_p*wy + r_p*wr + ae_p*wae) / tw
    hard = ((y_p>=0.5).astype(float)*wy + (r_p>=0.5).astype(float)*wr +
            (ae_p>=0.5).astype(float)*wae) / tw
    stk  = 1.0 / (1.0 + np.exp(-(cy*y_p + cr*r_p + cae*ae_p + b)))
    return (soft + hard + stk) / 3.0

fs            = ensemble_scores(y_probs, r_probs, ae_probs,
                                W_YOLO, W_RESNET, W_AE,
                                c_yolo, c_res, c_ae, bias)
overall_auroc = roc_auc_score(labels, fs)
fpr, tpr, thr = roc_curve(labels, fs)
f1s           = [f1_score(labels, (fs>=t).astype(int), zero_division=0) for t in thr]
best_idx      = int(np.argmax(f1s))
best_threshold= float(thr[best_idx])
best_f1       = float(f1s[best_idx])

print(f"  Ensemble AUROC : {overall_auroc:.4f}")
print(f"  Best threshold : {best_threshold:.4f}  (was 0.55)")
print(f"  Best F1        : {best_f1:.4f}")
print(classification_report(labels, (fs>=best_threshold).astype(int),
                             target_names=["Clean", "Adversarial"]))

# ─────────────────────────────────────────────────────────────────────────────
# STEP 9 — AE MSE THRESHOLD
# ─────────────────────────────────────────────────────────────────────────────
print("─"*65)
print("STEP 9 — AE MSE threshold")
print("─"*65)
if ae_model:
    _, _, thr_ae = roc_curve(labels, ae_mses)
    f1_ae        = [f1_score(labels, (ae_mses>=t).astype(int), zero_division=0) for t in thr_ae]
    best_ae      = float(thr_ae[int(np.argmax(f1_ae))])
    print(f"  Learned AE MSE threshold: {best_ae:.4f}  (was 0.45)")
    print(f"  Clean MSE mean±std: {ae_mses[labels==0].mean():.4f} ± {ae_mses[labels==0].std():.4f}")
    print(f"  Adv   MSE mean±std: {ae_mses[labels==1].mean():.4f} ± {ae_mses[labels==1].std():.4f}")
else:
    best_ae = 0.45
    print("  [SKIP] AE not loaded — keeping 0.45")

# ─────────────────────────────────────────────────────────────────────────────
# STEP 10 — RESNET SIGMOID MIDPOINTS
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "─"*65)
print("STEP 10 — ResNet sigmoid midpoints")
print("─"*65)
if resnet_model:
    conf_mid = float((r_confs[labels==0].mean() + r_confs[labels==1].mean()) / 2.0)
    entr_mid = float((r_entrs[labels==0].mean() + r_entrs[labels==1].mean()) / 2.0)
    print(f"  conf_mid: {conf_mid:.4f}  (was 0.30)")
    print(f"  entr_mid: {entr_mid:.4f}  (was 6.20)")
else:
    conf_mid, entr_mid = 0.30, 6.20
    print("  [SKIP] ResNet not loaded — keeping defaults")

# ─────────────────────────────────────────────────────────────────────────────
# STEP 11 — SAVE TO DB (only if safety check passed)
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "─"*65)
print("STEP 11 — Saving to database")
print("─"*65)

calibration_ts = datetime.utcnow().isoformat()

if SAVE_TO_DB:
    db_path = Path(args.db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute("""CREATE TABLE IF NOT EXISTS model_config
                    (key TEXT PRIMARY KEY, value TEXT NOT NULL,
                     updated_at TEXT NOT NULL, notes TEXT)""")
    entries = [
        ("W_YOLO_NORMAL",             str(round(W_YOLO,             4)), "AUROC-derived YOLO weight"),
        ("W_AE_NORMAL",               str(round(W_AE,               4)), "AUROC-derived AE weight"),
        ("W_RESNET_NORMAL",           str(round(W_RESNET,           4)), "AUROC-derived ResNet weight"),
        ("W_YOLO_HARDENED",           str(round(W_YOLO   * 1.33,    4)), "Hardened YOLO weight"),
        ("W_AE_HARDENED",             str(round(W_AE     * 1.50,    4)), "Hardened AE weight"),
        ("W_RESNET_HARDENED",         str(round(W_RESNET * 1.20,    4)), "Hardened ResNet weight"),
        ("META_C_YOLO",               str(round(c_yolo,             4)), "Meta-learner YOLO coef"),
        ("META_C_RESNET",             str(round(c_res,              4)), "Meta-learner ResNet coef"),
        ("META_C_AE",                 str(round(c_ae,               4)), "Meta-learner AE coef"),
        ("META_BIAS",                 str(round(bias,               4)), "Meta-learner bias"),
        ("THRESHOLD_NORMAL",          str(round(best_threshold,     4)), "Decision threshold normal"),
        ("THRESHOLD_HARDENED",        str(round(best_threshold*0.73,4)), "Decision threshold hardened"),
        ("AE_MSE_THRESHOLD_NORMAL",   str(round(best_ae,            4)), "AE MSE threshold normal"),
        ("AE_MSE_THRESHOLD_HARDENED", str(round(best_ae  * 0.67,    4)), "AE MSE threshold hardened"),
        ("RESNET_CONF_MID_NORMAL",    str(round(conf_mid,           4)), "ResNet conf midpoint"),
        ("RESNET_ENTR_MID_NORMAL",    str(round(entr_mid,           4)), "ResNet entr midpoint"),
        ("RESNET_CONF_MID_HARDENED",  str(round(conf_mid * 0.67,    4)), "Hardened conf midpoint"),
        ("RESNET_ENTR_MID_HARDENED",  str(round(entr_mid * 0.94,    4)), "Hardened entr midpoint"),
        ("CALIBRATION_DATE",          calibration_ts,                     "Calibration timestamp"),
        ("CALIBRATION_N_CLEAN",       str(n_clean_actual),                "Clean images used"),
        ("CALIBRATION_N_ADV",         str(n_adv_actual),                  "Adversarial images used"),
        ("CALIBRATION_CV_AUROC",      str(round(cv_mean,            4)), "5-fold CV AUROC"),
        ("CALIBRATION_CV_STD",        str(round(cv_std,             4)), "5-fold CV std"),
        ("CALIBRATION_AUROC",         str(round(overall_auroc,      4)), "Ensemble AUROC"),
        ("CALIBRATION_F1",            str(round(best_f1,            4)), "F1 at best threshold"),
    ]
    for k, v, n in entries:
        conn.execute("INSERT OR REPLACE INTO model_config VALUES (?,?,?,?)",
                     (k, v, calibration_ts, n))
    conn.commit(); conn.close()
    print(f"  ✅ Saved {len(entries)} entries to {args.db_path}")
    print(f"\n  ── DOCKER NEXT STEP ──────────────────────────────────────")
    print(f"  docker compose up --build ivm -d")
    print(f"  IVM will load calibrated values automatically on startup.")
    print(f"  ──────────────────────────────────────────────────────────")
else:
    print(f"  ⛔ NOT saved — CV AUROC {cv_mean:.4f} < {args.min_auroc}")
    print(f"  Hardcoded values remain active. No restart needed.")

# ─────────────────────────────────────────────────────────────────────────────
# STEP 12 — WRITE REPORT (always, regardless of save decision)
# ─────────────────────────────────────────────────────────────────────────────
status = "SAVED ✅" if SAVE_TO_DB else f"NOT SAVED (CV AUROC {cv_mean:.4f} < {args.min_auroc}) ⛔"
report = f"""
{'='*65}
  PhantomNet++ Calibration Report
  Generated : {calibration_ts}
  DB Status : {status}
{'='*65}

DATASET
  Clean images used        : {n_clean_actual}
  Adversarial images       : {n_adv_actual}
  Ratio                    : {n_clean_actual/max(n_adv_actual,1):.1f}:1
  Note: ALL DAG output folders treated as adversarial (incl. 00_Clean_Baseline)
        Clean images sourced exclusively from Tiny ImageNet

YOLO DIAGNOSTIC
  NMS available            : {NMS_AVAILABLE}
  YOLO valid outputs       : {y_valid}/{len(records)}

SAFETY CHECK
  5-fold CV AUROC          : {cv_mean:.4f} ± {cv_std:.4f}
  Minimum required         : {args.min_auroc}
  Result                   : {'PASSED ✅' if SAVE_TO_DB else 'FAILED ⛔'}

LEARNED VALUES  {'(active)' if SAVE_TO_DB else '(not applied — for reference only)'}

  Ensemble Weights (AUROC-normalised)
    W_YOLO   normal        : {W_YOLO:.4f}   was 1.5 (ratio 0.405)
    W_AE     normal        : {W_AE:.4f}   was 1.2 (ratio 0.324)
    W_RESNET normal        : {W_RESNET:.4f}   was 1.0 (ratio 0.270)

  Meta-Learner (logistic regression)
    c_yolo                 : {c_yolo:.4f}   was 2.2
    c_resnet               : {c_res:.4f}   was 1.1
    c_ae                   : {c_ae:.4f}   was 1.8
    bias                   : {bias:.4f}   was -2.4

  Decision Threshold (max-F1)
    Normal                 : {best_threshold:.4f}   was 0.55
    Hardened               : {best_threshold*0.73:.4f}   was 0.40

  AE MSE Threshold
    Normal                 : {best_ae:.4f}   was 0.45
    Hardened               : {best_ae*0.67:.4f}   was 0.30

  ResNet Midpoints
    conf_mid               : {conf_mid:.4f}   was 0.30
    entr_mid               : {entr_mid:.4f}   was 6.20

PERFORMANCE
  Ensemble AUROC           : {overall_auroc:.4f}
  Best F1                  : {best_f1:.4f}
  5-fold CV AUROC          : {cv_mean:.4f} ± {cv_std:.4f}
{'='*65}
"""
print(report)
Path("calibration_report.txt").write_text(report)
print("[DONE] calibration_report.txt written.")