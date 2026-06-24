# dag/scripts/preprocess.py
"""
Dataset-aware preprocessing for Sprint 1.
Supports:
 - CIFAR-10 binary batches: data/cifar-10-batches-py/
 - Tiny ImageNet: data/tiny-imagenet-200/{train,test}
Saves example preprocessed images to dag/data/preprocessed/
"""

import os
import pickle
from PIL import Image
import numpy as np
import cv2
from torchvision import transforms

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
DATA_ROOT = os.path.join(BASE_DIR, "data")
OUTPUT_DIR = os.path.join(BASE_DIR, "dag", "data", "preprocessed")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# torchvision transform for model-ready tensorization (kept here for reference)
transform = transforms.Compose([
    transforms.Resize((224, 224)),
    transforms.ToTensor(),  # yields 0-1 floats
    transforms.Normalize(mean=[0.485,0.456,0.406], std=[0.229,0.224,0.225])
])

def save_visual(arr_rgb_uint8, out_path):
    """arr_rgb_uint8 is HxWx3 uint8 (RGB). Save as BGR for cv2."""
    cv2.imwrite(out_path, cv2.cvtColor(arr_rgb_uint8, cv2.COLOR_RGB2BGR))

def preprocess_pil_to_vis(img_pil):
    """Given PIL RGB image, resize, normalize for display and return uint8 HWC"""
    img_resized = img_pil.resize((224,224))
    arr = np.array(img_resized).astype("float32") / 255.0
    # simple min-max scale back to 0-255 for visualizing normalized tensor
    arr_v = ((arr - arr.min()) / (arr.max()-arr.min()+1e-8) * 255.0).astype("uint8")
    return arr_v

# ---- CIFAR loader ----
def load_cifar10_samples(cifar_dir, max_samples=10):
    """Read CIFAR-10 batch files and yield PIL images (RGB)."""
    samples = []
    def load_batch(p):
        with open(p, "rb") as f:
            entry = pickle.load(f, encoding='latin1')
        data = entry['data']  # N x 3072
        labels = entry.get('labels', entry.get('fine_labels', None))
        for i in range(min(data.shape[0], max_samples - len(samples))):
            img_flat = data[i]
            # convert to HWC uint8
            r = img_flat[0:1024].reshape(32,32)
            g = img_flat[1024:2048].reshape(32,32)
            b = img_flat[2048:3072].reshape(32,32)
            img = np.dstack((r,g,b)).astype('uint8')
            samples.append(Image.fromarray(img))
            if len(samples) >= max_samples:
                break

    # load a couple of batches
    for fname in sorted(os.listdir(cifar_dir)):
        if fname.endswith(".bin") or fname.endswith(".pkl") or fname.startswith("data_batch") or fname.startswith("test_batch"):
            load_batch(os.path.join(cifar_dir, fname))
        if len(samples) >= max_samples:
            break
    return samples

# ---- Tiny ImageNet loader ----
def load_tiny_imagenet_samples(tiny_dir, max_samples=10):
    """Scan train/val and yield PIL images."""
    samples = []
    train_dir = os.path.join(tiny_dir, "train")
    # train/<wnid>/images/*.JPEG or train/<wnid>/images/*.jpg
    if os.path.isdir(train_dir):
        for wn in sorted(os.listdir(train_dir)):
            imgs_dir = os.path.join(train_dir, wn, "images")
            if os.path.isdir(imgs_dir):
                for fname in sorted(os.listdir(imgs_dir)):
                    if fname.lower().endswith(('.jpg', '.jpeg', '.png', '.JPEG')):
                        samples.append(Image.open(os.path.join(imgs_dir, fname)).convert("RGB"))
                        if len(samples) >= max_samples:
                            return samples
    # fallback to test folder
    test_dir = os.path.join(tiny_dir, "test")
    if os.path.isdir(test_dir):
        for root, _, files in os.walk(test_dir):
            for fname in files:
                if fname.lower().endswith(('.jpg', '.jpeg', '.png', '.JPEG')):
                    samples.append(Image.open(os.path.join(root, fname)).convert("RGB"))
                    if len(samples) >= max_samples:
                        return samples
    return samples

# ---- main driver ----
def main(dataset="auto"):
    # auto-select dataset
    cifar_dir = os.path.join(DATA_ROOT, "cifar-10-batches-py")
    tiny_dir = os.path.join(DATA_ROOT, "tiny-imagenet-200")
    images = []
    if dataset in ("auto","cifar") and os.path.isdir(cifar_dir):
        print("[*] Loading CIFAR-10 samples from", cifar_dir)
        images = load_cifar10_samples(cifar_dir, max_samples=8)
    if (not images) and (dataset in ("auto","tiny","imagenet","tiny-imagenet")) and os.path.isdir(tiny_dir):
        print("[*] Loading Tiny ImageNet samples from", tiny_dir)
        images = load_tiny_imagenet_samples(tiny_dir, max_samples=8)
    if not images:
        raise FileNotFoundError("No supported dataset found under data/. Expected cifar-10-batches-py/ or tiny-imagenet-200/")

    # save visual previews
    for i, pil_img in enumerate(images):
        vis = preprocess_pil_to_vis(pil_img)
        out = os.path.join(OUTPUT_DIR, f"sample_{i+1}.png")
        save_visual(vis, out)
        print("[+] Saved", out)
    print("✅ Preprocessing preview complete. Check:", OUTPUT_DIR)

if __name__ == "__main__":
    import sys
    ds = sys.argv[1] if len(sys.argv) > 1 else "auto"
    main(ds)
