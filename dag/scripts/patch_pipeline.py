# dag/scripts/patch_pipeline.py
"""
Digital patch generation + apply utilities.
Creates rectangular patches and applies them to RGB HxWx3 uint8 images.
Saves patched images and metadata.
"""

import os, json, numpy as np
from PIL import Image

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
OUT_DIR = os.path.join(BASE_DIR, "dag", "data")
os.makedirs(OUT_DIR, exist_ok=True)

def generate_patch(patch_size=(60,60), pattern="random", color=(255,0,0), seed=None):
    if seed is not None:
        np.random.seed(seed)
    h,w = patch_size
    if pattern == "random":
        return np.random.randint(0,256,(h,w,3), dtype=np.uint8)
    elif pattern == "solid":
        return np.full((h,w,3), color, dtype=np.uint8)
    else:
        return np.random.randint(0,256,(h,w,3), dtype=np.uint8)

def apply_patch(img_rgb, patch, x=None, y=None):
    """
    img_rgb: HxWx3 uint8 numpy
    patch: phxpw x3 uint8 numpy
    returns (patched_img, meta)
    """
    img = img_rgb.copy()
    ih, iw = img.shape[:2]
    ph, pw = patch.shape[:2]
    if ph > ih or pw > iw:
        raise ValueError("Patch larger than image")
    if x is None:
        x = np.random.randint(0, iw - pw + 1)
    if y is None:
        y = np.random.randint(0, ih - ph + 1)
    img[y:y+ph, x:x+pw] = patch
    meta = {"x":int(x), "y":int(y), "w":int(pw), "h":int(ph)}
    return img, meta

def save_image(arr_rgb_uint8, path):
    Image.fromarray(arr_rgb_uint8).save(path)

def save_meta(meta, path):
    with open(path, "w") as f:
        json.dump(meta, f, indent=2)

# quick demo if run directly
if __name__ == "__main__":
    # try to use a preprocessed sample if available
    sample = os.path.join(BASE_DIR, "dag", "data", "preprocessed", "sample_1.png")
    if not os.path.exists(sample):
        raise FileNotFoundError("Sample not found. Run preprocess first.")
    img = np.array(Image.open(sample).convert("RGB"))
    patch = generate_patch((50,50), pattern="random", seed=42)
    patched, meta = apply_patch(img, patch)
    out_img = os.path.join(OUT_DIR, "patched_demo.png")
    out_meta = os.path.join(OUT_DIR, "patched_demo.json")
    save_image(patched, out_img)
    save_meta(meta, out_meta)
    print("[+] Saved patched image and metadata:", out_img, out_meta)

