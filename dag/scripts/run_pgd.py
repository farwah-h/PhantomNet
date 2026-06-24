# dag/scripts/dag_run.py
import os
from PIL import Image
import numpy as np
import torch
from torchvision import models, transforms

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
PATCHED = os.path.join(BASE_DIR, "dag", "data", "patched_demo.png")
ORIG = os.path.join(BASE_DIR, "dag", "data", "preprocessed", "sample_1.png")

def load_model(device="cpu"):
    model = models.resnet50(pretrained=True).eval().to(device)
    return model

def imgpath_to_tensor(img_path, device="cpu"):
    transform = transforms.Compose([
        transforms.Resize((224,224)),
        transforms.ToTensor(),
        transforms.Normalize(mean=[0.485,0.456,0.406], std=[0.229,0.224,0.225])
    ])
    img = Image.open(img_path).convert("RGB")
    t = transform(img).unsqueeze(0).to(device)
    return t

def predict(model, tensor):
    with torch.no_grad():
        logits = model(tensor)
        return int(logits.argmax(dim=1).cpu().numpy()[0])

def main():
    device = "cpu"
    model = load_model(device)
    if not os.path.exists(ORIG) or not os.path.exists(PATCHED):
        raise FileNotFoundError("Ensure preprocess and patch_pipeline ran successfully.")
    t_orig = imgpath_to_tensor(ORIG, device)
    t_patched = imgpath_to_tensor(PATCHED, device)
    print("Original top-1:", predict(model, t_orig))
    print("Patched top-1: ", predict(model, t_patched))

if __name__ == "__main__":
    main()
