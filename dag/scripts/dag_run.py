"""
dag_run.py — Sprint 1
Evaluate original vs patched images using pretrained ResNet50 (CPU-friendly).
"""

import os
import torch
from PIL import Image
from torchvision import models, transforms

# Base paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
ORIG_IMG = os.path.join(BASE_DIR, "dag", "data", "preprocessed", "sample_1.png")
PATCHED_IMG = os.path.join(BASE_DIR, "dag", "data", "patched_demo.png")

# Define preprocessing transform (matches training)
transform = transforms.Compose([
    transforms.Resize((224, 224)),
    transforms.ToTensor(),
    transforms.Normalize(mean=[0.485, 0.456, 0.406],
                         std=[0.229, 0.224, 0.225])
])

def load_image_tensor(path):
    """Load image as normalized tensor batch (1,3,224,224)."""
    img = Image.open(path).convert("RGB")
    return transform(img).unsqueeze(0)

def predict(model, img_tensor):
    """Return top-1 class index."""
    with torch.no_grad():
        logits = model(img_tensor)
        pred = logits.argmax(dim=1).item()
    return pred

def main():
    device = torch.device("cpu")  # force CPU mode
    model = models.resnet50(weights=models.ResNet50_Weights.DEFAULT).to(device)
    model.eval()

    if not os.path.exists(ORIG_IMG) or not os.path.exists(PATCHED_IMG):
        raise FileNotFoundError("Make sure preprocess.py and patch_pipeline.py have been run first.")

    # Load tensors
    t_orig = load_image_tensor(ORIG_IMG).to(device)
    t_patch = load_image_tensor(PATCHED_IMG).to(device)

    # Predictions
    pred_orig = predict(model, t_orig)
    pred_patch = predict(model, t_patch)

    print(f"Original Image Prediction Index: {pred_orig}")
    print(f"Patched Image Prediction Index:  {pred_patch}")

if __name__ == "__main__":
    main()
