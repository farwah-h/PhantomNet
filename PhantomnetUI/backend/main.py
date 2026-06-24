import os
import random
import uuid
import base64
import io
import json
import numpy as np
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from siem_logger import siem_log, SiemSeverity, SiemSource
from pydantic import BaseModel
from PIL import Image

import torch
import torch.nn as nn
from torchvision import models, transforms

# --- CONFIGURATION ---
IMAGENET_FOLDER = "imagenet_subset"
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# --- APP SETUP ---
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- MODEL LOADER ---
print(f"Loading ResNet50 on {DEVICE}...")
weights = models.ResNet50_Weights.DEFAULT
model = models.resnet50(weights=weights).to(DEVICE)
model.eval()
preprocess = weights.transforms()
labels = weights.meta["categories"]

# --- UTILS ---

def image_to_base64(img: Image.Image) -> str:
    buffered = io.BytesIO()
    img.save(buffered, format="JPEG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    return f"data:image/jpeg;base64,{img_str}"

def get_random_image():
    if not os.path.exists(IMAGENET_FOLDER):
        os.makedirs(IMAGENET_FOLDER, exist_ok=True)
        import urllib.request
        try:
            [urllib.request.urlretrieve(f'https://picsum.photos/224/224?random={i}', f'{IMAGENET_FOLDER}/img_{i}.jpg') for i in range(5)]
        except: pass

    all_images = []
    for root, dirs, files in os.walk(IMAGENET_FOLDER):
        for file in files:
            if file.lower().endswith(('.png', '.jpg', '.jpeg')):
                all_images.append(os.path.join(root, file))
    
    if not all_images:
        raise HTTPException(status_code=404, detail="No images found")
    
    img_path = random.choice(all_images)
    try:
        img = Image.open(img_path).convert('RGB')
        return img, img_path
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

# Helper to reverse normalization for display
def denorm_tensor_to_pil(tensor):
    mean = torch.tensor([0.485, 0.456, 0.406]).view(3, 1, 1).to(DEVICE)
    std = torch.tensor([0.229, 0.224, 0.225]).view(3, 1, 1).to(DEVICE)
    
    # Check if batch dimension exists
    if tensor.dim() == 4:
        tensor = tensor.squeeze(0)
        
    x = tensor * std + mean
    x = torch.clamp(x, 0, 1)
    return transforms.ToPILImage()(x.cpu())

# --- AGGRESSIVE ATTACKS ---

def perform_attack(attack_type, image_tensor, target_label_idx, strength_factor):
    """strength_factor (1.0 to 10.0): Multiplier to force the attack harder."""
    # Ensure image_tensor is cloned and detached
    image_tensor = image_tensor.clone().detach()
    image_tensor.requires_grad = True
    
    epsilon = 0.1 * strength_factor 
    
    if attack_type == 'fgsm':
        output = model(image_tensor)
        loss = nn.CrossEntropyLoss()(output, target_label_idx)
        model.zero_grad()
        loss.backward()
        data_grad = image_tensor.grad.data
        adv_image = image_tensor + epsilon * data_grad.sign()
        return adv_image

    elif attack_type == 'pgd':
        steps = int(10 * strength_factor)
        alpha = epsilon / 4
        adv_image = image_tensor.clone().detach()
        for _ in range(steps):
            adv_image.requires_grad = True
            output = model(adv_image)
            loss = nn.CrossEntropyLoss()(output, target_label_idx)
            model.zero_grad()
            loss.backward()
            with torch.no_grad():
                adv_image = adv_image + alpha * adv_image.grad.sign()
                delta = torch.clamp(adv_image - image_tensor, min=-epsilon, max=epsilon)
                adv_image = image_tensor + delta
        return adv_image

    elif attack_type == 'patch':
        # FIXED: Correctly handle 4D tensor slicing
        base_size = 50 
        size = int(base_size * strength_factor) 
        
        # Denormalize
        mean = torch.tensor([0.485, 0.456, 0.406]).view(1, 3, 1, 1).to(DEVICE)
        std = torch.tensor([0.229, 0.224, 0.225]).view(1, 3, 1, 1).to(DEVICE)
        
        orig_denorm = image_tensor * std + mean
        
        # Get dimensions (Batch, Channel, Height, Width)
        b, c, h, w = orig_denorm.shape
        size = min(size, h-1)
        
        # Create solid high-contrast noise patch
        patch = torch.randint(0, 2, (c, size, size)).float().to(DEVICE)
        
        x = (w - size) // 2
        y = (h - size) // 2
        
        # Apply patch to the first image in batch [0]
        # Syntax: [Batch 0, All Channels, Height Slice, Width Slice]
        orig_denorm[0, :, y:y+size, x:x+size] = patch
        
        # Re-normalize
        normalize = transforms.Normalize([0.485, 0.456, 0.406], [0.229, 0.224, 0.225])
        # Need to squeeze batch dim for Normalize, then unsqueeze back
        return normalize(orig_denorm.squeeze(0)).unsqueeze(0)

    return image_tensor

# --- API ---

class SimulationRequest(BaseModel):
    name: str
    type: str  
    targetModel: str
    patchSize: int = 50
    brightness: int = 50
    noiseLevel: int = 30 
    occlusionArea: int = 40

@app.post("/api/simulation/start")
async def start_simulation(req: SimulationRequest):
    # Log the ACTUAL type being used to debug mismatches
    print(f"Starting Nuclear Simulation. Name: {req.name}, Type: {req.type}")
    
    original_pil, img_path = get_random_image()
    input_tensor = preprocess(original_pil).unsqueeze(0).to(DEVICE)

    output = model(input_tensor)
    init_pred_idx = output.max(1, keepdim=True)[1]
    init_label = labels[init_pred_idx.item()]
    print(f"Initial Pred: {init_label}")

    final_label = init_label
    final_conf = 0.0
    current_tensor = input_tensor
    
    # LOOP UNTIL SUCCESS
    base_strength = max(1.0, req.noiseLevel / 20.0)
    
    for attempt in range(1, 10): # Try up to 10 times
        print(f"--- Attempt {attempt} (Strength: {base_strength:.1f}) ---")
        
        try:
            current_tensor = perform_attack(
                req.type.lower(), 
                input_tensor, 
                init_pred_idx.view(-1), 
                strength_factor=base_strength
            )
            
            output_adv = model(current_tensor)
            adv_pred_idx = output_adv.max(1, keepdim=True)[1]
            final_conf = torch.nn.functional.softmax(output_adv, dim=1)[0][adv_pred_idx].item()
            final_label = labels[adv_pred_idx.item()]
            
            if final_label != init_label:
                print(f"SUCCESS! Fooled model into thinking it's: {final_label}")
                break
            else:
                print("Failed. DOUBLING STRENGTH...")
                base_strength += 1.5 
        except Exception as e:
            print(f"Attack Step Failed: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    res_before_pil = denorm_tensor_to_pil(input_tensor)
    res_after_pil = denorm_tensor_to_pil(current_tensor)
    is_success = final_label != init_label
    
    sim_id = f"SIM-{str(uuid.uuid4())[:6].upper()}"

    # ── SIEM: log simulation ─────────────────────────────────────────────────
    siem_log(
        severity   = SiemSeverity.WARNING if is_success else SiemSeverity.INFO,
        source     = SiemSource.DAG,
        event_type = "SimulationRun",
        message    = f"Attack simulation {'succeeded' if is_success else 'failed'}: {init_label} → {final_label} (conf {final_conf*100:.1f}%)",
        metadata   = {
            "sim_id":     sim_id,
            "is_success": is_success,
            "init_label": init_label,
            "final_label": final_label,
            "confidence": round(final_conf, 4),
        }
    )
    # ────────────────────────────────────────────────────────────────────────

    return {
        "id": sim_id,
        "beforeImage": image_to_base64(res_before_pil),
        "afterImage": image_to_base64(res_after_pil),
        "successRate": 100.0 if is_success else 0.0,
        "confidence": round(final_conf, 4),
        "confusionMatrix": [{"predicted": final_label, "actual": init_label, "count": 1}],
        "topMisclassifications": [{"class": f"{init_label} → {final_label}", "count": 1, "percentage": 100.0}]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)