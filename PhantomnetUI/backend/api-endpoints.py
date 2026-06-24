from database import (
    init_database,
    save_prediction,
    get_all_predictions,
    get_prediction_by_id,
    get_statistics
)
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

PKT = timezone(timedelta(hours=5))  # Pakistan Standard Time (UTC+5)

# Directory to store uploaded images
UPLOAD_DIR = Path(__file__).parent / 'uploads'
UPLOAD_DIR.mkdir(exist_ok=True)

# Initialize database on startup
init_database()

# =============================================================================
# ADD THESE NEW ENDPOINTS TO YOUR FASTAPI APP
# =============================================================================

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "online", "database": "connected"}


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
        
        # Return response
        return {
            'timestamp': datetime.now(PKT).isoformat(),
            'id': threat_id,
            'prediction_id': prediction_id,  # NEW: database ID
            'filename': image.filename,
            'individual_results': individual_results,
            'ensemble': ensemble,
            'threat_data': threat_data
        }
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
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