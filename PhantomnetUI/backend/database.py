"""
PhantomNet++ Database Schema
SQLite database for storing predictions, explanations, and scan history
"""

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
import json

# Database path
DB_PATH = Path(__file__).parent / 'db' / 'phantomnet.db'

# Ensure db directory exists
DB_PATH.parent.mkdir(exist_ok=True)

def init_database():
    """Initialize the database with all required tables"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # =============================================================================
    # TABLE 1: PREDICTIONS
    # Stores every prediction/scan made by the system
    # =============================================================================
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_id TEXT UNIQUE NOT NULL,
            timestamp DATETIME NOT NULL,
            filename TEXT NOT NULL,
            image_path TEXT,
            
            -- Ensemble Decision
            final_decision TEXT NOT NULL,
            confidence REAL NOT NULL,
            severity TEXT NOT NULL,
            
            -- Attack Information
            attack_type TEXT,
            attack_category TEXT,
            primary_indicator TEXT,
            
            -- JSON fields for detailed results
            individual_results TEXT,  -- JSON: {resnet: {...}, yolo: {...}, autoencoder: {...}}
            ensemble_details TEXT,    -- JSON: full ensemble result
            characteristics TEXT,     -- JSON: array of characteristics
            
            -- Metadata
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # =============================================================================
    # TABLE 2: MODEL_RESULTS
    # Detailed results from each individual model
    # =============================================================================
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS model_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prediction_id INTEGER NOT NULL,
            model_name TEXT NOT NULL,
            is_adversarial BOOLEAN,
            confidence REAL,
            status TEXT,
            details TEXT,  -- JSON: model-specific details
            
            FOREIGN KEY (prediction_id) REFERENCES predictions(id) ON DELETE CASCADE
        )
    ''')
    
    # =============================================================================
    # TABLE 3: EXPLANATIONS
    # XAI explanations (Grad-CAM, LIME, SHAP)
    # =============================================================================
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS explanations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prediction_id INTEGER NOT NULL,
            method TEXT NOT NULL,  -- 'gradcam', 'lime', 'shap'
            heatmap_path TEXT,
            feature_importance TEXT,  -- JSON: top features and their importance
            generated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            
            FOREIGN KEY (prediction_id) REFERENCES predictions(id) ON DELETE CASCADE
        )
    ''')
    
    # =============================================================================
    # TABLE 4: IMAGES
    # Store uploaded images (optional - could also just store paths)
    # =============================================================================
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS images (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prediction_id INTEGER NOT NULL,
            image_data BLOB,
            image_format TEXT,
            width INTEGER,
            height INTEGER,
            uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            
            FOREIGN KEY (prediction_id) REFERENCES predictions(id) ON DELETE CASCADE
        )
    ''')
    
    # =============================================================================
    # TABLE 5: SCAN_HISTORY
    # Aggregated view for quick queries
    # =============================================================================
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_id TEXT NOT NULL,
            timestamp DATETIME NOT NULL,
            filename TEXT NOT NULL,
            decision TEXT NOT NULL,
            severity TEXT,
            attack_type TEXT,
            confidence REAL,
            has_explanation BOOLEAN DEFAULT 0,
            
            FOREIGN KEY (threat_id) REFERENCES predictions(threat_id)
        )
    ''')
    
    # =============================================================================
    # INDEXES for faster queries
    # =============================================================================
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_predictions_timestamp ON predictions(timestamp DESC)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_predictions_threat_id ON predictions(threat_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_predictions_decision ON predictions(final_decision)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_model_results_prediction ON model_results(prediction_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_explanations_prediction ON explanations(prediction_id)')
    
    conn.commit()
    conn.close()
    
    print(f"✅ Database initialized at: {DB_PATH}")


def save_prediction(threat_id, filename, image_path, ensemble_result, individual_results, threat_data):
    """
    Save a prediction to the database
    
    Args:
        threat_id: Unique threat ID (e.g., "THR-1234")
        filename: Original filename
        image_path: Path to saved image
        ensemble_result: Full ensemble decision dict
        individual_results: Dict with resnet, yolo, autoencoder results
        threat_data: Attack type, category, characteristics
    
    Returns:
        prediction_id: Database ID of the saved prediction
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # Insert main prediction
        cursor.execute('''
            INSERT INTO predictions (
                threat_id, timestamp, filename, image_path,
                final_decision, confidence, severity,
                attack_type, attack_category, primary_indicator,
                individual_results, ensemble_details, characteristics
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            threat_id,
            datetime.now(timezone(timedelta(hours=5))),
            filename,
            image_path,
            ensemble_result['final_decision'],
            ensemble_result['confidence'],
            ensemble_result['severity'],
            threat_data.get('type'),
            threat_data.get('category'),
            threat_data.get('primary_indicator'),
            json.dumps(individual_results),
            json.dumps(ensemble_result),
            json.dumps(threat_data.get('characteristics', []))
        ))
        
        prediction_id = cursor.lastrowid
        
        # Insert individual model results
        for model_name, result in individual_results.items():
            if result and not result.get('error'):
                cursor.execute('''
                    INSERT INTO model_results (
                        prediction_id, model_name, is_adversarial,
                        confidence, status, details
                    ) VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    prediction_id,
                    model_name,
                    result.get('is_adversarial'),
                    result.get('confidence'),
                    result.get('status'),
                    json.dumps(result)
                ))
        
        # Insert into scan history for quick access
        cursor.execute('''
            INSERT INTO scan_history (
                threat_id, timestamp, filename, decision,
                severity, attack_type, confidence
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            threat_id,
            datetime.now(timezone(timedelta(hours=5))),
            filename,
            ensemble_result['final_decision'],
            ensemble_result['severity'],
            threat_data.get('type'),
            ensemble_result['confidence']
        ))
        
        conn.commit()
        print(f"✅ Saved prediction {threat_id} to database (ID: {prediction_id})")
        return prediction_id
        
    except Exception as e:
        conn.rollback()
        print(f"❌ Error saving prediction: {e}")
        raise
    finally:
        conn.close()


def get_all_predictions(limit=50, offset=0):
    """Get all predictions with pagination"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT * FROM predictions
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
    ''', (limit, offset))
    
    results = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    # Parse JSON fields
    for result in results:
        result['individual_results'] = json.loads(result['individual_results'])
        result['ensemble_details'] = json.loads(result['ensemble_details'])
        result['characteristics'] = json.loads(result['characteristics'])
    
    return results


def get_prediction_by_id(threat_id):
    """Get a specific prediction by threat_id"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM predictions WHERE threat_id = ?', (threat_id,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        result = dict(result)
        result['individual_results'] = json.loads(result['individual_results'])
        result['ensemble_details'] = json.loads(result['ensemble_details'])
        result['characteristics'] = json.loads(result['characteristics'])
        return result
    return None


def get_statistics():
    """Get overall system statistics"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    stats = {}
    
    # Total scans
    cursor.execute('SELECT COUNT(*) FROM predictions')
    stats['total_scans'] = cursor.fetchone()[0]
    
    # Adversarial vs Clean
    cursor.execute('SELECT final_decision, COUNT(*) FROM predictions GROUP BY final_decision')
    decision_counts = dict(cursor.fetchall())
    stats['adversarial'] = decision_counts.get('adversarial', 0)
    stats['clean'] = decision_counts.get('clean', 0)
    
    # By severity
    cursor.execute('SELECT severity, COUNT(*) FROM predictions WHERE final_decision = "adversarial" GROUP BY severity')
    stats['by_severity'] = dict(cursor.fetchall())
    
    # By attack type
    cursor.execute('SELECT attack_type, COUNT(*) FROM predictions WHERE final_decision = "adversarial" GROUP BY attack_type ORDER BY COUNT(*) DESC LIMIT 5')
    stats['top_attack_types'] = dict(cursor.fetchall())
    
    # Recent activity (last 24 hours)
    cursor.execute('''
        SELECT COUNT(*) FROM predictions 
        WHERE timestamp > datetime('now', '-1 day')
    ''')
    stats['last_24h'] = cursor.fetchone()[0]
    
    conn.close()
    return stats


def save_explanation(prediction_id, method, heatmap_path, feature_importance):
    """Save an XAI explanation"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO explanations (
            prediction_id, method, heatmap_path, feature_importance
        ) VALUES (?, ?, ?, ?)
    ''', (
        prediction_id,
        method,
        heatmap_path,
        json.dumps(feature_importance) if feature_importance else None
    ))
    
    # Update has_explanation flag
    cursor.execute('''
        UPDATE scan_history 
        SET has_explanation = 1 
        WHERE threat_id = (
            SELECT threat_id FROM predictions WHERE id = ?
        )
    ''', (prediction_id,))
    
    conn.commit()
    conn.close()
    print(f"✅ Saved {method} explanation for prediction {prediction_id}")


def get_explanations(prediction_id):
    """Get all explanations for a prediction"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM explanations WHERE prediction_id = ?', (prediction_id,))
    results = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    # Parse JSON
    for result in results:
        if result['feature_importance']:
            result['feature_importance'] = json.loads(result['feature_importance'])
    
    return results


def clear_all_data():
    """Clear all data from database (useful for testing)"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('DELETE FROM explanations')
    cursor.execute('DELETE FROM model_results')
    cursor.execute('DELETE FROM images')
    cursor.execute('DELETE FROM scan_history')
    cursor.execute('DELETE FROM predictions')
    
    conn.commit()
    conn.close()
    print("✅ All data cleared from database")


# =============================================================================
# INITIALIZE ON IMPORT
# =============================================================================
if __name__ == "__main__":
    init_database()
    print("\n📊 Database Statistics:")
    stats = get_statistics()
    print(f"  Total Scans: {stats['total_scans']}")
    print(f"  Adversarial: {stats['adversarial']}")
    print(f"  Clean: {stats['clean']}")
    print(f"  Last 24h: {stats['last_24h']}")