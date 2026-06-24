"""
calibration_loader.py — Load Learned Calibration Values into IVM
=================================================================
Drop this file next to threat_detection_backend.py.

In threat_detection_backend.py, add these two lines right after init_database():

    from calibration_loader import load_calibration
    load_calibration()

That's it. Every time IVM starts, it checks the model_config table.
If calibration values exist, they override the hardcoded constants.
If the table is empty (not yet calibrated), hardcoded values remain untouched.
"""

import sqlite3
import numpy as np
from pathlib import Path

# ── Point this at your actual DB ─────────────────────────────────────────────
_DB_PATH = Path(__file__).parent / "db" / "phantomnet.db"


def _read_config(conn: sqlite3.Connection) -> dict:
    """Read all model_config rows into a plain dict {key: value_as_string}."""
    try:
        cur = conn.execute("SELECT key, value FROM model_config")
        return {row[0]: row[1] for row in cur.fetchall()}
    except sqlite3.OperationalError:
        return {}   # table doesn't exist yet — calibration not run


def load_calibration(db_path: str = None) -> bool:
    """
    Read learned thresholds/weights/coefficients from phantomnet.db
    and patch the global variables in threat_detection_backend.

    Returns True if calibration values were found and applied, False otherwise.
    """
    import threat_detection_backend as ivm   # import the module whose globals we patch

    path = Path(db_path) if db_path else _DB_PATH
    if not path.exists():
        print("[calibration_loader] DB not found — using hardcoded defaults")
        return False

    conn = sqlite3.connect(str(path))
    cfg  = _read_config(conn)
    conn.close()

    if not cfg:
        print("[calibration_loader] model_config table empty — using hardcoded defaults")
        return False

    def get(key, fallback):
        try:
            return float(cfg[key]) if key in cfg else fallback
        except ValueError:
            return fallback

    # ── 1. Autoencoder MSE thresholds ────────────────────────────────────────
    ivm.AUTOENCODER_MSE_THRESHOLD = get("AE_MSE_THRESHOLD_NORMAL",   ivm.AUTOENCODER_MSE_THRESHOLD)
    ivm.HARDENED_AUTOENCODER_MSE  = get("AE_MSE_THRESHOLD_HARDENED", ivm.HARDENED_AUTOENCODER_MSE)

    # ── 2. ResNet sigmoid midpoints ───────────────────────────────────────────
    # These live inside detect_with_resnet() — we store them as module-level
    # attributes so detect_with_resnet() can read them dynamically.
    ivm.CALIBRATED_CONF_MID_NORMAL   = get("RESNET_CONF_MID_NORMAL",   0.30)
    ivm.CALIBRATED_ENTR_MID_NORMAL   = get("RESNET_ENTR_MID_NORMAL",   6.20)
    ivm.CALIBRATED_CONF_MID_HARDENED = get("RESNET_CONF_MID_HARDENED", 0.20)
    ivm.CALIBRATED_ENTR_MID_HARDENED = get("RESNET_ENTR_MID_HARDENED", 5.80)

    # ── 3. Ensemble weights ───────────────────────────────────────────────────
    ivm.CALIBRATED_W_YOLO_NORMAL    = get("W_YOLO_NORMAL",    1.5)
    ivm.CALIBRATED_W_AE_NORMAL      = get("W_AE_NORMAL",      1.2)
    ivm.CALIBRATED_W_RESNET_NORMAL  = get("W_RESNET_NORMAL",  1.0)
    ivm.CALIBRATED_W_YOLO_HARDENED  = get("W_YOLO_HARDENED",  2.0)
    ivm.CALIBRATED_W_AE_HARDENED    = get("W_AE_HARDENED",    1.8)
    ivm.CALIBRATED_W_RESNET_HARDENED= get("W_RESNET_HARDENED",1.2)

    # ── 4. Decision thresholds ────────────────────────────────────────────────
    ivm.CALIBRATED_THRESHOLD_NORMAL   = get("THRESHOLD_NORMAL",   0.55)
    ivm.CALIBRATED_THRESHOLD_HARDENED = get("THRESHOLD_HARDENED", 0.40)

    # ── 5. Meta-learner coefficients ──────────────────────────────────────────
    ivm.CALIBRATED_META_C_YOLO   = get("META_C_YOLO",   2.2)
    ivm.CALIBRATED_META_C_RESNET = get("META_C_RESNET", 1.1)
    ivm.CALIBRATED_META_C_AE     = get("META_C_AE",     1.8)
    ivm.CALIBRATED_META_BIAS     = get("META_BIAS",    -2.4)

    ts = cfg.get("CALIBRATION_DATE", "unknown")
    print(f"[calibration_loader] ✅ Loaded calibration from DB (run: {ts})")
    print(f"  Thresholds  → normal: {ivm.CALIBRATED_THRESHOLD_NORMAL:.4f}  "
          f"hardened: {ivm.CALIBRATED_THRESHOLD_HARDENED:.4f}")
    print(f"  AE MSE      → normal: {ivm.AUTOENCODER_MSE_THRESHOLD:.4f}  "
          f"hardened: {ivm.HARDENED_AUTOENCODER_MSE:.4f}")
    print(f"  Weights     → YOLO: {ivm.CALIBRATED_W_YOLO_NORMAL:.4f}  "
          f"AE: {ivm.CALIBRATED_W_AE_NORMAL:.4f}  "
          f"ResNet: {ivm.CALIBRATED_W_RESNET_NORMAL:.4f}")
    print(f"  Meta coefs  → c_y: {ivm.CALIBRATED_META_C_YOLO:.4f}  "
          f"c_r: {ivm.CALIBRATED_META_C_RESNET:.4f}  "
          f"c_ae: {ivm.CALIBRATED_META_C_AE:.4f}  "
          f"bias: {ivm.CALIBRATED_META_BIAS:.4f}")
    return True