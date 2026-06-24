# dag/tests/test_patch.py
import os
import sys
import pytest
import numpy as np
# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

# Now you can safely import from dag/scripts
from dag.scripts.patch_pipeline import generate_patch, apply_patch

def test_patch_apply():
    dummy = np.zeros((224,224,3), dtype=np.uint8)
    patch = generate_patch((20,20), pattern="solid", color=(10,20,30), seed=1)
    patched, meta = apply_patch(dummy, patch, x=10, y=15)
    assert (patched[15,10] == np.array([10,20,30])).all()
    assert meta["w"] == 20
