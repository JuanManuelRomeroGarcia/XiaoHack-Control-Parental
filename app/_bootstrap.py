# app/_bootstrap.py — fija sys.path y cwd al raíz de instalación (venv o portable)
from __future__ import annotations
import os
import sys
from pathlib import Path

def _root_dir() -> Path | None:
    try:
        # ...\XiaoHackParental
        return Path(__file__).resolve().parent.parent
    except Exception:
        return None

ROOT = _root_dir()
if ROOT:
    root_str = str(ROOT)
    # Asegura que el paquete 'app' se pueda importar aunque el CWD sea distinto
    if root_str not in sys.path:
        sys.path.insert(0, root_str)
    # CWD coherente para logs/assets
    try:
        os.chdir(ROOT)
    except Exception:
        pass

# En portable, garantiza que se procesen .pth (xh_portable.pth, pywin32, etc.)
try:
    import site  # noqa: F401  (side effects: añade site-packages + .pth a sys.path)
except Exception:
    pass
