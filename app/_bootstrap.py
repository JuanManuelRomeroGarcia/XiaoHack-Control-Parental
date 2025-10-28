# app/_bootstrap.py — fija sys.path y cwd al raíz de instalación
from __future__ import annotations
import os
import sys
from pathlib import Path

def _root_dir() -> Path | None:
    try:
        return Path(__file__).resolve().parent.parent  # ...\XiaoHackParental
    except Exception:
        return None

_root = _root_dir()
if _root:
    p = str(_root)
    if p not in sys.path:
        sys.path.insert(0, p)
    try:
        os.chdir(_root)  # cwd coherente para logs/assets
    except Exception:
        pass
