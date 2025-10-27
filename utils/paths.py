# utils/paths.py
from __future__ import annotations
import os
from pathlib import Path

APP_NAME = "XiaoHackParental"  # Nombre de carpeta en ProgramData/LocalAppData

def is_dev_root(root: Path) -> bool:
    # Heurística simple: si vemos VERSION o .git en la raíz, asumimos dev
    return (root / "VERSION").exists() or (root / ".git").exists()

def get_root_dir() -> Path:
    """
    Directorio base de instalación en producción.
    En dev, devuelve la raíz del repo.
    """
    # Si estamos ejecutando desde el repo, usa esa raíz:
    here = Path(__file__).resolve()
    for parent in [here] + list(here.parents):
        if is_dev_root(parent):
            return parent

    # Producción (instalado por BAT/ZIP)
    programdata = Path(os.getenv("ProgramData", r"C:\ProgramData"))
    return programdata / APP_NAME

def get_runtime_dir() -> Path:
    d = get_root_dir() / "runtime"
    d.mkdir(parents=True, exist_ok=True)
    return d

def get_bin_dir() -> Path:
    d = get_root_dir() / "bin"
    d.mkdir(parents=True, exist_ok=True)
    return d

def get_logs_dir() -> Path:
    d = get_root_dir() / "logs"
    d.mkdir(parents=True, exist_ok=True)
    return d

def get_config_dir() -> Path:
    """
    Config de usuario (por si separas datos por usuario).
    """
    local = Path(os.getenv("LOCALAPPDATA", r"C:\Users\Public\AppData\Local"))
    d = local / APP_NAME
    d.mkdir(parents=True, exist_ok=True)
    return d

def get_assets_dir() -> Path:
    """
    En dev: assets del repo. En prod: copiamos /assets/ a la instalación.
    """
    root = get_root_dir()
    d = root / "assets"
    d.mkdir(parents=True, exist_ok=True)
    return d

def get_venv_dir() -> Path:
    return get_root_dir() / "venv"

def get_pythonw_exe() -> Path:
    venv = get_venv_dir()
    cand = [
        venv / "Scripts" / "pythonw.exe",
        venv / "Scripts" / "python.exe",
    ]
    for c in cand:
        if c.exists():
            return c
    # Fallback al Python del sistema
    sys_py = Path(os.getenv("PYTHONW_EXE", ""))  # opcional
    if sys_py:
        return Path(sys_py)
    return Path("pythonw.exe")

def get_app_entry() -> Path:
    """
    Punto de entrada del GUI (tu run.py actual).
    """
    return get_root_dir() / "run.py"

def get_log_file(name: str = "control.log") -> Path:
    return get_logs_dir() / name
