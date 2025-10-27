# utils/runtime.py
from __future__ import annotations
import sys
import ctypes
import traceback
from typing import Optional

# --- Runtime paths/helpers usados por xiao_gui/services.py -------------------
from pathlib import Path
from utils import paths as xh_paths  # reutilizamos lo que ya tienes

# Ramas / nombres de tareas (coherente con el instalador)
_TASK_NAMESPACE = r"XiaoHackParental"
def task_fullname_guardian() -> str:
    return rf"{_TASK_NAMESPACE}\Guardian"

def task_fullname_notifier() -> str:
    # Nota: aunque hoy usamos Startup común, dejamos esta utilidad por si usas tarea ONLOGON
    return rf"{_TASK_NAMESPACE}\Notifier"

def install_root() -> Path:
    """Carpeta de instalación del runtime (ProgramData\\XiaoHackParental en prod o raíz del repo en dev)."""
    return xh_paths.get_root_dir()

def datadir_system() -> Path:
    """Datos del sistema (ProgramData\\XiaoHackParental)."""
    return xh_paths.get_root_dir()

def control_log_path() -> Path:
    """Ruta al control.log unificado."""
    return xh_paths.get_logs_dir() / "control.log"

def python_for_console() -> str:
    """Devuelve python.exe (preferiblemente del venv)."""
    venv = xh_paths.get_venv_dir() / "Scripts" / "python.exe"
    if venv.exists():
        return str(venv)
    return sys.executable  # fallback

def python_for_windowed() -> str:
    """Devuelve pythonw.exe (preferiblemente del venv)."""
    venvw = xh_paths.get_venv_dir() / "Scripts" / "pythonw.exe"
    if venvw.exists():
        return str(venvw)
    # fallback a python.exe si no hay pythonw
    venv = xh_paths.get_venv_dir() / "Scripts" / "python.exe"
    if venv.exists():
        return str(venv)
    return sys.executable

def updater_path() -> Path:
    """Busca updater.py en la raíz de instalación."""
    root = install_root()
    cand = [root / "updater.py", root / "app" / "updater.py"]
    for c in cand:
        if c.exists():
            return c
    return cand[0]

def uninstaller_path() -> Path:
    """Busca uninstall.py (acepta raíz o app/ para compatibilidad con tu árbol actual)."""
    root = install_root()
    cand = [root / "uninstall.py", root / "app" / "uninstall.py"]
    for c in cand:
        if c.exists():
            return c
    return cand[0]

def quote(s: str) -> str:
    """Quote simple para rutas con espacios en comandos de schtasks / TR."""
    s = str(s)
    if " " in s or "(" in s or ")" in s:
        if not (s.startswith('"') and s.endswith('"')):
            return f'"{s}"'
    return s


# --- Parseo de rol -------------------------------------------------------------
def parse_role(argv: list[str]) -> Optional[str]:
    try:
        if "--xh-role" in argv:
            i = argv.index("--xh-role")
            if i + 1 < len(argv):
                return argv[i + 1]
    except Exception:
        pass
    return None

# --- AppUserModelID (icono en barra de tareas) --------------------------------
def set_appusermodelid(app_id: str = "XiaoHack.Parental.Panel") -> None:
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(app_id)
    except Exception:
        pass

# --- Título del proceso (si setproctitle está disponible) ---------------------
def set_process_title(role: Optional[str]) -> None:
    try:
        import setproctitle  # type: ignore
        title = f"XiaoHack-{role}" if role else "XiaoHack"
        setproctitle.setproctitle(title)
    except Exception:
        pass

# --- Elevación UAC -------------------------------------------------------------
def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def relaunch_elevated(extra_args: list[str] | None = None, logger=None) -> None:
    """
    Relanza el proceso con elevación UAC, añadiendo --elevated para evitar bucles.
    """
    extra_args = extra_args or []
    if "--elevated" not in extra_args:
        extra_args = extra_args + ["--elevated"]
    params = " ".join(f'"{a}"' for a in (sys.argv + extra_args))
    exe = sys.executable
    if logger:
        logger.info("Requiere privilegios admin, relanzando con UAC…")
        logger.debug("Exe: %s", exe)
        logger.debug("Params: %s", params)
    try:
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        if logger:
            logger.info("ShellExecuteW retornó: %s", ret)
    except Exception:
        if logger:
            logger.error("Error al relanzar con elevación:\n%s", traceback.format_exc())
    sys.exit(0)

def maybe_elevate(require_admin: bool, argv: list[str], logger=None) -> None:
    """
    Si require_admin=True y no somos admin, relanza con UAC.
    Evita bucles si ya venimos con --elevated.
    """
    if not require_admin:
        return
    argv_lower = {a.lower() for a in argv[1:]}
    if "--elevated" in argv_lower:
        if logger:
            logger.info("Ejecutando ya en modo elevado (flag --elevated detectado).")
        return
    if is_admin():
        if logger:
            logger.info("Permisos de administrador confirmados.")
        return
    relaunch_elevated([], logger=logger)
