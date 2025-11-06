# utils/runtime.py
from __future__ import annotations
import os
import subprocess
import sys
import ctypes
from typing import Optional, Sequence

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
    return sys.executable


def python_for_windowed() -> str:
    exe = Path(sys.executable)
    pyw = exe.with_name("pythonw.exe")
    return str(pyw if pyw.exists() else exe)

def reexec_to_console_if_needed() -> bool:
    return False

def reexec_to_windowed_if_needed() -> bool:
    return False

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

def find_install_root(start: Path | None = None) -> Path:
    """
    Localiza la carpeta de instalación del runtime.
    Prioriza:
      1) var de entorno XH_INSTALL_DIR (instalador)
      2) carpeta padre que contenga updater.py o VERSION
      3) cwd
    """
    env = os.environ.get("XH_INSTALL_DIR", "").strip()
    if env:
        p = Path(env)
        if p.exists():
            return p

    here = Path(start or Path(__file__).resolve()).resolve()
    p = here
    for _ in range(6):
        if (p / "app").is_dir() or (p / "VERSION").exists() or (p / "VERSION.json").exists():
            return p
        if p.parent == p:
            break
        p = p.parent

    return Path.cwd()

def read_version(base: Path | None = None) -> str:
    """
    Devuelve la versión del runtime leyendo el fichero VERSION (utf-8).
    """
    try:
        root = find_install_root(base)
        return (root / "VERSION").read_text(encoding="utf-8").strip()
    except Exception:
        return "0.0.0"

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
def set_appusermodelid(appid: str) -> None:
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(appid)
    except Exception:
        pass

# --- Título del proceso (si setproctitle está disponible) ---------------------
def set_process_title(title: str) -> None:
    try:
        import setproctitle  # opcional
        setproctitle.setproctitle(title)
    except Exception:
        pass

# --- Elevación UAC -------------------------------------------------------------
def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def relaunch_elevated(argv: Sequence[str] | None = None) -> None:
    """
    Lanza el mismo módulo/script con privilegios elevados y termina el actual.
    Respeta XH_NO_REEXEC para no crear bucles ni dobles procesos.
    """
    if os.environ.get("XH_NO_REEXEC") == "1":
        return  # desactivado explícitamente
    try:
        # Ya admin/SYSTEM → no relanzar
        if ctypes.windll.shell32.IsUserAnAdmin():
            return
    except Exception:
        # Si falla la detección, mejor no relanzar que duplicar procesos
        return

    args = list(argv or sys.argv)
    exe  = current_interpreter(prefer_windowed=False)

    # Construye los parámetros correctamente (maneja espacios y comillas)
    try:
        params = subprocess.list2cmdline(args[1:])
    except Exception:
        params = " ".join(args[1:])

    try:
        # SW_SHOWNORMAL = 1
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        # ShellExecuteW devuelve >32 en éxito
        if rc > 32:
            os._exit(0)
        # Si rc <= 32, fallo: no hacemos nada (evitamos loops)
    except Exception:
        pass


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


def is_system_or_admin() -> bool:
    try:
        # True para Administrador y también para SYSTEM
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def current_interpreter(prefer_windowed: bool = False) -> str:
    """
    Devuelve el intérprete del venv si existe; si no, sys.executable.
    prefer_windowed=True → pythonw.exe si está disponible.
    """
    inst = Path(os.getenv("XH_INSTALL_DIR") or Path(__file__).resolve().parents[1])
    scripts = inst / "venv" / "Scripts"
    if prefer_windowed:
        cand = [scripts / "pythonw.exe", scripts / "python.exe"]
    else:
        cand = [scripts / "python.exe", scripts / "pythonw.exe"]
    for p in cand:
        if p.exists():
            return str(p)
    return sys.executable


def ensure_admin_for(role: str) -> None:
    """
    No eleva nunca para 'notifier'. Para 'guardian', asume que lo lanza Scheduler como SYSTEM.
    No hace NADA si ya se está elevado. Nunca relanza si XH_NO_REEXEC=1.
    """
    role = (role or "").lower()
    if role in ("notifier", "gui", "panel"):
        return
    if role == "guardian":
        return
    # Para cualquier otro rol especial, si quisieras, llama a relaunch_elevated().
    return
