# run.py — lanzador con elevación opcional (UAC) y logging centralizado
from __future__ import annotations

# =======================
# Bootstrap Python portable
# =======================
import os
import sys
import traceback
from pathlib import Path

# Endurecimiento del entorno (evita heredar cosas raras del sistema/usuario)
os.environ.setdefault("PYTHONUTF8", "1")
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
os.environ.setdefault("PYTHONNOUSERSITE", "1")

# 1) Resolver rutas clave
try:
    PROJECT_ROOT = Path(__file__).resolve().parent
except Exception:
    PROJECT_ROOT = Path.cwd()

# Si nos lanzan por .lnk/Task Scheduler sin cwd, fuerzo cwd al proyecto
try:
    os.chdir(str(PROJECT_ROOT))
except Exception:
    pass

# 2) DLLs & paths para portable (py312)
try:
    PYDIR = Path(sys.executable).parent            # ...\py312
    DLLS  = PYDIR / "DLLs"
    LIB   = PYDIR / "Lib"
    SITE  = LIB / "site-packages"

    # Carga de DLLs nativos (tcl/tk, _tkinter.pyd, pywin32, etc.)
    try:
        # Python 3.8+: imprescindible para evitar "DLL load failed" en portable
        os.add_dll_directory(str(PYDIR))
        os.add_dll_directory(str(DLLS))
    except Exception:
        pass

    # Amplío PATH para que Windows resuelva dependencias nativas
    os.environ["PATH"] = (
        f"{PYDIR};{DLLS};{os.environ.get('PATH','')}"
    )

    # Rutas de importación (primero portable)
    for p in (PYDIR, DLLS, LIB, SITE):
        sp = str(p)
        if sp not in sys.path:
            sys.path.insert(0, sp)

    # pywin32 system32 (si existe)
    PYW32_SYS = SITE / "pywin32_system32"
    if PYW32_SYS.exists():
        sp = str(PYW32_SYS)
        if sp not in sys.path:
            sys.path.insert(0, sp)
        os.environ["PATH"] = f"{sp};{os.environ.get('PATH','')}"

    # Tcl/Tk (Tkinter)
    os.environ.setdefault("TCL_LIBRARY", str(PYDIR / "tcl" / "tcl8.6"))
    os.environ.setdefault("TK_LIBRARY",  str(PYDIR / "tcl" / "tk8.6"))
except Exception:
    # No interferir si no estamos en portable
    pass

# =======================
# Resto del lanzador
# =======================
import logging

PROJECT_ROOT = Path(__file__).resolve().parent
# si el .lnk o la tarea no ponen WorkingDirectory, nos plantamos en el del proyecto
try:
    os.chdir(str(PROJECT_ROOT))
except Exception:
    pass

# inserta el directorio del proyecto al principio de sys.path
proj_str = str(PROJECT_ROOT)
if proj_str not in sys.path:
    sys.path.insert(0, proj_str)

# --- Inicializar logger muy pronto (ya con sys.path listo) ---
from app.logs import configure, get_logger, install_exception_hooks  # noqa: E402

# --- Helpers reutilizables de runtime ---
from utils.runtime import (  # noqa: E402
    parse_role,
    set_appusermodelid,
    set_process_title,
    maybe_elevate,
)

# --- AppUserModelID (icono barra de tareas) + título del proceso --------------
XH_ROLE = parse_role(sys.argv) or "panel"
set_appusermodelid("XiaoHack.Parental.Panel")
set_process_title(XH_ROLE)

# --- Config de logs del lanzador ----------------------------------------------
# Permite ajustar nivel vía variable de entorno XH_LOGLEVEL (opcional)
_log_level = os.getenv("XH_LOGLEVEL", "INFO").upper()
configure(level=_log_level)  # "INFO" por defecto
install_exception_hooks("launcher-crash")
log = get_logger("launcher")

# Log útil al arrancar (root)
try:
    logging.getLogger().info("XiaoHack process started (role=%s)", XH_ROLE)
except Exception:
    pass

# -----------------------------------------------------------------------------
# Ejecución principal
# -----------------------------------------------------------------------------
def main() -> None:
    # Flags de control:
    #   --require-admin : fuerza elevación al inicio (escenario mantenimiento/instalación)
    #   --no-elevate    : ignora cualquier intento de elevación (útil para debugging)
    #   --xh-role       : rol (panel/guardian/notifier/etc.) — no obligatorio aquí
    argv_lower = {a.lower() for a in sys.argv[1:]}
    require_admin = "--require-admin" in argv_lower
    no_elevate    = "--no-elevate" in argv_lower

    log.info("Iniciando lanzador XiaoHack Control Parental… (role=%s)", XH_ROLE)

    if require_admin and not no_elevate:
        maybe_elevate(require_admin=True, argv=sys.argv, logger=log)
        # Nota: maybe_elevate relanza el proceso si procede.
    else:
        log.info("Ejecución sin elevación inicial (se elevará SOLO cuando haga falta).")

    try:
        from xiao_gui.app import run
        log.info("Ejecutando aplicación principal (xiao_gui.app.run)")
        run()
    except Exception:
        log.error("Error durante la ejecución principal:\n%s", traceback.format_exc())
        raise

if __name__ == "__main__":
    main()
