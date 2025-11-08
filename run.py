# ruff: noqa=E402
# flake8: noqa: E402
# pyright: reportNotTopLevelImport=false
# isort: skip_file

# run.py — lanzador con elevación opcional (UAC) y logging centralizado
from __future__ import annotations

# =======================
# Bootstrap Python portable
# =======================
import os
import sys
import traceback
from pathlib import Path

# Endurecimiento del entorno
os.environ.setdefault("PYTHONUTF8", "1")
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
os.environ.setdefault("PYTHONNOUSERSITE", "1")

# 1) Resolver rutas clave y fijar cwd al proyecto
try:
    PROJECT_ROOT = Path(__file__).resolve().parent
except Exception:
    PROJECT_ROOT = Path.cwd()
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

    for d in (PYDIR, DLLS):
        try:
            os.add_dll_directory(str(d))
        except Exception:
            pass

    def _prepend_env_path(p: str) -> None:
        cur = os.environ.get("PATH", "")
        parts = cur.split(";") if cur else []
        if p and p not in parts:
            os.environ["PATH"] = (p + ";" + cur) if cur else p

    def _prepend_syspath(p: Path) -> None:
        sp = str(p)
        if sp and sp not in sys.path:
            sys.path.insert(0, sp)

    for p in (str(PYDIR), str(DLLS)):
        _prepend_env_path(p)
    for p in (PYDIR, DLLS, LIB, SITE):
        _prepend_syspath(p)

    PYW32_SYS = SITE / "pywin32_system32"
    if PYW32_SYS.exists():
        _prepend_syspath(PYW32_SYS)
        _prepend_env_path(str(PYW32_SYS))

    os.environ.setdefault("TCL_LIBRARY", str(PYDIR / "tcl" / "tcl8.6"))
    os.environ.setdefault("TK_LIBRARY",  str(PYDIR / "tcl" / "tk8.6"))

    try:
        import site as _site
        _site.addsitedir(str(SITE))  # asegura escaneo de .pth y añade paths
    except Exception:
        pass

except Exception:
    pass  # no interferir si no es portable

# =======================
# Resto del lanzador
# =======================
import logging

proj_str = str(PROJECT_ROOT)
if proj_str not in sys.path:
    sys.path.insert(0, proj_str)

from app.logs import configure, get_logger, install_exception_hooks  # noqa: E402
from utils.runtime import (  # noqa: E402
    parse_role,
    set_appusermodelid,
    set_process_title,
    maybe_elevate,
)

XH_ROLE = parse_role(sys.argv) or "panel"
set_appusermodelid("XiaoHack.Parental.Panel")
set_process_title(XH_ROLE)

_log_level = os.getenv("XH_LOGLEVEL", "INFO").upper()
configure(level=_log_level)
install_exception_hooks("launcher-crash")
log = get_logger("launcher")

try:
    logging.getLogger().info("XiaoHack process started (role=%s)", XH_ROLE)
except Exception:
    pass


def main():
    argv_lower = {a.lower() for a in sys.argv[1:]}
    require_admin = "--require-admin" in argv_lower
    no_elevate    = "--no-elevate" in argv_lower

    log.info("Iniciando lanzador XiaoHack Control Parental… (role=%s)", XH_ROLE)

    if require_admin and not no_elevate:
        maybe_elevate(require_admin=True, argv=sys.argv, logger=log)
    else:
        log.info("Ejecución sin elevación inicial (se elevará SOLO cuando haga falta).")

    try:
        from xiao_gui.app import run  # noqa: E402
        log.info("Ejecutando aplicación principal (xiao_gui.app.run)")
        run()
    except Exception:
        log.error("Error durante la ejecución principal:\n%s", traceback.format_exc())
        raise


if __name__ == "__main__":
    main()
