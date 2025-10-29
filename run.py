# run.py — lanzador con elevación opcional (UAC) y logging centralizado
from __future__ import annotations
import sys
import logging
import traceback

# --- Inicializar logger muy pronto ---
from app.logs import configure, get_logger, install_exception_hooks

# --- Helpers reutilizables de runtime ---
from utils.runtime import (
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
_log_level = "INFO"
try:
    import os
    _log_level = os.getenv("XH_LOGLEVEL", _log_level).upper()
except Exception:
    pass

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
def main():
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
    else:
        log.info("Ejecución sin elevación inicial (se elevará SOLO cuando haga falta).")

    try:
        from xiao_gui.app import run
        log.info("Ejecutando aplicación principal (xiao_gui.app.run)")
        # Nota: cualquier operación que requiera admin (p. ej. hosts) debe usar
        # servicios privilegiados (Guardian SYSTEM) o helpers elevados específicos.
        run()
    except Exception:
        log.error("Error durante la ejecución principal:\n%s", traceback.format_exc())
        raise

if __name__ == "__main__":
    main()
