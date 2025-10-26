# run.py — lanzador con elevación opcional (UAC) y logging centralizado
from __future__ import annotations
import sys
import ctypes
import traceback

# --- Inicializar logger muy pronto ---
from logs import configure, get_logger, install_exception_hooks

# --- AppUserModelID para icono en barra de tareas (Windows) ---
try:
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("XiaoHack.Parental.Panel")
except Exception:
    pass

# --- Identidad de proceso XiaoHack -------------------------------------------
XH_ROLE = None
try:
    if "--xh-role" in sys.argv:
        i = sys.argv.index("--xh-role")
        if i + 1 < len(sys.argv):
            XH_ROLE = sys.argv[i + 1]
except Exception:
    XH_ROLE = None

# Nombre “bonito” del proceso (si está disponible setproctitle)
try:
    import setproctitle  # type: ignore
    title = f"XiaoHack-{XH_ROLE}" if XH_ROLE else "XiaoHack"
    setproctitle.setproctitle(title)
except Exception:
    pass

# Log útil al arrancar (root)
try:
    import logging
    logging.getLogger().info("XiaoHack process started (role=%s)", XH_ROLE)
except Exception:
    pass

# --- Config de logs del lanzador ---
configure(level="INFO")  # cambia a "DEBUG" si necesitas más detalle
install_exception_hooks("launcher-crash")
log = get_logger("launcher")

# -----------------------------------------------------------------------------
# Elevación UAC (opcional)
# -----------------------------------------------------------------------------
def _is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def _relaunch_elevated(extra_args: list[str] | None = None):
    """
    Relanza el proceso con elevación UAC, añadiendo --elevated para evitar bucles.
    """
    extra_args = extra_args or []
    if "--elevated" not in extra_args:
        extra_args = extra_args + ["--elevated"]
    params = " ".join(f'"{a}"' for a in (sys.argv + extra_args))
    exe = sys.executable
    log.info("Requiere privilegios admin, relanzando con UAC…")
    log.debug("Exe: %s", exe)
    log.debug("Params: %s", params)
    try:
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        log.info("ShellExecuteW retornó: %s", ret)
    except Exception:
        log.error("Error al relanzar con elevación:\n%s", traceback.format_exc())
    sys.exit(0)

def _maybe_elevate(require_admin: bool):
    """
    Si require_admin=True y no somos admin, relanza con UAC.
    Evita bucles si ya venimos con --elevated.
    """
    if not require_admin:
        return
    if "--elevated" in sys.argv:
        log.info("Ejecutando ya en modo elevado (flag --elevated detectado).")
        return
    if _is_admin():
        log.info("Permisos de administrador confirmados.")
        return
    _relaunch_elevated([])

# -----------------------------------------------------------------------------
# Ejecución principal
# -----------------------------------------------------------------------------
def main():
    # Flags de control:
    #   --require-admin : fuerza elevación al inicio (escenario mantenimiento/instalación)
    #   --no-elevate    : ignora cualquier intento de elevación (útil para debugging)
    #   --xh-role       : rol (panel/guardian/notifier/etc.) — no obligatorio aquí
    require_admin = "--require-admin" in {a.lower() for a in sys.argv[1:]}
    no_elevate    = "--no-elevate" in {a.lower() for a in sys.argv[1:]}

    log.info("Iniciando lanzador XiaoHack Control Parental… (role=%s)", XH_ROLE or "panel")

    if require_admin and not no_elevate:
        _maybe_elevate(require_admin=True)
    else:
        log.info("Ejecución sin elevación inicial (se elevará SOLO cuando haga falta).")

    try:
        from xiao_gui.app import run
        log.info("Ejecutando aplicación principal (xiao_gui.app.run)")
        # Nota: cualquier operación que requiera admin (p. ej. hosts) debe usar
        # webfilter.ensure_hosts_rules_or_elevate / remove_parental_block_or_elevate
        run()
    except Exception:
        log.error("Error durante la ejecución principal:\n%s", traceback.format_exc())
        raise

if __name__ == "__main__":
    main()
