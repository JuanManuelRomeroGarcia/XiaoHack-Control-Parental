# run.py — lanzador con auto-elevación UAC y logging centralizado
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
    from setproctitle import setproctitle
    title = f"XiaoHack-{XH_ROLE}" if XH_ROLE else "XiaoHack"
    setproctitle(title)
except Exception:
    pass

# Log útil al arrancar
try:
    import logging
    logging.getLogger().info("XiaoHack process started (role=%s)", XH_ROLE)
except Exception:
    pass


configure(level="debug")  # Se puede cambiar a DEBUG para ver más detalle
install_exception_hooks()
log = get_logger("launcher")

def _ensure_admin_or_relaunch():
    """
    Comprueba si la app tiene privilegios de administrador.
    Si no, relanza con elevación (UAC). Evita relanzar en bucle usando el flag --elevated.
    """
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except Exception as e:
        log.warning("No se pudo com permisos de administrador: %s", e)
        is_admin = False

    # Evitar bucle infinito
    if "--elevated" in sys.argv:
        log.info("Ejecutando ya en modo elevado (flag detectado).")
        return

    if not is_admin:
        params = " ".join(f'"{a}"' for a in sys.argv + ["--elevated"])
        exe = sys.executable
        log.info("Requiere privilegios admin, relanzando con UAC...")
        log.debug("Ejecutable: %s", exe)
        log.debug("Parámetros: %s", params)
        try:
            ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
            log.info("ShellExecuteW devuelto: %s", ret)
        except Exception:
            log.error("Error al relanzar con elevación:\n%s", traceback.format_exc())
        sys.exit(0)
    else:
        log.info("Permisos de administrador confirmados.")

# --- Ejecución principal ---
def main():
    log.info("Iniciando lanzador XiaoHack Control Parental...")
    _ensure_admin_or_relaunch()

    try:
        from xiao_gui.app import run
        log.info("Ejecutando aplicación principal (xiao_gui.app.run)")
        run()
    except Exception:
        log.error("Error durante la ejecución principal:\n%s", traceback.format_exc())
        raise

if __name__ == "__main__":
    main()
