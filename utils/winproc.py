# utils/winproc.py — XiaoHack Parental
# Ejecución de comandos sin ventana ni shell, con trazas y control de errores.

import subprocess
import os
import shlex
import time
from typing import List, Tuple, Union
from logs import get_logger

log = get_logger("winproc")

# ---------------------------------------------------------------------------
# Constantes Windows (ocultar consola)
# ---------------------------------------------------------------------------
CREATE_NO_WINDOW = 0x08000000
STARTF_USESHOWWINDOW = 0x00000001
SW_HIDE = 0



# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _to_argv(args: Union[str, List[str]]) -> List[str]:
    """Convierte cadena a lista segura de argumentos (sin shell)."""
    if isinstance(args, str):
        return shlex.split(args)
    return list(args)

# ---------------------------------------------------------------------------
# Ejecución sin consola
# ---------------------------------------------------------------------------
def run_quiet(args: Union[str, List[str]], *,
              timeout: float = 10.0,
              text: bool = True) -> Tuple[int, str, str]:
    """
    Ejecuta un comando de forma silenciosa (sin ventana CMD).
    Devuelve (rc, stdout, stderr).

    Ejemplo:
        rc, out, err = run_quiet(["netsh", "interface", "show", "dns"])
    """
    argv = _to_argv(args)
    start = time.perf_counter()

    si = None
    creationflags = 0
    if os.name == "nt":
        si = subprocess.STARTUPINFO()
        si.dwFlags |= STARTF_USESHOWWINDOW
        si.wShowWindow = SW_HIDE
        creationflags = CREATE_NO_WINDOW

    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=text,
            timeout=timeout,
            shell=False,
            startupinfo=si,
            creationflags=creationflags
        )
        dt = (time.perf_counter() - start) * 1000
        log.debug("CMD OK rc=%d (%.1f ms) → %s", proc.returncode, dt, argv)
        return proc.returncode, (proc.stdout or "").strip(), (proc.stderr or "").strip()

    except subprocess.TimeoutExpired as e:
        dt = (time.perf_counter() - start) * 1000
        log.warning("CMD TIMEOUT (%.1f ms): %s", dt, argv)
        return 124, "", f"timeout: {e}"
    except Exception as e:
        dt = (time.perf_counter() - start) * 1000
        log.error("CMD ERROR (%.1f ms) %s: %s", dt, argv, e, exc_info=True)
        return 1, "", f"error: {e}"
    
# =====================================================================
# PowerShell helpers (sin ventanas)
# =====================================================================

def _ps(cmd: str) -> tuple[int, str, str]:
    """
    Ejecuta un comando PowerShell sin abrir ventana.
    Devuelve (rc, stdout, stderr).
    """
    try:
        rc, out, err = run_quiet(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd])
        log.debug("PS cmd rc=%s len_out=%d len_err=%d", rc, len(out or ""), len(err or ""))
        if rc != 0:
            log.warning("PowerShell error rc=%d: %s", rc, (err or out or "").strip())
        return rc, out, err
    except Exception as e:
        log.error("Error ejecutando PowerShell: %s", e, exc_info=True)
        return 1, "", str(e)


# ---------------------------------------------------------------------------
# Ejecutar en segundo plano (opcional)
# ---------------------------------------------------------------------------
def run_detached(args: Union[str, List[str]]) -> bool:
    """
    Ejecuta un proceso completamente separado (sin esperar a que termine).
    Devuelve True si el proceso se lanzó correctamente.
    """
    argv = _to_argv(args)

    si = None
    creationflags = 0
    if os.name == "nt":
        si = subprocess.STARTUPINFO()
        si.dwFlags |= STARTF_USESHOWWINDOW
        si.wShowWindow = SW_HIDE
        creationflags = CREATE_NO_WINDOW

    try:
        subprocess.Popen(
            argv,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            shell=False,
            startupinfo=si,
            creationflags=creationflags,
        )
        log.debug("CMD DETACHED lanzado → %s", argv)
        return True
    except Exception as e:
        log.error("Error lanzando proceso detached: %s", e, exc_info=True)
        return False
    
