# xiao_gui/services.py — gestión de servicios guardian y notifier
import os
import sys
import subprocess
import time
from pathlib import Path
import psutil # type: ignore
from logs import get_logger

log = get_logger("gui.services")

TASK_PATH = "\\XiaoHackParental\\"
TASK_BARE = "Guardian"

def _tn() -> str:
    """Nombre completo de la tarea para schtasks"""
    return f"{TASK_PATH.strip('\\\\')}\\{TASK_BARE}"

# ---------- utilidades generales ----------
def _root_dir() -> Path:
    """Ruta raíz del proyecto (sube dos niveles desde este archivo)."""
    return Path(__file__).resolve().parents[1]

def _pythonw_path() -> Path:
    """Devuelve pythonw.exe si existe, si no python.exe."""
    p = _root_dir() / "venv" / "Scripts" / "pythonw.exe"
    if p.exists():
        return p
    cand = Path(sys.executable).with_name("pythonw.exe")
    if cand.exists():
        return cand
    return Path(sys.executable)

def _notifier_script() -> Path:
    return _root_dir() / "notifier.py"

def _programdata_logs_path() -> Path:
    base = Path(os.getenv("ProgramData", r"C:\ProgramData")) / "XiaoHackParental" / "logs"
    base.mkdir(parents=True, exist_ok=True)
    return base / "control.log"

def _is_windows() -> bool:
    return os.name == "nt"


# ---------- helpers subprocess ----------
def _run_list(args: list[str], timeout: int = 12) -> tuple[int, str, str]:
    try:
        kw = dict(capture_output=True, text=True, timeout=timeout)
        if os.name == "nt":
            kw["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            kw["startupinfo"] = si
        cp = subprocess.run(args, **kw)
        log.debug("cmd rc=%d → %s", cp.returncode, args)
        return cp.returncode, cp.stdout or "", cp.stderr or ""
    except subprocess.TimeoutExpired as e:
        return 124, (e.stdout or ""), f"Timeout: {e}"
    except Exception as e:
        return 1, "", f"{type(e).__name__}: {e}"


# ---------- tarea programada (guardian) ----------
def query_task_state() -> str:
    """Lee el estado de la tarea programada \XiaoHackParental\Guardian."""
    if not _is_windows():
        return "No disponible (no Windows)"

    tn = _tn()
    rc, out, err = _run_list(["schtasks", "/Query", "/TN", tn, "/V", "/FO", "LIST"])
    if rc != 0:
        return "No instalada"

    state_text, last_text = "", ""
    for line in (out or "").splitlines():
        ls = line.strip()
        if ls.startswith(("Estado:", "Status:")):
            state_text = ls.split(":", 1)[1].strip()
        elif ls.startswith(("Último resultado:", "Ultimo resultado:", "Last Run Result:")):
            last_text = ls.split(":", 1)[1].strip()

    lt = last_text.upper().replace("0X", "0x")
    if "0x41301" in lt or state_text.lower() in ("en ejecución", "running"):
        return state_text or "En ejecución"
    if "0x41300" in lt or state_text.lower() in ("listo", "ready"):
        return state_text or "Listo"
    return state_text or "Instalada"


def start_service():
    """Crea y/o arranca la tarea Guardian en ProgramData."""
    if not _is_windows():
        return (1, "", "No disponible (no Windows)")

    base = Path(os.getenv("ProgramData", r"C:\ProgramData")) / "XiaoHackParental"
    run_bat = base / "run_guardian.bat"

    _run_list(["schtasks", "/Delete", "/TN", _tn(), "/F"])
    rc, out, err = _run_list([
        "schtasks", "/Create",
        "/TN", _tn(),
        "/TR", f"\"{run_bat}\"",
        "/SC", "ONSTART",
        "/RU", "SYSTEM",
        "/RL", "HIGHEST",
        "/F"
    ])
    if rc == 0:
        _run_list(["schtasks", "/Run", "/TN", _tn()])
    return rc, out, err

def stop_service():
    """Detiene la tarea Guardian en ejecución o mata procesos si fallase."""
    if not _is_windows():
        return (1, "", "No disponible (no Windows)")
    rc, out, err = _run_list(["schtasks", "/End", "/TN", _tn()])
    if rc == 0:
        time.sleep(0.6)
        return (0, "Tarea finalizada.", "")
    # fallback: matar guardian.py
    killed = 0
    for p in psutil.process_iter(attrs=["pid", "name", "cmdline"]):
        try:
            cmd = " ".join(p.info.get("cmdline") or []).lower()
            if "guardian.py" in cmd:
                p.terminate()
                killed += 1
        except Exception:
            pass
    return (0 if killed else rc, f"Terminados {killed} guardian(s).", err or "")


def open_task_scheduler():
    if not _is_windows():
        return
    log.info("Abriendo Programador de tareas de Windows...")
    for cmd in (["control.exe", "schedtasks"], ["taskschd.msc"]):
        try:
            subprocess.Popen(cmd, close_fds=True)
            return
        except Exception:
            continue

def restart_guardian():
    stop_service()
    time.sleep(0.3)
    return start_service()


# ---------- notifier (usuario actual) ----------
def _get_notifier_pids() -> list[int]:
    """Busca procesos notifier.py activos (usuario actual)."""
    pids = []
    npath = str(_notifier_script()).lower()
    for p in psutil.process_iter(attrs=["pid", "name", "cmdline"]):
        try:
            if p.pid == os.getpid():
                continue
            cmd = " ".join(p.info.get("cmdline") or []).lower()
            if "notifier.py" in cmd or npath in cmd:
                pids.append(p.pid)
        except Exception:
            pass
    return pids


def query_notifier_state() -> str:
    pids = _get_notifier_pids()
    state = f"Ejecutándose ({len(pids)})" if pids else "Detenido"
    log.debug("Estado notifier: %s", state)
    return state


def start_notifier():
    pyw = _pythonw_path()
    script = _notifier_script()
    try:
        creationflags = 0
        if pyw.name.lower().endswith("python.exe"):
            creationflags = 0x00000008  # DETACHED_PROCESS
        subprocess.Popen(
            [str(pyw), str(script)],
            cwd=str(_root_dir()),
            close_fds=True,
            creationflags=creationflags,
        )
        log.info("Notifier iniciado con %s", pyw.name)
        return (0, "OK", "")
    except Exception as e:
        log.error("Error al iniciar notifier: %s", e, exc_info=True)
        return (1, "", str(e))


def stop_notifier():
    pids = _get_notifier_pids()
    procs = []
    for pid in pids:
        try:
            pr = psutil.Process(pid)
            pr.terminate()
            procs.append(pr)
        except Exception:
            pass
    if procs:
        try:
            psutil.wait_procs(procs, timeout=1.5)
        except Exception:
            pass
    killed = len(procs)
    log.info("Notifier detenido (%d procesos).", killed)
    return (0, f"Terminados {killed} notifier(s).", "")


def restart_notifier():
    stop_notifier()
    time.sleep(0.3)
    return start_notifier()


def open_notifier_log():
    logp = _programdata_logs_path()
    if not logp.exists():
        try:
            logp.write_text("", encoding="utf-8")
        except Exception:
            pass
    try:
        if _is_windows():
            subprocess.Popen(["notepad.exe", str(logp)], close_fds=True)
        else:
            subprocess.Popen(["xdg-open", str(logp)], close_fds=True)
        log.info("Abriendo log del notifier: %s", logp)
        return (0, "OK", "")
    except Exception as e:
        log.error("Error abriendo log notifier: %s", e)
        return (1, "", str(e))
