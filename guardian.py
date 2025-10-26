# guardian.py — XiaoHack Control Parental (Windows)
# Bloqueo por nombre, ruta exacta, carpeta; argumentos; ficheros abiertos;
# auto-protección opcional; detección instantánea por WMI; logs centralizados; heartbeat;
# SINGLE-INSTANCE para evitar múltiples procesos.

import datetime
import os
import time
import sqlite3
import traceback
import threading
import queue
from pathlib import Path
import urllib
from urllib.parse import urlparse
from urllib.request import url2pathname

import psutil  # type: ignore

from notifier import WM_CLOSE
from webfilter import ensure_hosts_rules, remove_parental_block
from logger import AuditLogger
from logs import get_logger, install_exception_hooks
# ⚠️ Usamos ProgramData (rutas compartidas) desde storage:
from storage import (
    load_config, load_state, now_epoch,
    DB_PATH, LOGS_DIR, save_state
)

from scheduler import check_playtime_alerts, remaining_play_seconds, is_within_allowed_hours  # ← nuevo
# == Opcionales (pywin32). Si faltan, seguimos en modo polling.
try:
    import pythoncom  # type: ignore
    import win32com.client  # type: ignore  # WMI
    import win32gui  # type: ignore
    import win32process  # type: ignore
except Exception:
    pythoncom = win32com = win32gui = win32process = None

# --- Identidad de proceso XiaoHack -------------------------------------------
import sys
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

# Log útil al arrancar
try:
    import logging
    logging.getLogger().info("XiaoHack process started (role=%s)", XH_ROLE)
except Exception:
    pass


# =============================================================================
# Config básica y logger
# =============================================================================
BASE_DIR = Path(__file__).resolve().parent
PROTECT_SELF = False  # pon True si quieres blindar la carpeta de instalación

log = get_logger("guardian")
install_exception_hooks("guardian-crash")

# =============================================================================
# Normalización y utilidades
# =============================================================================
def _norm_name(s: str) -> str:
    return (s or "").strip().lower()

def _normpath(p: str) -> str:
    try:
        return os.path.normcase(os.path.realpath(os.path.abspath(p or "")))
    except Exception:
        return os.path.normcase(os.path.abspath(p or ""))

def _dirtrail(p: str) -> str:
    p = _normpath(p).rstrip("\\/")
    return p + os.sep

def _looks_like_path(s: str) -> str | None:
    if not s:
        return None
    s = s.strip().strip('"').strip("'")
    sl = s.lower()
    if sl.startswith("file://"):
        try:
            u = urlparse(s)
            if u.scheme == "file":
                local = url2pathname(u.path)
                if local:
                    return local
        except Exception:
            pass
    if s.startswith("\\\\?\\") or s.startswith("\\\\"):
        return s
    if ":" in s and ("\\" in s or "/" in s):
        return s
    return None

# =============================================================================
# DB mínima de eventos (para notifier)
# =============================================================================
def _log_event(kind: str, value: str, meta: str = ""):
    """Registro auxiliar para notifier (guardian.db)."""
    try:
        con = sqlite3.connect(str(DB_PATH))
        cur = con.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY, ts INTEGER, type TEXT, value TEXT, meta TEXT
        )""")
        cur.execute("INSERT INTO events(ts,type,value,meta) VALUES(?,?,?,?)",
                    (int(time.time()), kind, value, meta))
        con.commit()
        con.close()
    except Exception as e:
        log.warning("Error escribiendo evento notifier: %s", e)

# =============================================================================
# Notificaciones de tiempo de juego (avisos 10/5/1 min + cuenta atrás)
# =============================================================================
_last_allowed_flag = None
_last_play_rem_sent = {"m10": False, "m5": False, "m1": False}  # reservado
def _emit_notify(title: str, body: str = ""):
    # Usamos la misma tabla de eventos para notifier: type="notify"
    _log_event("notify", title, body)

def _playtime_tick(cfg: dict, st: dict, now_sec: int, now_dt):
    """
    - Emite avisos de 10/5/1 min y mensaje de 'comienza cuenta atrás'.
    - Actualiza state['play_countdown'] (0..60) y persiste si cambió.
    - Emite 'inicio de horario' y 'fin de horario' al cambiar el permiso por franjas.
    """
    global _last_allowed_flag

    # 1) Detectar cambio de permitido por horario (independiente de sesión manual)
    allowed_now = is_within_allowed_hours(cfg, now_dt)
    if _last_allowed_flag is None:
        _last_allowed_flag = allowed_now
    else:
        if allowed_now and not _last_allowed_flag:
            _emit_notify("Horario activo", "Ya puedes jugar (franja permitida).")
        elif (not allowed_now) and _last_allowed_flag:
            _emit_notify("Horario finalizado", "Se acabó la franja permitida.")
        _last_allowed_flag = allowed_now

    # 2) Avisos y cuenta atrás (manual o franja)
    msgs, countdown = check_playtime_alerts(st, now_dt, cfg)
    persisted = False
    if msgs:
        for m in msgs:
            _emit_notify("Tiempo de juego", m)
        persisted = True

    # 3) Persistir countdown si cambió
    if st.get("play_countdown", 0) != countdown:
        persisted = True

    if persisted:
        try:
            save_state(st)
        except Exception:
            pass

    # 4) Notificación de fin de tiempo (cuando remaining <= 0 y veníamos con modo activo)
    rem, mode = remaining_play_seconds(st, now_dt, cfg)
    if rem <= 0 and st.get("play_alert_mode") in ("manual", "schedule"):
        _emit_notify("Tiempo terminado", "El tiempo de juego ha finalizado.")
        try:
            save_state(st)
        except Exception:
            pass

# =============================================================================
# Gestión de procesos
# =============================================================================
def _kill_tree(proc: psutil.Process):
    try:
        for c in proc.children(recursive=True):
            try:
                c.terminate()
            except Exception:
                pass
        proc.terminate()
        psutil.wait_procs([proc], timeout=1.0)
        if proc.is_running():
            try:
                proc.kill()
            except Exception:
                pass
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

# =============================================================================
# Notepad: detección por ventana
# =============================================================================
def _notepad_has_blocked_window(pid: int, blocked_dirs_plus_self: list[str]) -> bool:
    if not (win32gui and win32process):
        return False
    hit = False
    def _enum(hwnd, _):
        nonlocal hit
        try:
            _, p = win32process.GetWindowThreadProcessId(hwnd)
            if p != pid:
                return True
            title = (win32gui.GetWindowText(hwnd) or "").lower()
            for d in blocked_dirs_plus_self:
                folder_name = os.path.basename(d.rstrip("\\/")).lower()
                if folder_name and folder_name in title:
                    hit = True
                    return False
        except Exception:
            pass
        return True
    try:
        win32gui.EnumWindows(_enum, None)
    except Exception:
        return False
    return hit

# =============================================================================
# Matching
# =============================================================================
CORE_HOSTS = {"taskeng.exe", "cmd.exe", "conhost.exe", "mmc.exe", "svchost.exe"}
EDITOR_LIKE = {
    "notepad.exe", "notepad++.exe", "code.exe", "code-helper.exe",
    "wordpad.exe", "winword.exe", "excel.exe", "powerpnt.exe",
    "python.exe", "pythonw.exe",
    "chrome.exe", "msedge.exe", "firefox.exe", "opera.exe",
    "brave.exe", "vivaldi.exe", "iexplore.exe", "msedgewebview2.exe"
}

def _match_blocked(proc: psutil.Process, cfg, st,
                   blocked_names, blocked_execs, blocked_dirs, self_dirs,
                   ancestor_pids: set[int]) -> str | None:
    try:
        exe_path = _normpath(proc.exe() or "")
        cwd_path = _normpath(proc.cwd() or "")
        base     = _norm_name(os.path.basename(exe_path))
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return None
    try:
        if proc.pid == os.getpid() or proc.pid in ancestor_pids:
            return None
    except Exception:
        pass
    try:
        pname_low = (proc.info.get("name") or proc.name() or "").lower()
    except Exception:
        pname_low = ""

    # Whitelist por juego
    play_until = int(st.get("play_until", 0) or 0)
    allowed_by_manual = play_until > now_epoch()
    allowed_by_schedule = is_within_allowed_hours(cfg, datetime.datetime.now())
    if allowed_by_manual or allowed_by_schedule:
        wl = set(_norm_name(x) for x in (st.get("play_whitelist") or cfg.get("game_whitelist", [])))
        if base in wl:
            return None

    if base in blocked_names:
        return "name"
    if exe_path in blocked_execs:
        return "exact"
    for d in blocked_dirs:
        if exe_path.startswith(d) or cwd_path.startswith(d):
            return f"dir:{d}"
    for d in self_dirs:
        if exe_path.startswith(d) or cwd_path.startswith(d):
            return f"self:{d}"

    try:
        args = proc.cmdline()
    except Exception:
        args = []
    for a in args[1:]:
        p_like = _looks_like_path(a)
        if not p_like:
            continue
        ap = _normpath(p_like)
        for d in blocked_dirs + self_dirs:
            if ap.startswith(d):
                if pname_low in CORE_HOSTS:
                    return None
                return f"arg:{d}"

    if base in EDITOR_LIKE:
        try:
            for f in proc.open_files():
                fp = _normpath(f.path)
                for d in blocked_dirs + self_dirs:
                    if fp.startswith(d):
                        if pname_low in CORE_HOSTS:
                            return None
                        return f"openfile:{d}"
        except Exception:
            pass

    if base == "notepad.exe":
        if _notepad_has_blocked_window(proc.pid, blocked_dirs + self_dirs):
            if pname_low not in CORE_HOSTS:
                return "wnd:notepad"
    return None

# =============================================================================
# WMI watcher: detección instantánea
# =============================================================================
def _wmi_watch_loop(q: "queue.Queue[tuple[int,str]]", stop_ev: threading.Event):
    if not (pythoncom and win32com):
        return
    while not stop_ev.is_set():
        try:
            pythoncom.CoInitialize()
            locator = win32com.client.Dispatch("WbemScripting.SWbemLocator")
            svc = locator.ConnectServer(".", "root\\cimv2")
            watcher = svc.ExecNotificationQuery("SELECT * FROM Win32_ProcessStartTrace")
            log.info("WMI watcher activo")
            while not stop_ev.is_set():
                try:
                    evt = watcher.NextEvent(2000)
                    if evt:
                        q.put((int(evt.ProcessID), (evt.ProcessName or "").lower()))
                except pythoncom.com_error:
                    time.sleep(1)
                except Exception:
                    time.sleep(0.2)
        except Exception as e:
            log.warning("WMI watcher reinicio por error: %s", e)
            time.sleep(2)
        finally:
            try:
                pythoncom.CoUninitialize()
            except Exception:
                pass

# =============================================================================
# Explorer Watch
# =============================================================================
def _explorer_watch_loop(get_blocked_dirs_callable, stop_ev: threading.Event):
    if not (win32com and win32gui):
        return
    try:
        pythoncom.CoInitialize()
    except Exception:
        pass
    shell = None
    last_dirs: tuple[str, ...] = ()
    last_check = 0.0
    backoff = 0.3

    while not stop_ev.is_set():
        try:
            now = time.time()
            if now - last_check > 1:
                blocked_dirs = get_blocked_dirs_callable()
                last_dirs = tuple(blocked_dirs)
                last_check = now
            else:
                blocked_dirs = list(last_dirs)
            if not blocked_dirs:
                time.sleep(backoff)
                continue
            if shell is None:
                try:
                    shell = win32com.client.Dispatch("Shell.Application")
                except Exception as e:
                    log.warning("ExplorerWatch fallo inicial: %s", e)
                    time.sleep(backoff)
                    continue
            try:
                wins = shell.Windows()
            except Exception:
                shell = None
                time.sleep(backoff)
                continue
            for w in wins:
                try:
                    url = (w.LocationURL or "")
                    if not url.lower().startswith("file:///"):
                        continue
                    p = _normpath(urllib.request.url2pathname(urllib.parse.urlparse(url).path))
                    for d in blocked_dirs:
                        if p.startswith(d):
                            hwnd = int(w.HWND)
                            log.info("Cerrar Explorer hwnd=%s path=%s", hwnd, p)
                            try:
                                win32gui.PostMessage(hwnd, WM_CLOSE, 0, 0)
                            except Exception:
                                try:
                                    w.Quit()
                                except Exception:
                                    pass
                            _log_event("block", "explorer.exe", f"dir:{d}")
                            break
                except Exception:
                    continue
        except Exception as e:
            log.error("ExplorerWatch loop error: %s", e)
            shell = None
        time.sleep(backoff)
    try:
        pythoncom.CoUninitialize()
    except Exception:
        pass

# =============================================================================
# SINGLE-INSTANCE
# =============================================================================
LOCK_PATH = LOGS_DIR.parent / "guardian.lock"
def _acquire_singleton() -> bool:
    try:
        if LOCK_PATH.exists():
            try:
                old = int(LOCK_PATH.read_text(encoding="utf-8").strip() or "0")
                if old and not psutil.pid_exists(old):
                    LOCK_PATH.unlink(missing_ok=True)
            except Exception:
                pass
        fd = os.open(str(LOCK_PATH), os.O_CREAT | os.O_EXCL | os.O_RDWR)
        try:
            os.write(fd, str(os.getpid()).encode("ascii", "ignore"))
        finally:
            try:
                os.close(fd)
            except Exception:
                pass
        return True
    except FileExistsError:
        return False

# =============================================================================
# Main
# =============================================================================
def main():
    if not _acquire_singleton():
        log.warning("Otro guardian ya está ejecutándose — salgo")
        return

    log.info("Guardian START pid=%s", os.getpid())
    try:
        psutil.Process(os.getpid()).nice(psutil.HIGH_PRIORITY_CLASS)  # type: ignore[attr-defined]
    except Exception:
        pass

    cfg = load_config()
    st  = load_state()
    audit = AuditLogger()

    try:
        me = psutil.Process(os.getpid())
        ancestor_pids = {p.pid for p in me.parents()}
    except Exception:
        ancestor_pids = set()

    # aplicar reglas sólo si el usuario lo ha aprobado (state.applied=True)
    _applied_last = bool(st.get("applied", False))
    if _applied_last:
        try:
            # aplicar con cfg efectiva (sin dominios si domains_enabled=False)
            cfg_eff = dict(cfg)
            if not cfg_eff.get("domains_enabled", True):
                cfg_eff["blocked_domains"] = []
            ensure_hosts_rules(cfg_eff)
            log.info("Reglas aplicadas (state.applied=True).")
        except PermissionError:
            log.warning("Sin permisos para editar hosts (ejecuta como Administrador para aplicar SafeSearch)")
    else:
        log.info("Reglas NO aplicadas en arranque (state.applied=False) — esperando activación desde la app.")

    blocked_names = set(_norm_name(x) for x in cfg.get("blocked_apps", []) if x)
    blocked_execs = set(_normpath(x) for x in cfg.get("blocked_executables", []) if x)
    blocked_dirs  = [_dirtrail(x) for x in (_normpath(p) for p in cfg.get("blocked_paths", []) if p)]
    self_dirs: list[str] = [_dirtrail(str(BASE_DIR))] if PROTECT_SELF else []

    log.info("cfg names=%s", ",".join(sorted(blocked_names)))
    log.info("cfg execs=%s", ",".join(sorted(blocked_execs)))
    log.info("cfg dirs=%s", ",".join(blocked_dirs + self_dirs))

    def _get_blocked_dirs_snapshot():
        return blocked_dirs + self_dirs

    exp_stop_ev = threading.Event()
    threading.Thread(target=_explorer_watch_loop,
                     args=(_get_blocked_dirs_snapshot, exp_stop_ev),
                     name="ExplorerWatch", daemon=True).start()

    q: "queue.Queue[tuple[int,str]]" = queue.Queue()
    stop_ev = threading.Event()
    threading.Thread(target=_wmi_watch_loop,
                     args=(q, stop_ev),
                     name="WMIWatch", daemon=True).start()

    last_reload = 0
    log.info("Servicio XiaoHack Parental iniciado correctamente.")
    recently_blocked: dict[int, float] = {}

    _last_play_tick = 0      # marca en segundos
    _last_hb_sec = -1        # último segundo en que se emitió heartbeat (múltiplo de 30)
    _last_tel_sec = -1       # último segundo de telemetría (múltiplo de 5)

    while True:
        now = time.time()
        now_i = int(now)

        # --- TICK de tiempo de juego (cada 1 s) ---
        try:
            if now_i != _last_play_tick:
                _last_play_tick = now_i
                # recarga rápida de cfg/state reciente (snapshot)
                cfg = load_config()
                st  = load_state()
                _playtime_tick(cfg, st, _last_play_tick, datetime.datetime.fromtimestamp(_last_play_tick))
        except Exception as e:
            log.warning("playtime_tick error: %s", e)

        # 1) Procesos nuevos vía WMI
        drained = 0
        while drained < 50:
            try:
                pid, _nm = q.get_nowait()
            except queue.Empty:
                break
            drained += 1
            try:
                p = psutil.Process(pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            for _ in range(3):
                reason = _match_blocked(p, cfg, st, blocked_names, blocked_execs, blocked_dirs, self_dirs, ancestor_pids)
                if reason:
                    if recently_blocked.get(pid, 0) + 2.0 > now:
                        break
                    pname = (p.info.get("name") if hasattr(p, "info") else None) or p.name() or "?"
                    log.warning("FAST-BLOCK %s reason=%s", pname, reason)
                    audit.log_block(pname, reason)
                    _log_event("block", pname, reason)
                    _kill_tree(p)
                    recently_blocked[pid] = now
                    break
                time.sleep(0.03)

        # 2) Escaneo de respaldo
        if now_i % 2 == 0:
            for p in psutil.process_iter(attrs=["pid", "name"]):
                try:
                    pid = p.info.get("pid")
                    if pid in recently_blocked and recently_blocked[pid] + 2.0 > now:
                        continue
                    reason = _match_blocked(p, cfg, st, blocked_names, blocked_execs, blocked_dirs, self_dirs, ancestor_pids)
                    if reason:
                        pname = p.info.get("name") or "?"
                        log.warning("BLOCK %s reason=%s", pname, reason)
                        audit.log_block(pname, reason)
                        _log_event("block", pname, reason)
                        _kill_tree(p)
                        recently_blocked[pid] = now
                except Exception:
                    continue

        # 3) Telemetría opcional (throttle 1 vez cada 5 s)
        if cfg.get("log_process_activity", True) and (now_i % 5 == 0) and (_last_tel_sec != now_i):
            _last_tel_sec = now_i
            for p in psutil.process_iter(attrs=["name"]):
                try:
                    audit.log_seen(p.info["name"])
                except Exception:
                    pass

        # 4) Recarga config/estado
        if now - last_reload > 10:
            cfg = load_config()
            st = load_state()
            blocked_names = set(_norm_name(x) for x in cfg.get("blocked_apps", []) if x)
            blocked_execs = set(_normpath(x) for x in cfg.get("blocked_executables", []) if x)
            blocked_dirs  = [_dirtrail(x) for x in (_normpath(p) for p in cfg.get("blocked_paths", []) if p)]
            last_reload = now
            log.debug("reload cfg: names=%s", ",".join(sorted(blocked_names)))
            log.debug("reload cfg: execs=%s", ",".join(sorted(blocked_execs)))
            log.debug("reload cfg: dirs=%s", ",".join(blocked_dirs + self_dirs))

        # reaccionar a cambios de applied
        try:
            new_applied = bool(st.get("applied", False))
            if new_applied != _applied_last:
                if new_applied:
                    # aplicar con cfg efectiva (sin dominios si domains_enabled=False)
                    cfg_eff = dict(cfg)
                    if not cfg_eff.get("domains_enabled", True):
                        cfg_eff["blocked_domains"] = []
                    ensure_hosts_rules(cfg_eff)
                    log.info("Reglas aplicadas tras activación desde la app (state.applied=True).")
                else:
                    # limpiar bloque parental del hosts si estaba presente
                    try:
                        removed = remove_parental_block()
                        log.info("Bloque parental %s por applied=False.",
                                 "eliminado" if removed else "no presente")
                    except PermissionError:
                        log.warning("Sin permisos para limpiar hosts (applied=False).")
                _applied_last = new_applied
        except PermissionError:
            log.warning("Sin permisos para editar hosts (ejecuta como Administrador para aplicar/limpiar)")
        except Exception as e:
            log.warning("Error aplicando/limpiando reglas tras cambio de applied: %s", e)

        # Heartbeat cada ~30 s (una sola vez por segundo múltiplo de 30)
        if (now_i % 30 == 0) and (_last_hb_sec != now_i):
            _last_hb_sec = now_i
            log.debug("heartbeat")

        time.sleep(0.05)

# =============================================================================
if __name__ == "__main__":
    try:
        main()
    except Exception:
        log.error("FATAL:\n%s", traceback.format_exc())
        raise
