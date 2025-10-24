# notifier.py — XiaoHack (usuario)
# Integra logging centralizado y mejora la trazabilidad de notificaciones, bloqueos y Explorer.
# No altera la lógica original.

import os
import sys
import time
import json
import threading
import sqlite3
import html
from pathlib import Path
from logs import get_logger, install_exception_hooks

log = get_logger("notifier")
install_exception_hooks("notifier-crash")

BASE = Path(__file__).resolve().parent
DB   = BASE / "guardian.db"

APPDATA = Path(os.getenv("APPDATA", str(BASE)))
STATE_DIR = APPDATA / "XiaoHackParental"
STATE_DIR.mkdir(parents=True, exist_ok=True)
STATE_FILE = STATE_DIR / "notifier_state.json"

PROGRAMDATA_DIR = Path(os.getenv("PROGRAMDATA", r"C:\ProgramData")) / "XiaoHackParental"
CONFIG_PATH_PD  = PROGRAMDATA_DIR / "config.json"

try:
    from storage import load_config
except Exception as e:
    load_config = None
    log.warning("No se pudo importar storage.py: %s", e)

APP_ID       = "XiaoHack.Parental"
APP_DISPLAY  = "XiaoHack Control Parental"

# --- librerías opcionales ---
WINRT_OK = WINOTIFY_OK = False
TOASTER = None
try:
    from winsdk.windows.ui.notifications import ToastNotificationManager, ToastNotification
    from winsdk.windows.data.xml.dom import XmlDocument
    WINRT_OK = True
except Exception:
    pass
try:
    from winotify import Notification as WNotify, audio as wnaudio
    WINOTIFY_OK = True
except Exception:
    pass
if not WINOTIFY_OK:
    try:
        from win10toast import ToastNotifier
        TOASTER = ToastNotifier()
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


# --------------------------------------------------------------------
# Estado persistente
# --------------------------------------------------------------------
def load_state():
    try:
        if STATE_FILE.exists():
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception as e:
        log.warning("Error al leer estado: %s", e)
    return {"last_id": 0}

def save_state(st):
    try:
        tmp = STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(st, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(STATE_FILE)
    except Exception as e:
        log.error("Error al guardar estado: %s", e)

# --------------------------------------------------------------------
# Registro AppID y shortcut
# --------------------------------------------------------------------
def register_appid_in_registry(app_id: str, display_name: str, icon_path: str | None):
    try:
        import winreg
        key_path = fr"Software\Classes\AppUserModelId\{app_id}"
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as k:
            winreg.SetValueEx(k, "DisplayName", 0, winreg.REG_SZ, display_name)
            if icon_path:
                winreg.SetValueEx(k, "IconUri", 0, winreg.REG_SZ, icon_path)
        log.debug("AppID registrado en HKCU: %s", app_id)
    except Exception as e:
        log.warning("Fallo al registrar AppID: %s", e)

def ensure_appid_shortcut(app_id: str, icon_path: str | None = None):
    """Crea/actualiza un .lnk en el Menú Inicio con AUMID (branding)."""
    try:
        import pythoncom
        from win32com.shell import shell # type: ignore
        from win32com.propsys import propsys, pscon # type: ignore

        pythoncom.CoInitialize()
        start_menu = APPDATA / "Microsoft" / "Windows" / "Start Menu" / "Programs"
        start_menu.mkdir(parents=True, exist_ok=True)
        lnk_path = str((start_menu / "XiaoHack Parental.lnk").resolve())

        pyw = (BASE / "venv" / "Scripts" / "pythonw.exe")
        if not pyw.exists():
            pyw = Path(sys.executable).with_name("pythonw.exe")
        args = f"\"{(BASE / 'notifier.py').resolve()}\""
        workdir = str(BASE)

        link = pythoncom.CoCreateInstance(shell.CLSID_ShellLink, None,
                                          pythoncom.CLSCTX_INPROC_SERVER,
                                          shell.IID_IShellLink)
        link.SetPath(str(pyw))
        link.SetArguments(args)
        link.SetWorkingDirectory(workdir)
        if icon_path:
            try: 
                link.SetIconLocation(icon_path, 0)
            except Exception:
                pass

        propstore = link.QueryInterface(propsys.IID_IPropertyStore)
        propstore.SetValue(pscon.PKEY_AppUserModel_ID,
                           propsys.PROPVARIANTType(app_id, pythoncom.VT_LPWSTR))
        propstore.Commit()

        persist = link.QueryInterface(pythoncom.IID_IPersistFile)
        persist.Save(lnk_path, 0)
        log.debug("Shortcut actualizado: %s", lnk_path)
    except Exception as e:
        log.warning("Fallo al crear shortcut: %s", e)
    finally:
        try:
            import pythoncom
            pythoncom.CoUninitialize()
        except Exception:
            pass

# --------------------------------------------------------------------
# Toasts (WinRT / winotify / win10toast)
# --------------------------------------------------------------------
def _show_winrt_toast(title: str, msg: str, icon_path: str | None = None):
    safe_title, safe_msg = html.escape(title or ""), html.escape(msg or "")
    img_xml = f"<image placement='appLogoOverride' src='{html.escape(icon_path)}'/>" if icon_path else ""
    xml = f"<toast><visual><binding template='ToastGeneric'><text>{safe_title}</text><text>{safe_msg}</text>{img_xml}</binding></visual></toast>"
    xdoc = XmlDocument()
    xdoc.load_xml(xml)
    ToastNotificationManager.create_toast_notifier(APP_ID).show(ToastNotification(xdoc))

def notify(title: str, msg: str, duration=5):
    icon = None
    for cand in ("app_icon.ico", "app_icon.png"):
        p = BASE / "assets" / cand
        if p.exists():
            icon = str(p)
            break
    log.info("Notificación: %s | %s", title, msg[:80])
    # WinRT
    if WINRT_OK:
        try:
            _show_winrt_toast(title, msg, icon)
            return True
        except Exception as e:
            log.warning("WinRT toast error: %s", e)
    # winotify
    if WINOTIFY_OK:
        try:
            n = WNotify(app_id=APP_ID, title=title, msg=msg, icon=icon)
            try: 
                n.set_audio(wnaudio.Reminder, loop=False)
            except Exception:
                pass
            n.show()
            return True
        except Exception as e:
            log.warning("winotify error: %s", e)
    # win10toast
    if TOASTER:
        try:
            TOASTER.show_toast(title, msg, duration=duration, threaded=True)
            return True
        except Exception as e:
            log.warning("win10toast error: %s", e)
    log.error("Ningún método de notificación disponible.")
    return False

_TOAST_SEEN: dict[str, float] = {}
def notify_once(key: str, title: str, msg: str, min_interval: float = 5.0):
    now = time.time()
    if now - _TOAST_SEEN.get(key, 0) < min_interval:
        return False
    _TOAST_SEEN[key] = now
    return notify(title, msg, duration=5)

# --------------------------------------------------------------------
# SQLite y eventos
# --------------------------------------------------------------------
def query_new_blocks(since_id: int):
    try:
        con = sqlite3.connect(str(DB))
        cur = con.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY, ts INTEGER, type TEXT, value TEXT, meta TEXT
        )""")
        cur.execute("SELECT id, ts, value, meta FROM events WHERE type='block' AND id > ? ORDER BY id ASC", (since_id,))
        rows = cur.fetchall()
        con.close()
        return rows
    except Exception as e:
        log.error("Error SQLite: %s", e)
        return []

# --------------------------------------------------------------------
# Monitor de Explorer
# --------------------------------------------------------------------
try:
    import pythoncom
    import win32com.client
    import win32gui
    WM_CLOSE = 0x0010
except Exception:
    pythoncom = win32com = win32gui = None
    WM_CLOSE = 0

def explorer_watch_loop(stop_ev: threading.Event):
    """Supervisa ventanas del Explorador y cierra carpetas bloqueadas."""
    if not (pythoncom and win32com and win32gui):
        log.warning("ExplorerWatch: COM/Win32 no disponible.")
        return
    log.info("ExplorerWatch iniciado.")
    shell = None
    last_closed = {}
    backoff = 0.3

    try: 
        pythoncom.CoInitialize()
    except Exception:
        pass

    while not stop_ev.is_set():
        try:
            blocked = []
            try:
                if CONFIG_PATH_PD.exists():
                    cfg = json.loads(CONFIG_PATH_PD.read_text(encoding="utf-8"))
                    blocked = [p for p in (cfg.get("blocked_paths") or []) if p]
            except Exception:
                pass

            if not blocked:
                time.sleep(0.5)
                continue
            if shell is None:
                shell = win32com.client.Dispatch("Shell.Application")
            for w in shell.Windows():
                try:
                    hwnd = int(getattr(w, "HWND", 0))
                    if not hwnd:
                        continue
                    cls = win32gui.GetClassName(hwnd)
                    if cls not in ("CabinetWClass", "ExploreWClass"):
                        continue
                    doc = getattr(w, "Document", None)
                    if doc and getattr(getattr(doc, "Folder", None), "Self", None):
                        path = getattr(doc.Folder.Self, "Path", "")
                        for d in blocked:
                            if path.lower().startswith(d.lower()) and time.time() - last_closed.get(hwnd, 0) > 1.5:
                                log.info("Cerrar carpeta bloqueada: %s", path)
                                win32gui.PostMessage(hwnd, WM_CLOSE, 0, 0)
                                notify_once(f"dir:{d}", "Carpeta bloqueada", "Necesitas permiso del tutor para abrir esta carpeta.", 6.0)
                                last_closed[hwnd] = time.time()
                                break
                except Exception as e:
                    log.debug("Error ventana Explorer: %s", e)
        except Exception as e:
            log.error("ExplorerWatch loop error: %s", e)
            shell = None
        time.sleep(backoff)
    try: 
        pythoncom.CoUninitialize()
    except Exception:
        pass
    log.info("ExplorerWatch detenido.")

# --------------------------------------------------------------------
# Main
# --------------------------------------------------------------------
def main():
    log.info("Notifier iniciado.")
    icon_path = None
    for cand in ("app_icon.ico", "app_icon.png"):
        p = BASE / "assets" / cand
        if p.exists():
            icon_path = str(p)
            break

    register_appid_in_registry(APP_ID, APP_DISPLAY, icon_path)
    ensure_appid_shortcut(APP_ID, icon_path)

    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)
    except Exception:
        pass

    stop_ev = threading.Event()
    threading.Thread(target=explorer_watch_loop, args=(stop_ev,), name="ExplorerWatch", daemon=True).start()

    st = load_state()
    last = int(st.get("last_id", 0))
    if last == 0:
        rows = query_new_blocks(0)
        if rows:
            last = rows[-1][0]
            st["last_id"] = last
            save_state(st)
            log.info("Saltado histórico hasta id=%s", last)

    while True:
        try:
            rows = query_new_blocks(last)
            for rid, ts, val, meta in rows:
                app, reason = (val or "").strip(), (meta or "").strip().lower()
                if reason.startswith(("dir:", "self:", "arg:", "openfile:", "wnd:")):
                    dir_path = next((reason[len(pref):].strip() for pref in ("dir:", "self:", "arg:", "openfile:", "wnd:") if reason.startswith(pref)), "")
                    shown = os.path.basename(dir_path) or "(ruta protegida)"
                    notify_once(f"dir:{dir_path}", "Carpeta bloqueada", f"No tienes permiso para abrir: {shown}", 6.0)
                else:
                    notify_once(f"app:{app.lower()}", "Aplicación bloqueada", f"{app}\nNecesitas permiso del tutor para usarla.", 3.0)
                last = rid
                st["last_id"] = last
                save_state(st)
        except Exception as e:
            log.error("Error en loop principal: %s", e)
        time.sleep(0.3)

if __name__ == "__main__":
    if any(a.lower() in ("--test", "--test-toast") for a in sys.argv[1:]):
        log.info("Modo test de notificación.")
        notify("Prueba de notificación", "Si ves este toast con el nombre correcto, todo está OK.", 5)
        sys.exit(0)
    main()
