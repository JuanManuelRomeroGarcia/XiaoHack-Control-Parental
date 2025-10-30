# notifier.py — XiaoHack (usuario)
# Overlay nativo Win32 (Layered + TopMost + NoActivate) per-monitor para countdown
# Lectura de estado y eventos desde %ProgramData%\XiaoHackParental (mismo que guardian)
# Toasters WinRT/winotify/win10toast + ExplorerWatch

from __future__ import annotations
import app._bootstrap  # noqa: F401  # side-effects

import os
import sys
import time
import json
import threading
import html
from pathlib import Path

from app.helperdb import fetch_events_since
from app.storage import (
    set_data_dir_forced as _storage_set_data_dir_forced,
    load_config as _storage_load_config,  # noqa: F401
    load_state as _storage_load_state,
    data_dir as _storage_data_dir,
    DB_PATH as _STORAGE_DB_PATH,
)
from utils.runtime import parse_role, set_process_title, set_appusermodelid
from app.logs import get_logger, install_exception_hooks

log = get_logger("notifier")
install_exception_hooks("notifier-crash")

# === Overlay countdown: usar SIEMPRE lo que calcula scheduler/guardian ===
try:
    from app.scheduler import get_overlay_countdown as _sched_get_overlay_countdown
except Exception:
    _sched_get_overlay_countdown = None


# --------------------------------------------------------------------
# Identidad XiaoHack (centralizada)
# --------------------------------------------------------------------
APP_ID      = "XiaoHack.Parental"
APP_DISPLAY = "XiaoHack Control Parental"

XH_ROLE = parse_role(sys.argv) or "notifier"
set_appusermodelid(APP_ID)
set_process_title(XH_ROLE)

try:
    import logging
    logging.getLogger().debug("XiaoHack process started (role=%s)", XH_ROLE)
except Exception:
    pass

# --------------------------------------------------------------------
# Rutas de instalación/datos (respetando variables de entorno de los .bat)
# --------------------------------------------------------------------
BASE = Path(__file__).resolve().parent                 # ...\app
INSTALL_DIR = Path(os.getenv("XH_INSTALL_DIR", str(BASE.parent)))  # raíz de instalación
ASSETS_DIR = INSTALL_DIR / "assets"

# Forzar data_dir a lo que venga en XH_DATA_DIR o a ProgramData\XiaoHackParental
_XH_DATA_ENV = os.getenv("XH_DATA_DIR", "")
if _XH_DATA_ENV:
    DATA_DIR_FORCED = Path(_XH_DATA_ENV)
else:
    DATA_DIR_FORCED = Path(os.getenv("PROGRAMDATA", r"C:\ProgramData")) / "XiaoHackParental"

try:
    _storage_set_data_dir_forced(str(DATA_DIR_FORCED))
    log.info("Notifier data_dir forzado: %s", _storage_data_dir())
except Exception as e:
    log.warning("No se pudo forzar data_dir: %s", e)

DB_PD = _STORAGE_DB_PATH
CONFIG_PATH_PD = DATA_DIR_FORCED / "config.json"

# Estado local por-usuario (para recordar último id de evento mostrado)
APPDATA = Path(os.getenv("APPDATA", str(BASE)))
STATE_DIR = APPDATA / "XiaoHackParental"
STATE_DIR.mkdir(parents=True, exist_ok=True)
STATE_FILE = STATE_DIR / "notifier_state.json"

# --------------------------------------------------------------------
# Estado local del notifier
# --------------------------------------------------------------------
def load_state_local():
    try:
        if STATE_FILE.exists():
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception as e:
        log.warning("Error al leer notifier_state: %s", e)
    return {"last_id": 0}

def save_state_local(st):
    try:
        tmp = STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(st, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(STATE_FILE)
    except Exception as e:
        log.error("Error al guardar notifier_state: %s", e)

# --------------------------------------------------------------------
# AUMID / AppID — registro + acceso directo
# --------------------------------------------------------------------
def register_appid_in_registry(app_id: str, display_name: str, icon_path: str | None):
    """Registra el AppID en HKCU para branding de toasts."""
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
    """
    Crea/actualiza un .lnk en el Menú Inicio del usuario actual que lanza:
      pythonw.exe -m app.notifier --xh-role notifier
    - Si hay propsys, fija también el AppUserModelID en el .lnk.
    - Si no, crea shortcut simple (AppID ya mapeado por registro).
    """
    start_menu = Path(os.getenv("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs"
    start_menu.mkdir(parents=True, exist_ok=True)
    lnk_path = str((start_menu / "XiaoHack Parental.lnk").resolve())

    pyw = Path(sys.executable).with_name("pythonw.exe")
    args = "-m app.notifier --xh-role notifier"
    workdir = str(INSTALL_DIR)

    # intento “completo” con AppID en el .lnk
    try:
        import pythoncom
        from win32com.shell import shell  # type: ignore
        from win32com.propsys import propsys, pscon  # type: ignore

        pythoncom.CoInitialize()
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
        log.debug("Shortcut con AppID creado: %s", lnk_path)
        try:
            pythoncom.CoUninitialize()
        except Exception:
            pass
        return
    except Exception as e:
        log.warning("Shortcut con AppID no disponible (%s). Creando básico…", e)
        try:
            import pythoncom
            pythoncom.CoUninitialize()
        except Exception:
            pass

    # fallback básico (sin AppID en .lnk; AppID vía registro)
    try:
        import win32com.client  # type: ignore
        ws = win32com.client.Dispatch("WScript.Shell")
        s = ws.CreateShortcut(lnk_path)
        s.TargetPath = str(pyw)
        s.Arguments = args
        s.WorkingDirectory = workdir
        if icon_path:
            s.IconLocation = icon_path
        s.Save()
        log.debug("Shortcut básico creado: %s", lnk_path)
    except Exception as e2:
        log.warning("No se pudo crear shortcut básico: %s", e2)

def _shell_notify_refresh():
    """Refresca asociaciones/menú inicio tras crear el .lnk con AppID."""
    try:
        import ctypes
        SHCNE_ASSOCCHANGED = 0x08000000
        SHCNF_IDLIST = 0x0000
        ctypes.windll.shell32.SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None)
    except Exception:
        pass

def _pick_icon() -> str | None:
    for cand in ("app_icon.ico", "app_icon.png"):
        p = ASSETS_DIR / cand
        if p.exists():
            return str(p)
    return None

def ensure_aumid_ready():
    """
    Idempotente: registra el AppID en HKCU, asegura el .lnk en Start Menu
    y hace un pequeño refresco del Shell para que WinRT lo reconozca.
    """
    icon_path = _pick_icon()
    log.debug("ensure_aumid_ready: icon=%s", icon_path)
    try:
        register_appid_in_registry(APP_ID, APP_DISPLAY, icon_path)
    except Exception as e:
        log.debug("register_appid_in_registry fallo: %s", e)
    try:
        ensure_appid_shortcut(APP_ID, icon_path)
    except Exception as e:
        log.debug("ensure_appid_shortcut fallo: %s", e)
    _shell_notify_refresh()
    time.sleep(0.2)

def diagnose_notification_env(auto_fix: bool = False) -> dict:
    """
    Devuelve un dict con el estado del entorno de notificaciones.
    Si auto_fix=True, intenta habilitar valores básicos en HKCU (sin elevar).
    """
    import winreg

    def _get_dword(root, path, name, default=None):
        try:
            with winreg.OpenKey(root, path) as k:
                val, typ = winreg.QueryValueEx(k, name)
                if typ == winreg.REG_DWORD:
                    return int(val)
        except Exception:
            pass
        return default

    def _set_dword(root, path, name, value) -> bool:
        try:
            with winreg.CreateKey(root, path) as k:
                winreg.SetValueEx(k, name, 0, winreg.REG_DWORD, int(value))
            return True
        except Exception:
            return False

    # Presencia de acceso directo (.lnk) con AUMID
    start_menu_lnk = Path(os.getenv("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "XiaoHack Parental.lnk"
    has_shortcut = start_menu_lnk.exists()

    # WinRT disponible
    winrt_available = bool(WINRT_OK)

    # Global: toasts habilitados
    p_push = r"Software\Microsoft\Windows\CurrentVersion\PushNotifications"
    toast_enabled = _get_dword(winreg.HKEY_CURRENT_USER, p_push, "ToastEnabled", None)
    if toast_enabled == 0 and auto_fix:
        if _set_dword(winreg.HKEY_CURRENT_USER, p_push, "ToastEnabled", 1):
            toast_enabled = 1

    # App específica: Enabled por AUMID
    p_app = fr"Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\{APP_ID}"
    app_enabled = _get_dword(winreg.HKEY_CURRENT_USER, p_app, "Enabled", None)
    if app_enabled == 0 and auto_fix:
        if _set_dword(winreg.HKEY_CURRENT_USER, p_app, "Enabled", 1):
            app_enabled = 1

    # Focus Assist / No molestar (heurística)
    p_quiet = r"Software\Microsoft\Windows\CurrentVersion\QuietHours"
    quiet_hours_active = _get_dword(winreg.HKEY_CURRENT_USER, p_quiet, "QuietHoursActive", 0)

    res = {
        "app_id": APP_ID,
        "winrt_available": winrt_available,
        "has_shortcut": has_shortcut,
        "shortcut_path": str(start_menu_lnk),
        "toast_enabled": toast_enabled,            # 1=on, 0=off, None=sin clave
        "app_enabled": app_enabled,                # 1=on, 0=off, None=sin clave
        "quiet_hours_active": int(bool(quiet_hours_active)),
        "data_dir": str(_storage_data_dir()),
    }
    return res

# --------------------------------------------------------------------
# Toasts (WinRT / winotify / win10toast + Balloon fallback)
# --------------------------------------------------------------------
WINRT_OK = WINOTIFY_OK = False
TOASTER = None
try:
    from winsdk.windows.ui.notifications import ToastNotificationManager, ToastNotification  # type: ignore
    from winsdk.windows.data.xml.dom import XmlDocument  # type: ignore
    WINRT_OK = True
except Exception as e:
    log.debug("winsdk (WinRT) no disponible: %s", e)

try:
    from winotify import Notification as WNotify, audio as wnaudio  # type: ignore
    WINOTIFY_OK = True
except Exception as e:
    log.debug("winotify no disponible: %s", e)

if not WINOTIFY_OK:
    try:
        from win10toast import ToastNotifier  # type: ignore
        TOASTER = ToastNotifier()
    except Exception as e:
        log.debug("win10toast no disponible: %s", e)

def _show_winrt_toast(title: str, msg: str, icon_path: str | None = None):
    safe_title, safe_msg = html.escape(title or ""), html.escape(msg or "")
    img_xml = f"<image placement='appLogoOverride' src='{html.escape(icon_path)}'/>" if icon_path else ""
    xml = f"<toast><visual><binding template='ToastGeneric'><text>{safe_title}</text><text>{safe_msg}</text>{img_xml}</binding></visual></toast>"
    xdoc = XmlDocument()
    xdoc.load_xml(xml)
    ToastNotificationManager.create_toast_notifier(APP_ID).show(ToastNotification(xdoc))

def _balloon_fallback(title: str, msg: str, icon_path: str | None = None, timeout_ms: int = 5000) -> bool:
    """Fallback definitivo usando Shell_NotifyIconW (balloon)."""
    try:
        import ctypes
        from ctypes import wintypes as wt
        import uuid
        NIM_ADD, NIM_MODIFY, NIM_DELETE = 0, 1, 2
        NIF_MESSAGE, NIF_ICON, NIF_TIP, NIF_INFO = 0x1, 0x2, 0x4, 0x10  # noqa: F841
        HWND_MESSAGE, WM_USER = 0xFFFFFFFF, 0x0400

        class NOTIFYICONDATAW(ctypes.Structure):
            _fields_ = [
                ("cbSize", wt.DWORD), ("hWnd", wt.HWND), ("uID", wt.UINT),
                ("uFlags", wt.UINT), ("uCallbackMessage", wt.UINT),
                ("hIcon", wt.HICON), ("szTip", wt.WCHAR * 128),
                ("dwState", wt.DWORD), ("dwStateMask", wt.DWORD),
                ("szInfo", wt.WCHAR * 256), ("uTimeoutOrVersion", wt.UINT),
                ("szInfoTitle", wt.WCHAR * 64), ("dwInfoFlags", wt.DWORD),
                ("guidItem", wt.GUID), ("hBalloonIcon", wt.HICON),
            ]

        Shell_NotifyIconW = ctypes.windll.shell32.Shell_NotifyIconW
        LoadImageW        = ctypes.windll.user32.LoadImageW
        hicon = None
        if icon_path and Path(icon_path).exists():
            LR_LOADFROMFILE, LR_DEFAULTSIZE, IMAGE_ICON = 0x10, 0x40, 1
            hicon = LoadImageW(None, icon_path, IMAGE_ICON, 0, 0, LR_LOADFROMFILE | LR_DEFAULTSIZE)

        nid = NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        nid.hWnd = HWND_MESSAGE
        nid.uID = 1
        nid.uFlags = NIF_MESSAGE | NIF_INFO | (NIF_ICON if hicon else 0)
        nid.uCallbackMessage = WM_USER + 1
        nid.hIcon = hicon
        nid.szTip = (APP_DISPLAY or "")[:127]
        nid.szInfo = (msg or "")[:255]
        nid.szInfoTitle = (title or APP_DISPLAY or "")[:63]
        nid.uTimeoutOrVersion = max(1000, min(timeout_ms, 30000))
        nid.dwInfoFlags = 0
        nid.guidItem = (ctypes.c_byte * 16).from_buffer_copy(uuid.uuid4().bytes)  # type: ignore

        Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid))
        Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(nid))
        time.sleep(nid.uTimeoutOrVersion / 1000.0)
        Shell_NotifyIconW(NIM_DELETE, ctypes.byref(nid))
        return True
    except Exception as e:
        log.warning("Balloon fallback error: %s", e)
        return False

def notify(title: str, msg: str, duration=5):
    icon = _pick_icon()
    log.info("Notificación: %s | %s", title, (msg or "")[:80])

    # 1) WinRT
    if WINRT_OK:
        try:
            _show_winrt_toast(title, msg, icon)
            log.info("toast via WinRT (AUMID=%s)", APP_ID)
            return True
        except Exception as e:
            log.warning("WinRT toast error: %s", e)

    # 2) winotify
    if WINOTIFY_OK:
        try:
            n = WNotify(app_id=APP_ID, title=title, msg=msg, icon=icon)
            try:
                n.set_audio(wnaudio.Reminder, loop=False)
            except Exception:
                pass
            n.show()
            log.info("toast via winotify (AUMID=%s)", APP_ID)
            return True
        except Exception as e:
            log.warning("winotify error: %s", e)

    # 3) win10toast
    if TOASTER:
        try:
            TOASTER.show_toast(title, msg, duration=duration, threaded=True)
            log.info("toast via win10toast")
            return True
        except Exception as e:
            log.warning("win10toast error: %s", e)

    # 4) Balloon del sistema
    if _balloon_fallback(title, msg, icon, timeout_ms=max(3000, int(duration * 1000))):
        log.info("toast via Shell_NotifyIconW (balloon)")
        return True

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
# SQLite: leer eventos nuevos (desde guardian.db)
# --------------------------------------------------------------------
def query_new_blocks(since_id: int):
    return fetch_events_since("block", since_id)

def query_new_countdown_events(since_id: int):
    return fetch_events_since("countdown", since_id)

def query_new_notifies(since_id: int):
    return fetch_events_since("notify", since_id)

_LAST_STOP_TS = 0.0
_LAST_START_DEADLINE = None

def _handle_countdown_event(value: str, meta: str):
    """
    value: "start" | "stop"
    meta : JSON {"deadline": epoch} o {"seconds": n}
    Reglas:
      - Anti-rearme: si acabamos de parar (t<3s), ignorar 'start'
      - Idempotencia: si llega un 'start' con el mismo deadline y ya está armado, ignorar
    """
    global _LAST_STOP_TS, _LAST_START_DEADLINE
    try:
        payload = {}
        if meta:
            try:
                payload = json.loads(meta)
            except Exception:
                payload = {}

        if value == "start":
            # Ventana anti-rearme tras STOP
            if _LAST_STOP_TS and (time.time() - _LAST_STOP_TS) < 3.0:
                log.info("Countdown START ignorado (ventana tras STOP)")
                return

            deadline = None
            if "deadline" in payload:
                deadline = float(payload["deadline"])
            elif "seconds" in payload:
                # Construimos un deadline sintético para poder comparar duplicados
                deadline = time.time() + float(payload["seconds"])

            if deadline is not None:
                # Si ya armamos este mismo deadline y el overlay está activo, ignorar
                if (_LAST_START_DEADLINE is not None
                        and abs(_LAST_START_DEADLINE - deadline) < 0.5
                        and _LC.remaining() > 0):
                    log.info("Countdown START duplicado (deadline=%s) ignorado", deadline)
                    return

                _LC.arm_until(deadline, source="event")
                _LAST_START_DEADLINE = deadline
                log.info("Overlay armed by EVENT (deadline=%s)", deadline)
            elif "seconds" in payload:
                secs = float(payload["seconds"])
                if _LC.remaining() > 0 and abs(_LC.remaining() - secs) < 0.5:
                    log.info("Countdown START duplicado (seconds=%s) ignorado", secs)
                    return
                _LC.arm_for(secs, source="event")
                _LAST_START_DEADLINE = None
                log.info("Overlay armed by EVENT (seconds=%s)", secs)

        elif value == "stop":
            _LC.disarm()
            _LAST_STOP_TS = time.time()
            _LAST_START_DEADLINE = None
            log.info("Overlay disarmed by EVENT")

    except Exception as e:
        log.warning("countdown-event error: %s", e)


# --------------------------------------------------------------------
# Explorer Watch (como antes)
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
# Overlay TopMost nativo — per monitor
# --------------------------------------------------------------------
def _overlay_settings():
    """
    Lee ProgramData\XiaoHackParental\config.json:
      "overlay": {"mode":"banner|fullscreen","position":"top|bottom","height":160,"opacity":0.92}
    Defaults: banner/top/160/0.92
    """
    try:
        cfg = _storage_load_config() or {}
        ov = (cfg.get("overlay") or {})
        mode = (ov.get("mode") or "banner").lower()
        if mode not in ("banner", "fullscreen"):
            mode = "banner"
        position = (ov.get("position") or "top").lower()
        if position not in ("top", "bottom"):
            position = "top"
        height = max(80, min(400, int(ov.get("height", 160))))
        opacity = max(0.10, min(1.0, float(ov.get("opacity", 0.92))))
        return mode, position, height, opacity
    except Exception:
        return "banner", "top", 160, 0.92

def _overlay_seconds_from_state(st: dict) -> int:
    """Devuelve 0..60. Preferir 'play_countdown' escrito por guardian/scheduler."""
    # 1) Campo directo si existe (lo actualiza guardian cada segundo en último minuto)
    try:
        n = int(st.get("play_countdown", 0) or 0)
        return max(0, min(60, n))
    except Exception:
        pass

    # 2) Fallback al scheduler si está disponible
    if _sched_get_overlay_countdown:
        try:
            n = int(_sched_get_overlay_countdown(st))
            return max(0, min(60, n))
        except Exception:
            pass

    return 0


def _safe_overlay_seconds() -> int:
    """
    1) Primero, si está armado el temporizador local (pulsos start/stop), úsalo.
    2) Si NO está armado, mira el state (play_countdown/scheduler) y arma SOLO lo que quede.
    """
    # Al inicio de _safe_overlay_seconds():
    if _LAST_STOP_TS and (time.time() - _LAST_STOP_TS) < 3.0:
        return 0
        # 1) Temporizador local (pista fiable porque viene de eventos start/stop)
        n = _sec_from_local_timer()
        
    if n > 0:
        return n

    # 2) Fallback suave: lee state y arma por los segundos que falten (no usa deadline_ts)
    try:
        st = _storage_load_state() or {}
        n = _overlay_seconds_from_state(st)  # << usa play_countdown/scheduler
        if 0 < n <= 60:
            _LC.arm_for(n, source="state")   # arma solo lo que falte
            return _sec_from_local_timer()
    except Exception:
        pass

    return 0



WIN32_OVERLAY_OK = False
_OVERLAY_IMPL = "none"

try:
    import ctypes
    from ctypes import wintypes  # noqa: F401
    import win32con
    import win32api
    import win32gui  # type: ignore

    WS_EX_LAYERED     = 0x00080000
    WS_EX_TRANSPARENT = 0x00000020
    WS_EX_TOOLWINDOW  = 0x00000080
    WS_EX_TOPMOST     = 0x00000008
    WS_EX_NOACTIVATE  = 0x08000000
    WS_POPUP          = 0x80000000

    LWA_ALPHA         = 0x00000002

    user32 = ctypes.windll.user32
    _HWND_MAP: dict[int, "_Win32OverlayWindow"] = {}  # noqa: F722

    class _Win32OverlayWindow:
        def __init__(self, x, y, w, h, subtitle: str, opacity: float):
            self.x, self.y, self.w, self.h = x, y, w, h
            self.subtitle = subtitle
            self.opacity = opacity
            self._text = "60"

            ex = WS_EX_LAYERED | WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_TRANSPARENT
            self.hwnd = win32gui.CreateWindowEx(ex, "Static", None, WS_POPUP, x, y, w, h, 0, 0, 0, None)
            _HWND_MAP[int(self.hwnd)] = self

            # Subclase con ctypes para click-through y pintura
            import ctypes as ct
            from ctypes import wintypes as WT
            GWL_WNDPROC = -4  # noqa: F841
            WNDPROC = ct.WINFUNCTYPE(ct.c_long, WT.HWND, ct.c_uint, WT.WPARAM, WT.LPARAM)
            

            def _wndproc(hWnd, msg, wParam, lParam):
                try:
                    if msg == win32con.WM_NCHITTEST:
                        return win32con.HTTRANSPARENT
                    if msg == win32con.WM_PAINT:
                        self._on_paint(hWnd)
                        return 0
                    if msg in (win32con.WM_MOUSEACTIVATE, win32con.WM_ACTIVATE, win32con.WM_SETFOCUS):
                        return 0
                except Exception:
                    pass
                return user32.DefWindowProcW(hWnd, msg, wParam, lParam)

            self._new_wndproc = WNDPROC(_wndproc)  # mantener viva la ref
            user32.SetWindowLongPtrW(self.hwnd, -4, self._new_wndproc)

            # Opacidad global
            user32.SetLayeredWindowAttributes(self.hwnd, 0, int(self.opacity * 255), LWA_ALPHA)

            win32gui.SetWindowPos(self.hwnd, win32con.HWND_TOPMOST, x, y, w, h,
                                  win32con.SWP_NOACTIVATE | win32con.SWP_SHOWWINDOW)
            self.visible = True
            
        def set_subtitle(self, subtitle: str | None):
            if subtitle is not None and subtitle != self.subtitle:
                self.subtitle = subtitle
                # Forzamos repintado si ya es visible
                try:
                    win32gui.InvalidateRect(self.hwnd, None, True)
                except Exception:
                    pass  

        def _on_paint(self, hwnd):
            hdc, ps = win32gui.BeginPaint(hwnd)
            try:
                # Fondo negro (la transparencia la aplica el alpha global del layered)
                brush = win32gui.CreateSolidBrush(win32api.RGB(0, 0, 0))
                win32gui.FillRect(hdc, win32gui.GetClientRect(hwnd), brush)
                win32gui.DeleteObject(brush)

                import math
                rect = win32gui.GetClientRect(hwnd)
                w = rect[2] - rect[0]
                h = rect[3] - rect[1]

                # Tallas: número grande y subtítulo más pequeño
                diag = int(math.hypot(w, h))
                size_main = max(48, min(140, diag // 18))
                size_sub  = max(16, min(36,  diag // 60))

                lf1 = win32gui.LOGFONT()
                lf1.lfFaceName="Segoe UI"
                lf1.lfHeight=-size_main
                lf1.lfWeight=700
                hfont1 = win32gui.CreateFontIndirect(lf1)
                lf2 = win32gui.LOGFONT()
                lf2.lfFaceName="Segoe UI"
                lf2.lfHeight=-size_sub
                lf2.lfWeight=400
                hfont2 = win32gui.CreateFontIndirect(lf2)

                win32gui.SetBkMode(hdc, win32con.TRANSPARENT)

                # 1) Número — en la mitad superior del banner (evita solape)
                rect_num = (rect[0], int(h * 0.03), rect[2], int(h * 0.60))
                win32gui.SetTextColor(hdc, win32api.RGB(255, 255, 255))
                win32gui.SelectObject(hdc, hfont1)
                win32gui.DrawText(hdc, self._text, -1, rect_num,
                                win32con.DT_CENTER | win32con.DT_VCENTER | win32con.DT_SINGLELINE)

                # 2) Subtítulo — parte baja del banner
                rect_sub = (rect[0], int(h * 0.64), rect[2], rect[3])
                win32gui.SetTextColor(hdc, win32api.RGB(220, 220, 220))
                win32gui.SelectObject(hdc, hfont2)
                win32gui.DrawText(hdc, self.subtitle, -1, rect_sub,
                                win32con.DT_CENTER | win32con.DT_TOP)

                win32gui.DeleteObject(hfont1)
                win32gui.DeleteObject(hfont2)
            finally:
                win32gui.EndPaint(hwnd, ps)

        def show(self, text: str):
            self._text = text
            # Reimpone TOPMOST por si otra ventana topmost (tu panel) nos pasó por encima
            win32gui.SetWindowPos(
                self.hwnd, win32con.HWND_TOPMOST, self.x, self.y, self.w, self.h,
                win32con.SWP_NOACTIVATE | win32con.SWP_SHOWWINDOW
            )
            win32gui.InvalidateRect(self.hwnd, None, True)
            if not self.visible:
                win32gui.ShowWindow(self.hwnd, win32con.SW_SHOWNA)
                self.visible = True


        def hide(self):
            if self.visible:
                win32gui.ShowWindow(self.hwnd, win32con.SW_HIDE)
                self.visible = False

        def destroy(self):
            try:
                self.hide()
            except Exception: 
                pass
            try: 
                win32gui.DestroyWindow(self.hwnd)
            except Exception: 
                pass
            _HWND_MAP.pop(int(self.hwnd), None)

    class Win32OverlayManager:
        """
        Crea las ventanas del overlay solo cuando hace falta (lazy) y
        las mantiene SIEMPRE ocultas al iniciar para evitar el flash inicial.
        """
        def __init__(self):
            self.windows: list[_Win32OverlayWindow] = []
            self.subtitle = "Último minuto • Guarda tu partida"
            self.mode, self.position, self.height_px, self.opacity = _overlay_settings()
            self._ready = False           # ← aún no se han creado las ventanas
            self._last_monitors = None    # firma simple para detectar cambios de monitores

        def _monitors_signature(self) -> tuple:
            """Firma simple del layout de monitores para recrear si cambian."""
            try:
                sig = []
                for _hMon, _hdc, (l1, t, r, b) in win32api.EnumDisplayMonitors():
                    sig.append((l1, t, r, b))
                return tuple(sig)
            except Exception:
                # primario
                sw = win32api.GetSystemMetrics(0)
                sh = win32api.GetSystemMetrics(1)
                return ((0, 0, sw, sh),)

        def _init_monitors(self, make_visible: bool = False):
            """
            Crea todas las ventanas. Si make_visible=False, las deja ocultas explícitamente.
            """
            self.windows.clear()
            try:
                mons = win32api.EnumDisplayMonitors()
                for _hMon, _hdc, (l1, t, r, b) in mons:
                    w, h = r - l1, b - t
                    if self.mode == "banner":
                        hh = min(self.height_px, max(80, int(h * 0.22)))
                        y  = t if self.position == "top" else b - hh
                        wnd = _Win32OverlayWindow(l1, y, w, hh, self.subtitle, self.opacity)
                    else:
                        wnd = _Win32OverlayWindow(l1, t, w, h, self.subtitle, self.opacity)
                    self.windows.append(wnd)
            except Exception as e:
                log.warning("EnumDisplayMonitors no disponible (%s), usando primario", e)
                sw = win32api.GetSystemMetrics(0)
                sh = win32api.GetSystemMetrics(1)
                if self.mode == "banner":
                    hh = min(self.height_px, max(80, int(sh * 0.22)))
                    y  = 0 if self.position == "top" else sh - hh
                    self.windows.append(_Win32OverlayWindow(0, y, sw, hh, self.subtitle, self.opacity))
                else:
                    self.windows.append(_Win32OverlayWindow(0, 0, sw, sh, self.subtitle, self.opacity))

            # MUY IMPORTANTE: ocultar todo inmediatamente al crear si no queremos visibilidad inicial
            if not make_visible:
                try:
                    for w in self.windows:
                        w.hide()
                except Exception:
                    pass

            self._ready = True
            self._last_monitors = self._monitors_signature()

        def _ensure_ready(self, make_visible: bool = False):
            """Crea las ventanas si aún no existen o si cambió la geometría de monitores."""
            sig = self._monitors_signature()
            if (not self._ready) or (self._last_monitors != sig):
                # destruir lo anterior si existe
                if self._ready:
                    try:
                        for w in self.windows:
                            w.destroy()
                    except Exception:
                        pass
                    self.windows.clear()
                    self._ready = False
                # crear nuevas (ocultas salvo que se pida lo contrario)
                self._init_monitors(make_visible=make_visible)

        def render(self, n: int):
            """
            Pinta el número 'n'. Si no está listo, crea ventanas en modo OCULTO
            y solo las muestra al hacer show(...).
            """
            if n <= 0:
                self.hide()
                return

            self._ensure_ready(make_visible=False)
            txt = str(n)
            for w in self.windows:
                # <<< clave: propagar el subtítulo actual a cada ventana
                w.set_subtitle(self.subtitle)
                w.show(txt)

        def render_text(self, text: str):
            if not text:
                self.hide()
                return
            self._ensure_ready(make_visible=False)
            for w in self.windows:
                # <<< clave: propagar el subtítulo también en los flashes 10/5
                w.set_subtitle(self.subtitle)
                w.show(text)

        def hide(self):
            """Oculta todas las ventanas si existen."""
            if not self._ready:
                return
            try:
                for w in self.windows:
                    w.hide()
            except Exception:
                pass

        def destroy(self):
            """Destruye todas las ventanas y limpia estado."""
            try:
                for w in self.windows:
                    w.destroy()
            except Exception:
                pass
            self.windows.clear()
            self._ready = False
            self._last_monitors = None


    WIN32_OVERLAY_OK = True
    _OVERLAY_IMPL = "win32"
except Exception as e:
    WIN32_OVERLAY_OK = False
    _OVERLAY_IMPL = "tk-fallback"
    log.warning("Overlay Win32 no disponible: %s", e)
# Fallback Tkinter (solo si Win32 no está operativo)
try:
    import tkinter as tk
    from tkinter import ttk  # noqa: F401
except Exception:
    tk = None

def tk_overlay_loop(stop_ev: threading.Event):
    if tk is None:
        log.warning("Overlay deshabilitado: tkinter no disponible.")
        return
    try:
        root = tk.Tk()
        root.withdraw()
        root.overrideredirect(True)
        root.attributes("-topmost", True)
        try:
            root.attributes("-alpha", 0.92)
        except Exception:
            pass

        sw = root.winfo_screenwidth()
        sh = root.winfo_screenheight()
        root.geometry(f"{sw}x{sh}+0+0")

        frame = tk.Frame(root, bg="#000000")
        frame.place(relx=0, rely=0, relwidth=1, relheight=1)

        default_subtitle = "Último minuto • Guarda tu partida"
        label = tk.Label(frame, text="60", font=("Segoe UI", 140, "bold"), fg="#FFFFFF", bg="#000000")
        label.place(relx=0.5, rely=0.45, anchor="center")
        sub = tk.Label(frame, text=default_subtitle, font=("Segoe UI", 24), fg="#DDDDDD", bg="#000000")
        sub.place(relx=0.5, rely=0.62, anchor="center")

        visible = False
        last_txt = None

        SLEEP_ACTIVE = 0.06
        SLEEP_IDLE   = 0.20

        while not stop_ev.is_set():
            # 1) Flash 10/5 min (5s)
            ftxt, fsub = _flash_current()
            if ftxt:
                if not visible:
                    root.deiconify()
                    visible = True
                if ftxt != last_txt:
                    label.config(text=str(ftxt))
                    sub.config(text=fsub or default_subtitle)
                    last_txt = ftxt
                root.update_idletasks()
                root.update()
                time.sleep(SLEEP_ACTIVE)
                continue  # <- evita usar 'n' sin asignar

            # 2) Countdown último minuto
            n = _safe_overlay_seconds()
            if n > 0:
                if not visible:
                    root.deiconify()
                    visible = True
                txt = str(n)
                if txt != last_txt:
                    label.config(text=txt)
                    sub.config(text=default_subtitle)
                    last_txt = txt
                root.update_idletasks()
                root.update()
                time.sleep(SLEEP_ACTIVE)
            else:
                if visible:
                    root.withdraw()
                    visible = False
                    last_txt = None
                time.sleep(SLEEP_IDLE)
    except Exception as e:
        log.warning("tk overlay error: %s", e)


def overlay_loop(stop_ev: threading.Event):
    """
    Muestra:
      - Flash 10/5 min (5s) si está activo.
      - Si no hay flash: countdown del último minuto (n=60..1) desde el timer local/state.
    """
    SLEEP_ACTIVE = 0.06
    SLEEP_IDLE   = 0.20
    default_subtitle = "Último minuto • Guarda tu partida"

    def _pump():
        try:
            if WIN32_OVERLAY_OK:
                win32gui.PumpWaitingMessages()
        except Exception:
            pass

    if WIN32_OVERLAY_OK:
        log.info("Overlay usando implementación Win32 Layered (TopMost, NoActivate).")
        mgr = Win32OverlayManager()
        last_n = -1
        visible = False
        try:
            while not stop_ev.is_set():
                # 1) Flash 10/5 min
                ftxt, fsub = _flash_current()
                if ftxt:
                    mgr.subtitle = fsub or default_subtitle
                    mgr.render_text(ftxt)
                    visible = True
                    last_n = -1  # no mezclar con número previo
                    _pump()
                    time.sleep(SLEEP_ACTIVE)
                    continue

                # 2) Countdown último minuto
                n = _safe_overlay_seconds()
                if n > 0:
                    mgr.subtitle = default_subtitle
                    if not visible:
                        visible = True
                    if n != last_n:
                        mgr.render(n)
                        last_n = n
                    _pump()
                    time.sleep(SLEEP_ACTIVE)
                else:
                    if visible:
                        mgr.hide()
                        visible = False
                        last_n = -1
                    _pump()
                    time.sleep(SLEEP_IDLE)
        except Exception as e:
            log.warning("Overlay Win32 error: %s (fallback Tkinter)", e)
            try:
                mgr.destroy()
            except Exception:
                pass
            tk_overlay_loop(stop_ev)
        finally:
            try:
                mgr.destroy()
            except Exception:
                pass
    else:
        log.info("Overlay usando fallback Tkinter (banner no disponible).")
        # Fallback con soporte básico de flash
        if tk is None:
            return
        try:
            root = tk.Tk()
            root.withdraw()
            root.overrideredirect(True)
            root.attributes("-topmost", True)
            try:
                root.attributes("-alpha", 0.92)
            except Exception:
                pass
            sw = root.winfo_screenwidth()
            sh = root.winfo_screenheight()
            root.geometry(f"{sw}x{sh}+0+0")
            frame = tk.Frame(root, bg="#000000")
            frame.place(relx=0, rely=0, relwidth=1, relheight=1)
            label = tk.Label(frame, text="60", font=("Segoe UI", 140, "bold"), fg="#FFFFFF", bg="#000000")
            label.place(relx=0.5, rely=0.45, anchor="center")
            sub = tk.Label(frame, text=default_subtitle, font=("Segoe UI", 24), fg="#DDDDDD", bg="#000000")
            sub.place(relx=0.5, rely=0.62, anchor="center")
            visible = False
            last_txt = None

            while not stop_ev.is_set():
                ftxt, fsub = _flash_current()
                if ftxt:
                    if not visible:
                        root.deiconify()
                        visible = True
                    if ftxt != last_txt:
                        label.config(text=str(ftxt))
                        sub.config(text=fsub or default_subtitle)
                        last_txt = ftxt
                    root.update_idletasks()
                    root.update()
                    time.sleep(SLEEP_ACTIVE)
                    continue

                n = _safe_overlay_seconds()
                if n > 0:
                    if not visible:
                        root.deiconify()
                        visible = True
                    txt = str(n)
                    if txt != last_txt:
                        label.config(text=txt)
                        sub.config(text=default_subtitle)
                        last_txt = txt
                    root.update_idletasks()
                    root.update()
                    time.sleep(SLEEP_ACTIVE)
                else:
                    if visible:
                        root.withdraw()
                        visible = False
                        last_txt = None
                    time.sleep(SLEEP_IDLE)
        except Exception as e:
            log.warning("tk overlay error: %s", e)

        
        
# === Timer interno (independiente de state por segundo) =======================
class LocalCountdown:
    HEARTBEAT_MAX_AGE = 35.0
    MAX_LAST_MINUTE   = 60

    def __init__(self):
        self.armed = False
        self.deadline = 0.0
        self.source = ""   # "deadline" | "countdown" | "event"
        self.armed_ts = 0.0

    def disarm(self):
        self.armed = False
        self.deadline = 0.0
        self.source = ""
        self.armed_ts = 0.0

    def arm_until(self, abs_deadline: float, source: str = "event"):
        import time as _t
        rem = float(abs_deadline) - _t.time()
        if rem <= 0 or rem > self.MAX_LAST_MINUTE:
            self.disarm()
            return
        self.armed = True
        self.deadline = float(abs_deadline)
        self.source = source
        self.armed_ts = _t.time()

    def arm_for(self, seconds_from_now: float, source: str = "event"):
        import time as _t
        self.arm_until(_t.time() + float(seconds_from_now), source=source)

    def seconds_left(self) -> int:
        import time as _t
        import math
        if not self.armed:
            return 0
        rem = self.deadline - _t.time()
        if rem <= 0:
            self.disarm()
            return 0
        if rem > self.MAX_LAST_MINUTE:
            self.disarm()
            return 0
        return int(max(1, min(self.MAX_LAST_MINUTE, math.ceil(rem))))


_LC = LocalCountdown()

def _sec_from_local_timer() -> int:
    try:
        n = _LC.seconds_left()
        return n if 1 <= n <= 60 else 0
    except Exception:
        return 0


# === “Flash” banner de 10/5 min (5s) =========================================
_FLASH = {"text": None, "subtitle": None, "until": 0.0}

def trigger_flash_banner(text: str, subtitle: str | None = None, seconds: float = 5.0):
    _FLASH["text"] = str(text)
    _FLASH["subtitle"] = subtitle
    _FLASH["until"] = time.time() + float(seconds)

def _flash_current():
    if _FLASH["until"] > time.time() and _FLASH["text"]:
        return _FLASH["text"], _FLASH["subtitle"]
    return None, None



# --------------------------------------------------------------------
# Main
# --------------------------------------------------------------------
def main():
    log.info("Notifier iniciado. Overlay=%s", _OVERLAY_IMPL)

    # Asegurar AUMID listo ANTES de lanzar hilos o notificaciones
    ensure_aumid_ready()
    diagnose_notification_env(auto_fix=True)
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)
    except Exception:
        pass

    stop_ev = threading.Event()
    threading.Thread(target=explorer_watch_loop, args=(stop_ev,), name="ExplorerWatch", daemon=True).start()
    threading.Thread(target=overlay_loop,    args=(stop_ev,), name="Overlay",        daemon=True).start()

    # Saltar histórico de bloqueos
    st_local = load_state_local()
    last = int(st_local.get("last_id", 0))
    if last == 0:
        rows = query_new_blocks(0)
        if rows:
            last = rows[-1][0]
            st_local["last_id"] = last
            save_state_local(st_local)
            log.info("Saltado histórico hasta id=%s", last)

        # Saltar histórico (compat: bloques/notifies/countdown con punteros separados)
    st_local = load_state_local()
    last_block = int(st_local.get("last_block_id", st_local.get("last_id", 0)) or 0)
    last_cd    = int(st_local.get("last_cd_id", 0) or 0)
    last_nt    = int(st_local.get("last_nt_id", 0) or 0)

    while True:
        try:
            # 1) COUNTDOWN: arma/para timer interno
            rows_cd = query_new_countdown_events(last_cd)
            for rid, ts, val, meta in rows_cd:
                _handle_countdown_event((val or "").strip().lower(), meta or "")
                last_cd = rid
                st_local["last_cd_id"] = last_cd
            if rows_cd:
                save_state_local(st_local)

            # 2) NOTIFY: toasts + flash 10/5 min (5s)
            rows_nt = query_new_notifies(last_nt)
            for rid, ts, title, body in rows_nt:
                t = (title or "").strip()
                b = (body or "").strip()
                # Toast normal siempre
                notify(t or "Aviso", b, duration=5)

                # Flash banner si es aviso de tiempo de juego (10/5 minutos)
                if t.lower() == "tiempo de juego":
                    lb = b.lower()
                    if "10 minutos" in lb:
                        log.info("Flash 10m recibido → mostrar banner 10")
                        trigger_flash_banner("10", "Quedan 10 minutos", seconds=5.0)
                    elif "5 minutos" in lb:
                        log.info("Flash 5m recibido → mostrar banner 5")
                        trigger_flash_banner("5", "Quedan 5 minutos", seconds=5.0)

                last_nt = rid
                st_local["last_nt_id"] = last_nt
            if rows_nt:
                save_state_local(st_local)

            # 3) BLOCKS: igual que antes
            rows = query_new_blocks(last_block)
            for rid, ts, val, meta in rows:
                app, reason = (val or "").strip(), (meta or "").strip().lower()
                if reason.startswith(("dir:", "self:", "arg:", "openfile:", "wnd:")):
                    dir_path = next((reason[len(pref):].strip() for pref in ("dir:", "self:", "arg:", "openfile:", "wnd:") if reason.startswith(pref)), "")
                    shown = os.path.basename(dir_path) or "(ruta protegida)"
                    notify_once(f"dir:{dir_path}", "Carpeta bloqueada", f"No tienes permiso para abrir: {shown}", 6.0)
                else:
                    notify_once(f"app:{app.lower()}", "Aplicación bloqueada", f"{app}\nNecesitas permiso del tutor para usarla.", 3.0)
                last_block = rid
                st_local["last_block_id"] = last_block
            if rows:
                save_state_local(st_local)

        except Exception as e:
            log.error("Error en loop principal: %s", e)

        time.sleep(0.15)


if __name__ == "__main__":
    if any(a.lower() in ("--test", "--test-toast") for a in sys.argv[1:]):
        log.info("Modo test de notificación.")
        notify("Prueba de notificación", "Si ves este toast con el nombre correcto, todo está OK.", 5)
        sys.exit(0)

    if any(a.lower() == "--diagnose" for a in sys.argv[1:]):
        auto_fix = any(a.lower() in ("--fix", "--auto-fix") for a in sys.argv[1:])
        # ¡OJO!: no llamar a ensure_aumid_ready() aquí
        res = diagnose_notification_env(auto_fix=auto_fix)
        print(json.dumps(res, ensure_ascii=False))
        sys.exit(0)

    main()
