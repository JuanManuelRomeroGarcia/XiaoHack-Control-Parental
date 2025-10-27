# notifier.py — XiaoHack (usuario)
# Overlay nativo Win32 (Layered + TopMost + NoActivate) per-monitor para countdown
# Lectura de estado y eventos desde %ProgramData%\XiaoHackParental (mismo que guardian)
# Toasters WinRT/winotify/win10toast + ExplorerWatch (como antes)

import os
import sys
import time
import json
import threading
import sqlite3
import html
from pathlib import Path

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

# --------------------------------------------------------------------
# Identidad XiaoHack (centralizada)
# --------------------------------------------------------------------
XH_ROLE = parse_role(sys.argv) or "notifier"
set_appusermodelid("XiaoHack.Parental.Notifier")
set_process_title(XH_ROLE)

try:
    import logging
    logging.getLogger().info("XiaoHack process started (role=%s)", XH_ROLE)
except Exception:
    pass

# --------------------------------------------------------------------
# Forzar data_dir a ProgramData (mismo que guardian)
# --------------------------------------------------------------------

PROGRAMDATA_DIR = Path(os.getenv("PROGRAMDATA", r"C:\ProgramData")) / "XiaoHackParental"
try:
    _storage_set_data_dir_forced(str(PROGRAMDATA_DIR))
    log.info("Notifier data_dir forzado a ProgramData: %s", _storage_data_dir())
except Exception as e:
    log.warning("No se pudo forzar data_dir a ProgramData: %s", e)
DB_PD = _STORAGE_DB_PATH


BASE = Path(__file__).resolve().parent
APPDATA = Path(os.getenv("APPDATA", str(BASE)))
STATE_DIR = APPDATA / "XiaoHackParental"
STATE_DIR.mkdir(parents=True, exist_ok=True)
STATE_FILE = STATE_DIR / "notifier_state.json"

CONFIG_PATH_PD = PROGRAMDATA_DIR / "config.json"

APP_ID      = "XiaoHack.Parental"
APP_DISPLAY = "XiaoHack Control Parental"

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
# Registro AppID y acceso a toasts
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
    try:
        import pythoncom
        from win32com.shell import shell  # type: ignore
        from win32com.propsys import propsys, pscon  # type: ignore

        pythoncom.CoInitialize()
        start_menu = APPDATA / "Microsoft" / "Windows" / "Start Menu" / "Programs"
        start_menu.mkdir(parents=True, exist_ok=True)
        lnk_path = str((start_menu / "XiaoHack Parental.lnk").resolve())

        pyw = Path(sys.executable).with_name("pythonw.exe")
        args = f"\"{(BASE / 'notifier.py').resolve()}\" --xh-role notifier"
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

# Toasts
WINRT_OK = WINOTIFY_OK = False
TOASTER = None
try:
    from winsdk.windows.ui.notifications import ToastNotificationManager, ToastNotification # type: ignore
    from winsdk.windows.data.xml.dom import XmlDocument # type: ignore
    WINRT_OK = True
except Exception:
    pass
try:
    from winotify import Notification as WNotify, audio as wnaudio # type: ignore
    WINOTIFY_OK = True
except Exception:
    pass
if not WINOTIFY_OK:
    try:
        from win10toast import ToastNotifier # type: ignore
        TOASTER = ToastNotifier()
    except Exception:
        pass

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
    if WINRT_OK:
        try:
            _show_winrt_toast(title, msg, icon)
            return True
        except Exception as e:
            log.warning("WinRT toast error: %s", e)
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
# SQLite: leer eventos nuevos (desde guardian.db)
# --------------------------------------------------------------------
def query_new_blocks(since_id: int):
    try:
        con = sqlite3.connect(str(DB_PD))
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
# Overlay TopMost nativo — per monitor (cubre fullscreen "exclusive" en la mayoría de casos)
# --------------------------------------------------------------------
WIN32_OVERLAY_OK = False
_OVERLAY_IMPL = "none"

try:
    import ctypes
    from ctypes import wintypes
    import win32con
    import win32api
    import win32gui  # type: ignore

    # Constantes
    WS_EX_LAYERED      = 0x00080000
    WS_EX_TRANSPARENT  = 0x00000020
    WS_EX_TOOLWINDOW   = 0x00000080
    WS_EX_TOPMOST      = 0x00000008
    WS_EX_NOACTIVATE   = 0x08000000

    WS_POPUP           = 0x80000000

    LWA_ALPHA          = 0x00000002

    GWL_EXSTYLE        = -20

    # GDI
    SRCCOPY            = 0x00CC0020

    # Estructuras para UpdateLayeredWindow
    class POINT(ctypes.Structure):
        _fields_ = [("x", wintypes.LONG), ("y", wintypes.LONG)]

    class SIZE(ctypes.Structure):
        _fields_ = [("cx", wintypes.LONG), ("cy", wintypes.LONG)]

    class BLENDFUNCTION(ctypes.Structure):
        _fields_ = [("BlendOp", ctypes.c_byte),
                    ("BlendFlags", ctypes.c_byte),
                    ("SourceConstantAlpha", ctypes.c_byte),
                    ("AlphaFormat", ctypes.c_byte)]

    AC_SRC_OVER = 0x00
    AC_SRC_ALPHA = 0x01

    user32 = ctypes.windll.user32
    gdi32  = ctypes.windll.gdi32

    # HBITMAP por DIBSection con alpha
    def _create_text_bitmap(w, h, text: str, subtitle: str | None = None):
        # Creamos un DC y DIBSection ARGB
        hdc = win32gui.CreateCompatibleDC(0)
        bmi = win32gui.BITMAPINFO()
        bmi['bmiHeader']['biSize'] = ctypes.sizeof(win32gui.BITMAPINFOHEADER)
        bmi['bmiHeader']['biWidth'] = w
        bmi['bmiHeader']['biHeight'] = -h  # top-down
        bmi['bmiHeader']['biPlanes'] = 1
        bmi['bmiHeader']['biBitCount'] = 32
        bmi['bmiHeader']['biCompression'] = win32con.BI_RGB
        hbitmap, bits = win32gui.CreateDIBSection(hdc, bmi, win32con.DIB_RGB_COLORS)
        old = win32gui.SelectObject(hdc, hbitmap)

        # Fondo semitransparente (negro)
        import struct
        bg = (0, 0, 0, int(0.92*255))  # ARGB
        px = struct.pack("BBBB", bg[2], bg[1], bg[0], bg[3])  # noqa: F841
        # Rellenar
        ctypes.memset(bits, 0, w * h * 4)
        # (memset negro con alpha 0; para alpha global lo hacemos con blend)

        # Render del texto (blanco)
        # Elegimos tamaños relativos a la diagonal
        import math
        diag = int(math.hypot(w, h))
        size_main = max(72, diag // 18)
        size_sub  = max(18, diag // 60)

        # Crear fuentes
        lf = win32gui.LOGFONT()
        lf.lfFaceName = "Segoe UI"
        lf.lfHeight = -size_main
        lf.lfWeight = 700
        hfont_main = win32gui.CreateFontIndirect(lf)

        lf2 = win32gui.LOGFONT()
        lf2.lfFaceName = "Segoe UI"
        lf2.lfHeight = -size_sub
        lf2.lfWeight = 400
        hfont_sub = win32gui.CreateFontIndirect(lf2)

        win32gui.SetBkMode(hdc, win32con.TRANSPARENT)
        win32gui.SetTextColor(hdc, win32api.RGB(255, 255, 255))

        # Medir y centrar
        rect = (0, 0, w, h)
        flags = win32con.DT_CENTER | win32con.DT_VCENTER | win32con.DT_SINGLELINE
        win32gui.SelectObject(hdc, hfont_main)
        win32gui.DrawText(hdc, text, -1, rect, flags)

        if subtitle:
            win32gui.SelectObject(hdc, hfont_sub)
            rect_sub = (0, int(h*0.60), w, h)
            win32gui.SetTextColor(hdc, win32api.RGB(220, 220, 220))
            win32gui.DrawText(hdc, subtitle, -1, rect_sub, win32con.DT_CENTER | win32con.DT_TOP)

        # Limpieza
        win32gui.SelectObject(hdc, old)
        win32gui.DeleteObject(hfont_main)
        win32gui.DeleteObject(hfont_sub)
        win32gui.DeleteDC(hdc)
        return hbitmap

    class _Win32OverlayWindow:
        def __init__(self, x, y, w, h, subtitle: str):
            self.x, self.y, self.w, self.h = x, y, w, h
            self.subtitle = subtitle
            self.hwnd = win32gui.CreateWindowEx(
                WS_EX_LAYERED | WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
                "Static",  # clase simple
                None,
                WS_POPUP,
                x, y, w, h,
                0, 0, 0, None
            )
            win32gui.SetWindowPos(self.hwnd, win32con.HWND_TOPMOST, x, y, w, h,
                                  win32con.SWP_NOACTIVATE | win32con.SWP_SHOWWINDOW)
            self.visible = False
            self._current_bitmap = None

        def _blit_text(self, text: str):
            # Crear bitmap con texto y hacer UpdateLayeredWindow
            hbmp = _create_text_bitmap(self.w, self.h, text, self.subtitle)
            hdc_screen = win32gui.GetDC(0)
            hdc_mem = win32gui.CreateCompatibleDC(hdc_screen)
            old = win32gui.SelectObject(hdc_mem, hbmp)

            size = SIZE(self.w, self.h)
            pos = POINT(self.x, self.y)
            src = POINT(0, 0)
            blend = BLENDFUNCTION(AC_SRC_OVER, 0, int(0.92*255), 0)  # alpha global ~0.92

            user32.UpdateLayeredWindow(self.hwnd, hdc_screen, ctypes.byref(pos),
                                       ctypes.byref(size), hdc_mem, ctypes.byref(src),
                                       0, ctypes.byref(blend), 0x02)  # ULW_ALPHA

            win32gui.SelectObject(hdc_mem, old)
            win32gui.DeleteDC(hdc_mem)
            win32gui.ReleaseDC(0, hdc_screen)

            if self._current_bitmap:
                win32gui.DeleteObject(self._current_bitmap)
            self._current_bitmap = hbmp

        def show(self, text: str):
            if not self.visible:
                win32gui.ShowWindow(self.hwnd, win32con.SW_SHOWNA)
                self.visible = True
            self._blit_text(text)

        def hide(self):
            if self.visible:
                win32gui.ShowWindow(self.hwnd, win32con.SW_HIDE)
                self.visible = False

        def destroy(self):
            try:
                self.hide()
            except Exception:
                pass
            if self._current_bitmap:
                try:
                    win32gui.DeleteObject(self._current_bitmap)
                except Exception:
                    pass
            try:
                win32gui.DestroyWindow(self.hwnd)
            except Exception:
                pass

    class Win32OverlayManager:
        def __init__(self):
            self.windows: list[_Win32OverlayWindow] = []
            self.subtitle = "Último minuto • Guarda tu partida"
            self._init_monitors()

        def _init_monitors(self):
            self.windows.clear()
            def _cb(hMon, hdc, rc, data):
                left, top, right, bottom = rc
                w, h = right - left, bottom - top
                self.windows.append(_Win32OverlayWindow(left, top, w, h, self.subtitle))
                return True
            win32gui.EnumDisplayMonitors(0, None, _cb, None)

        def render(self, n: int):
            text = str(n)
            for w in self.windows:
                w.show(text)

        def hide(self):
            for w in self.windows:
                w.hide()

        def destroy(self):
            for w in self.windows:
                w.destroy()
            self.windows.clear()

    WIN32_OVERLAY_OK = True
    _OVERLAY_IMPL = "win32"
except Exception as e:
    WIN32_OVERLAY_OK = False
    _OVERLAY_IMPL = "tk-fallback"
    log.warning("Overlay Win32 no disponible: %s", e)

# Fallback Tkinter (solo si Win32 no está operativo)
try:
    import tkinter as tk
    from tkinter import ttk
except Exception:
    tk = None
    ttk = None

def tk_overlay_loop(stop_ev: threading.Event):
    if tk is None:
        log.warning("Overlay deshabilitado: tkinter no disponible.")
        return
    from app.scheduler import get_overlay_countdown
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
        sub = tk.Label(frame, text="Último minuto • Guarda tu partida", font=("Segoe UI", 24), fg="#DDDDDD", bg="#000000")
        sub.place(relx=0.5, rely=0.62, anchor="center")
        visible = False
        last_n = -1
        while not stop_ev.is_set():
            st = _storage_load_state()
            n = get_overlay_countdown(st)
            if n > 0:
                if not visible:
                    root.deiconify()
                    visible = True
                if n != last_n:
                    label.config(text=str(n))
                    last_n = n
                root.update_idletasks()
                root.update()
            else:
                if visible:
                    root.withdraw()
                    visible = False
                time.sleep(0.2)
    except Exception as e:
        log.warning("tk overlay error: %s", e)

def overlay_loop(stop_ev: threading.Event):
    from app.scheduler import get_overlay_countdown
    if WIN32_OVERLAY_OK:
        log.info("Overlay usando implementación Win32 Layered (TopMost, NoActivate).")
        mgr = Win32OverlayManager()
        last_n = -1
        visible = False
        try:
            while not stop_ev.is_set():
                n = 0
                try:
                    st = _storage_load_state()
                    n = get_overlay_countdown(st)
                except Exception:
                    n = 0
                if n > 0:
                    if not visible:
                        visible = True
                    if n != last_n:
                        mgr.render(n)
                        last_n = n
                else:
                    if visible:
                        mgr.hide()
                        visible = False
                    time.sleep(0.2)
        except Exception as e:
            log.warning("Overlay Win32 error: %s (cambiando a fallback Tkinter)", e)
            try:
                mgr.destroy()
            except Exception:
                pass
            # fallback
            tk_overlay_loop(stop_ev)
        finally:
            try:
                mgr.destroy()
            except Exception:
                pass
    else:
        log.info("Overlay usando fallback Tkinter.")
        tk_overlay_loop(stop_ev)

# --------------------------------------------------------------------
# Main
# --------------------------------------------------------------------
def main():
    log.info("Notifier iniciado. Overlay=%s", _OVERLAY_IMPL)
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
    threading.Thread(target=overlay_loop, args=(stop_ev,), name="Overlay", daemon=True).start()

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
                st_local["last_id"] = last
                save_state_local(st_local)
        except Exception as e:
            log.error("Error en loop principal: %s", e)
        time.sleep(0.3)

if __name__ == "__main__":
    if any(a.lower() in ("--test", "--test-toast") for a in sys.argv[1:]):
        log.info("Modo test de notificación.")
        notify("Prueba de notificación", "Si ves este toast con el nombre correcto, todo está OK.", 5)
        sys.exit(0)
    main()
