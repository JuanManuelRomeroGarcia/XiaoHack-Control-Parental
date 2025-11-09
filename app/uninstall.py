# uninstall.py — XiaoHack (GUI completa, 2 fases, limpieza ProgramData/LocalAppData y sin tareas)
from __future__ import annotations
import importlib.util
import os
import sys
import json
import shutil
import ctypes
import stat
import time
import subprocess
import tempfile
from pathlib import Path
import logging

# ========= Bootstrap portable (py312) antes de usar tkinter =========
try:
    _pydir = os.path.dirname(sys.executable)  # ...\py312 si usamos embebido
    try:
        os.add_dll_directory(_pydir)
        os.add_dll_directory(os.path.join(_pydir, "DLLs"))
    except Exception:
        pass
    os.environ.setdefault("TCL_LIBRARY", os.path.join(_pydir, "tcl", "tcl8.6"))
    os.environ.setdefault("TK_LIBRARY",  os.path.join(_pydir, "tcl", "tk8.6"))
except Exception:
    pass
# ===================================================================

# --- AppUserModelID para icono correcto en barra de tareas
try:
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("XiaoHack.Parental.Panel")
except Exception:
    pass

# --- logging básico (usa logs.py si está)
try:
    from app.logs import configure, get_logger, install_exception_hooks
    configure(level="INFO")
    install_exception_hooks("uninstall-crash")
    log = get_logger("xh.uninstall")
except Exception:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    log = logging.getLogger("xh.uninstall")

# --- deps opcionales ---
_HAS_TK = True
try:
    import tkinter as tk
    from tkinter import ttk, messagebox
except Exception:
    _HAS_TK = False
try:
    import psutil  # type: ignore
except Exception:
    psutil = None
try:
    import bcrypt  # type: ignore
except Exception:
    bcrypt = None

# --- RUTAS / POLÍTICA ---
PROGRAM_FILES = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
PROGRAM_DATA  = Path(os.environ.get("ProgramData",  r"C:\ProgramData"))

APP_NAME      = "XiaoHackParental"

INSTALL_DIR   = Path(__file__).resolve().parents[1]       # %ProgramFiles%\XiaoHackParental
DATA_DIR_SYS  = PROGRAM_DATA / APP_NAME                   # %ProgramData%\XiaoHackParental

CONFIG_PATH   = DATA_DIR_SYS / "config.json"
INSTALL_MARK  = INSTALL_DIR / "installed.json"

PROGRAMS_COMMON = PROGRAM_DATA / r"Microsoft\Windows\Start Menu\Programs"
LNK_MENU_DIR_NEW = PROGRAMS_COMMON / "XiaoHack Control Parental"
LNK_MENU_DIR_OLD = PROGRAMS_COMMON / "XiaoHack Parental"
PUBLIC_DESKTOP  = Path(os.environ.get("PUBLIC", r"C:\Users\Public")) / "Desktop"
USER_DESKTOP    = Path(os.environ.get("USERPROFILE", "")) / "Desktop"

COMMON_START  = PROGRAM_DATA / r"Microsoft\Windows\Start Menu\Programs\StartUp"

MATCHES = ("--xh-role", "guardian.py", "notifier.py", "run.py", "webfilter.py", "dnsconfig.py")
KEEP_NAMES = {"uninstall.py"}  # NO excluimos py312 (hay que borrarlo)

# --- Icono de la app (XiaoHack) ----------------------------------------------
ICON_CANDIDATES = [
    Path(__file__).resolve().parents[1] / "assets" / "xiaohack.ico",
    Path(__file__).resolve().parents[1] / "assets" / "icon.ico",
    Path(__file__).resolve().parents[1] / "icon.ico",
]

def _apply_app_icon(win: "tk.Tk|tk.Toplevel") -> None:
    """Intenta poner el icono .ico propio en la ventana."""
    try:
        for p in ICON_CANDIDATES:
            if p.exists():
                win.iconbitmap(str(p))
                return
    except Exception:
        pass

# -------------------------------------------------------------------
# Utilidades
# -------------------------------------------------------------------
def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def _ensure_admin_or_relaunch():
    try:
        if ctypes.windll.shell32.IsUserAnAdmin():
            return
    except Exception:
        return
    exe = sys.executable  # pythonw.exe embebido (py312)
    params = "-m app.uninstall --elevated 1"
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        sys.exit(0)
    except Exception:
        pass

def _module_exists(modname: str) -> bool:
    try:
        return importlib.util.find_spec(modname) is not None
    except Exception:
        return False

def run(cmd, timeout=None):
    CREATE_NO_WINDOW = 0x08000000
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
    except Exception as e:
        log.debug("run(%s) error: %s", cmd, e)
        return subprocess.CompletedProcess(cmd, 255, "", str(e))

def load_cfg() -> dict:
    try:
        if CONFIG_PATH.exists():
            return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}

# ---------- helpers UI ----------
def _raise_front(win: "tk.Tk|tk.Toplevel", ms: int = 1200) -> None:
    try:
        win.lift()
        win.attributes("-topmost", True)
        win.after(ms, lambda: win.attributes("-topmost", False))
        win.focus_force()
    except Exception:
        pass

def _center(win: "tk.Tk|tk.Toplevel", w: int, h: int) -> None:
    try:
        win.update_idletasks()
        sw = win.winfo_screenwidth()
        sh = win.winfo_screenheight()
        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 2)
        win.geometry(f"{w}x{h}+{x}+{y}")
    except Exception:
        pass

class _PinDialog(tk.Toplevel):
    def __init__(self, parent: tk.Tk, title: str = "Desinstalador Control Parental"):
        super().__init__(parent)
        _apply_app_icon(self)
        self.title(title)
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        _center(self, 380, 180)
        _raise_front(self, 1500)

        frm = ttk.Frame(self, padding=12)
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text="Introduce el PIN del tutor:", font=("Segoe UI", 10)).pack(anchor="w")
        self.var = tk.StringVar()
        e = ttk.Entry(frm, show="*", textvariable=self.var, width=32)
        e.pack(fill="x", pady=(6, 10))
        e.focus_set()

        btns = ttk.Frame(frm)
        btns.pack(fill="x")
        ttk.Button(btns, text="OK", command=self._ok).pack(side="left")
        ttk.Button(btns, text="Cancelar", command=self._cancel).pack(side="right")

        self.result: str | None = None
        self.bind("<Return>", lambda *_: self._ok())
        self.bind("<Escape>", lambda *_: self._cancel())

    def _ok(self):
        self.result = self.var.get().strip()
        self.destroy()

    def _cancel(self):
        self.result = None
        self.destroy()

class _ConfirmDialog(tk.Toplevel):
    def __init__(self, parent: tk.Tk):
        super().__init__(parent)
        _apply_app_icon(self)
        self.title("Confirmación")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        _center(self, 420, 200)
        _raise_front(self, 1500)

        frm = ttk.Frame(self, padding=12)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text='Escribe EXACTAMENTE: DESINSTALAR', font=("Segoe UI", 10)).pack(anchor="w")
        self.var = tk.StringVar()
        e = ttk.Entry(frm, textvariable=self.var, width=36)
        e.pack(fill="x", pady=(6, 10))
        e.focus_set()

        btns = ttk.Frame(frm)
        btns.pack(fill="x")
        ttk.Button(btns, text="Confirmar", command=self._ok).pack(side="left")
        ttk.Button(btns, text="Cancelar", command=self._cancel).pack(side="right")

        self.ok = False
        self.bind("<Return>", lambda *_: self._ok())
        self.bind("<Escape>", lambda *_: self._cancel())

    def _ok(self):
        self.ok = (self.var.get().strip() == "DESINSTALAR")
        self.destroy()

    def _cancel(self):
        self.ok = False
        self.destroy()

def uninstall_requires_pin(cfg: dict) -> bool:
    return bool(cfg.get("uninstall_requires_pin", True))

def verify_pin_gui(root: tk.Tk, cfg: dict) -> bool:
    dlg = _PinDialog(root)
    root.wait_window(dlg)
    pin = dlg.result
    if not pin:
        return False

    stored = (cfg.get("parent_password_hash") or "").strip()
    if stored and bcrypt:
        try:
            if bcrypt.checkpw(pin.encode(), stored.encode()):
                return True
            messagebox.showerror("PIN incorrecto", "El PIN no coincide.", parent=root)
            return False
        except Exception:
            pass

    # Confirmación textual si no hay hash o bcrypt no está
    cdlg = _ConfirmDialog(root)
    root.wait_window(cdlg)
    if not cdlg.ok:
        messagebox.showwarning("Cancelado", "No se confirmó la desinstalación.", parent=root)
        return False

    plain = (cfg.get("parent_password_plain") or "").strip()
    return (not plain) or (pin == plain)

# -------------------- procesos / tareas / borrado -----------------------------
def schtasks_stop_delete_all():
    for name in ("\\XiaoHackParental\\Guardian", "\\XiaoHackParental\\Notificador", "XiaoHack_FinalCleanup"):
        run(["schtasks", "/End", "/TN", name])
        run(["schtasks", "/Delete", "/TN", name, "/F"])

def _exclude_self(p):
    try:
        return p.pid == os.getpid()
    except Exception:
        return False

def kill_related(install_path: str, list_only=False):
    rows = []
    if not psutil:
        return rows
    inst = install_path.lower()
    for p in psutil.process_iter(attrs=["pid", "name", "cmdline", "exe", "cwd"]):
        try:
            if _exclude_self(p):
                continue
            info = p.info
            cmd = " ".join(info.get("cmdline") or [])
            exe = (info.get("exe") or "").lower()
            cwd = (info.get("cwd") or "").lower()
            if (inst in cmd.lower()) or (inst in exe) or (inst in cwd) or any(m in cmd.lower() for m in MATCHES):
                rows.append((p.pid, info.get("name") or "python", cmd))
                if not list_only:
                    try:
                        p.terminate()
                    except Exception:
                        pass
        except Exception:
            pass
    if not list_only:
        time.sleep(0.9)
        for pid, _, _ in rows:
            try:
                q = psutil.Process(pid)
                if q.is_running():
                    try:
                        q.kill()
                    except Exception:
                        pass
            except Exception:
                pass
    return rows

def close_all_logs():
    try:
        logging.shutdown()
    except Exception:
        pass
    time.sleep(0.8)

def safe_rmtree(path: Path, retries=8, delay=0.8) -> bool:
    if not path.exists():
        return True
    for _ in range(retries):
        try:
            for r, dnames, fnames in os.walk(path, topdown=False):
                for n in fnames:
                    p = Path(r) / n
                    try: 
                        os.chmod(p, stat.S_IWRITE)
                    except Exception:
                        pass
                for n in dnames:
                    d = Path(r) / n
                    try:
                        os.chmod(d, stat.S_IWRITE)
                    except Exception: 
                        pass
            shutil.rmtree(path, ignore_errors=False)
            return True
        except Exception:
            time.sleep(delay)
    return False

def revert_hosts_if_possible():
    try:
        from app.webfilter import remove_parental_block
        removed = remove_parental_block()
        log.info("Bloque parental %s.", "eliminado" if removed else "no presente")
        return
    except Exception:
        pass
    try:
        hosts = Path(r"C:\Windows\System32\drivers\etc\hosts")
        if hosts.exists():
            import re
            c = hosts.read_text(encoding="utf-8", errors="ignore")
            c = re.sub(r"\n?# === PARENTAL_BEGIN ===.*?# === PARENTAL_END ===\n?", "\n", c, flags=re.S)
            hosts.write_text(c, encoding="utf-8")
            log.info("Hosts limpiado por fallback de marcadores.")
    except Exception:
        pass

def remove_shortcuts():
    def _del(p: Path):
        try:
            p.unlink(missing_ok=True)
        except Exception:
            pass

    for name in ("XiaoHack Control Parental.lnk", "XiaoHack Control Uninstall.lnk",
                 "XiaoHack Parental.lnk", "XiaoHack Uninstall.lnk"):
        _del(PUBLIC_DESKTOP / name)
        if USER_DESKTOP:
            _del(USER_DESKTOP / name)

    for base in (LNK_MENU_DIR_NEW, LNK_MENU_DIR_OLD):
        if base.exists():
            for lnk in base.glob("*.lnk"):
                _del(lnk)
            try:
                if not any(base.iterdir()):
                    base.rmdir()
            except Exception:
                pass

    for name in ("XiaoHack Notifier.lnk",
                 "XiaoHackParental Notifier.lnk",
                 "XiaoHack Control Parental Notifier.lnk"):
        _del(COMMON_START / name)

def restore_dns_auto():
    if _module_exists("app.dnsconfig"):
        try:
            from app import dnsconfig
            ok, msg = dnsconfig.set_dns_auto(interface_alias=None)
            log.info("[dns] Auto vía módulo: %s", msg or ("OK" if ok else ""))
            return
        except Exception:
            pass
    ps = r'''
$ifaces = Get-DnsClient | Where-Object { $_.AddressFamily -in ('IPv4','IPv6') }
foreach ($i in $ifaces) {
  try { Set-DnsClientServerAddress -InterfaceIndex $i.InterfaceIndex -ResetServerAddresses -ErrorAction Stop } catch {}
}
"OK"
'''
    run(["PowerShell","-NoProfile","-ExecutionPolicy","Bypass","-Command", ps])

def clear_doh_policies():
    did_any = False
    for mod, path in (("app.braveconfig", "Brave"), ("app.chromeconfig", "Chrome")):
        if _module_exists(mod):
            try:
                m = importlib.import_module(mod)
                ok, msg = m.clear_brave_policy(scope="BOTH") if "brave" in mod else m.clear_chrome_policy(scope="BOTH")
                log.info("[doh] %s vía módulo: %s", path, msg or ("OK" if ok else ""))
                did_any = True
            except Exception:
                pass
    if did_any:
        return
    ps = r'''
$paths = @(
 'HKCU:\Software\Policies\Google\Chrome',
 'HKLM:\SOFTWARE\Policies\Google\Chrome',
 'HKCU:\Software\Policies\BraveSoftware\Brave',
 'HKLM:\SOFTWARE\Policies\BraveSoftware\Brave'
)
foreach ($p in $paths) {
  try { New-Item -Path $p -Force | Out-Null } catch {}
  foreach ($n in @('DnsOverHttpsMode','DnsOverHttpsTemplates','BuiltInDnsClientEnabled')) {
    try { Remove-ItemProperty -Path $p -Name $n -ErrorAction SilentlyContinue } catch {}
  }
}
"OK"
'''
    run(["PowerShell","-NoProfile","-ExecutionPolicy","Bypass","-Command", ps])

# ----------------------- borrado en dos fases ---------------------------------
MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004
def _movefileex_delete_on_reboot(path: str) -> bool:
    try:
        k32 = ctypes.windll.kernel32
        from ctypes import wintypes
        k32.MoveFileExW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
        k32.MoveFileExW.restype = wintypes.BOOL
        p = "\\\\?\\" + path
        return bool(k32.MoveFileExW(p, None, MOVEFILE_DELAY_UNTIL_REBOOT))
    except Exception:
        return False

def mark_tree_for_delete_on_reboot(root: str | Path) -> int:
    root = str(root)
    count = 0
    try:
        for r, dirs, files in os.walk(root, topdown=False):
            for f in files:
                fp = os.path.join(r, f)
                if _movefileex_delete_on_reboot(fp):
                    count += 1
            for d in dirs:
                dp = os.path.join(r, d)
                if _movefileex_delete_on_reboot(dp): 
                    count += 1
        if _movefileex_delete_on_reboot(root):
            count += 1
    except Exception:
        pass
    return count

def register_runonce_cleanup(paths: list[str]) -> bool:
    try:
        import winreg as wr
    except Exception:
        return False
    ps = '$paths=@(' + ",".join(f'"{p}"' for p in paths) + r''');
foreach($t in $paths){
  if(Test-Path $t){
    try{ takeown /f "$t" /r /d y | Out-Null }catch{}
    try{ icacls "$t" /grant "*S-1-5-32-544:(OI)(CI)F" /t /c /q | Out-Null }catch{}
    try{ Remove-Item -LiteralPath $t -Recurse -Force -ErrorAction SilentlyContinue }catch{}
  }
}
"OK"
'''
    cmd = rf'PowerShell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command {ps}'
    try:
        key = wr.OpenKey(wr.HKEY_LOCAL_MACHINE,
                         r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                         0, wr.KEY_SET_VALUE | 0x0100)
        wr.SetValueEx(key, "XiaoHack_FinalCleanup", 0, wr.REG_SZ, cmd)
        wr.CloseKey(key)
        return True
    except Exception:
        return False

def delete_folder_two_phase(install_path: str):
    root_dir = Path(install_path)
    for item in list(root_dir.iterdir()):
        if item.name in KEEP_NAMES:
            continue
        try:
            if item.is_dir():
                safe_rmtree(item)
            else:
                item.unlink(missing_ok=True)
        except Exception:
            pass

# ----------------------- GUI principal ----------------------------------------
def gui_main():
    _ensure_admin_or_relaunch()

    # Ventana root primero (para que los diálogos sean hijos y salgan delante)
    root = tk.Tk()
    _apply_app_icon(root) 
    root.title("Desinstalador Control Parental XiaoHack")
    root.minsize(980, 560)
    _center(root, 1024, 600)
    _raise_front(root, 1500)
    root.resizable(True, True)

    cfg = load_cfg()
    if uninstall_requires_pin(cfg):
        if not verify_pin_gui(root, cfg):
            root.destroy()
            return

    try:
        marker = json.loads(INSTALL_MARK.read_text(encoding="utf-8"))
        install_path = marker.get("install_path", str(INSTALL_DIR))
    except Exception:
        install_path = str(INSTALL_DIR)

    frm = ttk.Frame(root, padding=12)
    frm.pack(fill="both", expand=True)
    ttk.Label(frm, text=f"Carpeta de instalación: {install_path}").pack(anchor="w", pady=(0, 6))
    ttk.Label(frm, text=f"Datos (sistema): {DATA_DIR_SYS}").pack(anchor="w")

    cols = ("PID", "Nombre", "Comando")
    tree = ttk.Treeview(frm, columns=cols, show="headings", height=11)
    for i, w in zip(cols, (80, 120, 640)):
        tree.heading(i, text=i)
        tree.column(i, width=w, anchor="w")
    tree.pack(fill="both", expand=True)

    status = tk.StringVar(value="Listo.")
    ttk.Label(frm, textvariable=status, anchor="w").pack(fill="x", pady=(8, 0))

    btns = ttk.Frame(frm)
    btns.pack(fill="x", pady=8)

    def refresh():
        tree.delete(*tree.get_children())
        rows = kill_related(install_path, list_only=True)
        for pid, name, cmd in rows:
            tree.insert("", "end", values=(pid, name, cmd))
        status.set(f"Procesos detectados: {len(rows)}")

    def stop_processes():
        status.set("Cerrando procesos y tareas…")
        root.update_idletasks()
        kill_related(install_path, list_only=False)
        schtasks_stop_delete_all()
        time.sleep(0.6)
        refresh()
        status.set("Procesos cerrados (si había).")

    def clean_shortcuts():
        status.set("Eliminando accesos directos…")
        root.update_idletasks()
        remove_shortcuts()
        status.set("Accesos directos eliminados.")

    def revert_hosts_gui():
        status.set("Revirtiendo hosts…")
        root.update_idletasks()
        revert_hosts_if_possible()
        status.set("Hosts revertido (si aplicaba).")

    POST_BAT = None

    def delete_folder():
        nonlocal POST_BAT
        status.set("Cerrando procesos/tareas…")
        root.update_idletasks()
        stop_processes()
        status.set("Cerrando logs…")
        root.update_idletasks()
        close_all_logs()
        status.set("Eliminando accesos…")
        root.update_idletasks()
        clean_shortcuts()
        status.set("Restaurando DNS y limpiando DoH…")
        root.update_idletasks()
        clear_doh_policies()
        restore_dns_auto()

        status.set("Borrando contenido (fase 1)…")
        root.update_idletasks()
        delete_folder_two_phase(install_path)

        POST_BAT = _write_post_cleanup_bat(install_path)
        try: 
            subprocess.Popen(["cmd","/c",f'"{POST_BAT}"'], creationflags=0x08000000)
        except Exception:
            pass

        time.sleep(0.9)
        remaining = Path(install_path).exists() or DATA_DIR_SYS.exists()
        if remaining:
            n = 0
            if Path(install_path).exists():
                n += mark_tree_for_delete_on_reboot(install_path)
            if DATA_DIR_SYS.exists(): 
                n += mark_tree_for_delete_on_reboot(DATA_DIR_SYS)
            register_runonce_cleanup([str(install_path), str(DATA_DIR_SYS)])
            messagebox.showinfo(
                "Limpieza pendiente",
                "Quedan restos bloqueados (py312/ o ProgramData). Se han marcado para borrarse al reiniciar "
                "y se ha registrado un RunOnce para forzar la limpieza."
            )
            status.set("Limpieza pendiente al reinicio.")
        else:
            status.set("Limpieza completada.")
            messagebox.showinfo("Completado", "Se ha eliminado XiaoHack Parental correctamente.")

        root.after(200, root.destroy)

    def on_close():
        root.destroy()

    ttk.Button(btns, text="🔄 Refrescar", command=refresh).pack(side="left")
    ttk.Button(btns, text="✖ Cerrar procesos", command=stop_processes).pack(side="left", padx=6)
    ttk.Button(btns, text="🧹 Quitar accesos", command=clean_shortcuts).pack(side="left", padx=6)
    ttk.Button(btns, text="🛡 Hosts revert", command=revert_hosts_gui).pack(side="left", padx=6)
    ttk.Button(btns, text="🗂️ Borrar carpeta", command=delete_folder).pack(side="left", padx=6)
    ttk.Button(btns, text="Salir", command=on_close).pack(side="right")

    root.protocol("WM_DELETE_WINDOW", on_close)
    refresh()
    root.mainloop()

# ------------------- fallback consola -------------------
def console_main():
    _ensure_admin_or_relaunch()
    try:
        marker = json.loads(INSTALL_MARK.read_text(encoding="utf-8"))
        install_path = marker.get("install_path", str(INSTALL_DIR))
    except Exception:
        install_path = str(INSTALL_DIR)

    print("Cerrando tareas y procesos…")
    schtasks_stop_delete_all()
    kill_related(install_path, list_only=False)
    close_all_logs()

    print("Revirtiendo hosts…")
    revert_hosts_if_possible()

    print("Eliminando accesos…")
    remove_shortcuts()

    print("Limpiando DoH y restaurando DNS…")
    clear_doh_policies()
    restore_dns_auto()

    print("Borrando contenido (fase 1)…")
    delete_folder_two_phase(install_path)

    post_bat = _write_post_cleanup_bat(install_path)
    try: 
        subprocess.Popen(["cmd","/c",f'"{post_bat}"'], creationflags=0x08000000)
    except Exception:
        pass

    time.sleep(0.9)
    remaining = []
    if Path(install_path).exists():
        remaining.append(install_path)
    if DATA_DIR_SYS.exists():    
        remaining.append(str(DATA_DIR_SYS))
    if remaining:
        n = 0
        for p in remaining: 
            n += mark_tree_for_delete_on_reboot(p)
        register_runonce_cleanup([str(install_path), str(DATA_DIR_SYS)])
        print(f"Pendiente: marcados {n} elementos para borrado al reiniciar + RunOnce registrado.")
    else:
        print("Limpieza completada.")
    print("Puedes cerrar esta ventana.")

# ------------------- helpers post-cleanup (BAT) -------------------
def _write_post_cleanup_bat(install_path: str):
    post_bat = Path(tempfile.gettempdir()) / "xh_post_cleanup.bat"
    progdata = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "XiaoHackParental")
    install  = str(install_path)
    bat = f"""@echo off
setlocal enableextensions
pushd "%TEMP%" >nul 2>&1
set "SIDADM=S-1-5-32-544"
for %%D in ("{progdata}" "{install}") do (
  if exist "%%~fD" (
    attrib -r -s -h "%%~fD\\*" /s /d >nul 2>&1
    for /l %%i in (1 1 8) do (
      takeown /f "%%~fD" /r /d y >nul 2>&1
      icacls "%%~fD" /grant "*%SIDADM%:(OI)(CI)F" /t /c /q >nul 2>&1
      del /f /q "%%~fD\\guardian.db"       >nul 2>&1
      del /f /q "%%~fD\\guardian.db-wal"   >nul 2>&1
      del /f /q "%%~fD\\guardian.db-shm"   >nul 2>&1
      del /f /q "%%~fD\\logs\\control.log" >nul 2>&1
      powershell -NoProfile -ExecutionPolicy Bypass -Command "Remove-Item -LiteralPath '%%~fD' -Recurse -Force -ErrorAction SilentlyContinue" >nul 2>&1
      rmdir /s /q "%%~fD" >nul 2>&1
      if exist "%%~fD" ping 127.0.0.1 -n 2 >nul
    )
  )
)
exit /b 0
"""
    try:
        post_bat.write_text(bat, encoding="utf-8", newline="\r\n")
        log.info("post-bat OK -> %s", post_bat)
    except Exception as e:
        log.error("post-bat write failed: %s", e)
    return post_bat

# ------------------------------------------------------------------
if __name__ == "__main__":
    if _HAS_TK:
        gui_main()
    else:
        console_main()
