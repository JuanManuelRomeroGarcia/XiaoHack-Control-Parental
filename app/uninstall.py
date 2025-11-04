# uninstall.py — XiaoHack (GUI completa, 2 fases, limpieza ProgramData/LocalAppData y exclusión de self)
from __future__ import annotations
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

# --- AppUserModelID para icono correcto en barra de tareas ---
try:
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("XiaoHack.Parental.Panel")
except Exception:
    pass

# --- logging básico (usa logs.py si está) ---
try:
    from app.logs import configure, get_logger, install_exception_hooks
    configure(level="INFO")
    install_exception_hooks("uninstall-crash")
    log = get_logger("xh.uninstall")
except Exception:
    import logging
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    log = logging.getLogger("xh.uninstall")

# --- deps opcionales ---
_HAS_TK = True
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, simpledialog
except Exception:
    _HAS_TK = False
try:
    import psutil  # type: ignore
except Exception:
    psutil = None
    log.warning("psutil no disponible; instala con: venv\\Scripts\\python.exe -m pip install psutil")
try:
    import bcrypt  # type: ignore
except Exception:
    bcrypt = None

# --- RUTAS / POLÍTICA NUEVA ---
PROGRAM_FILES = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
PROGRAM_DATA  = Path(os.environ.get("ProgramData",  r"C:\ProgramData"))

APP_NAME      = "XiaoHackParental"

INSTALL_DIR   = Path(__file__).resolve().parent                     # %ProgramFiles%\XiaoHackParental
DATA_DIR_SYS  = PROGRAM_DATA / APP_NAME                             # %ProgramData%\XiaoHackParental        

# Config “real” ahora vive en ProgramData:
CONFIG_PATH   = DATA_DIR_SYS / "config.json"
# Marker opcional (si existe):
INSTALL_MARK  = INSTALL_DIR / "installed.json"

# Accesos comunes y escritorio
PROGRAMS_COMMON = PROGRAM_DATA / r"Microsoft\Windows\Start Menu\Programs"
LNK_MENU_DIR    = PROGRAMS_COMMON / "XiaoHack Parental"
LNK_MENU_PANEL  = LNK_MENU_DIR / "XiaoHack Parental.lnk"
LNK_MENU_UNINST = LNK_MENU_DIR / "Desinstalar XiaoHack Parental.lnk"
PUBLIC_DESKTOP  = Path(os.environ.get("PUBLIC", r"C:\Users\Public")) / "Desktop"
USER_DESKTOP    = Path(os.environ.get("USERPROFILE", "")) / "Desktop"
LNK_DESK_PANEL_PUB  = PUBLIC_DESKTOP / "XiaoHack Parental.lnk"
LNK_DESK_UNINST_PUB = PUBLIC_DESKTOP / "XiaoHack Uninstall.lnk"
LNK_DESK_PANEL_USER  = USER_DESKTOP / "XiaoHack Parental.lnk"
LNK_DESK_UNINST_USER = USER_DESKTOP / "XiaoHack Uninstall.lnk"

COMMON_START  = PROGRAM_DATA / r"Microsoft\Windows\Start Menu\Programs\StartUp"  # por compat

# Tareas programadas (nueva y heredadas)
TASKS = [
    r"XiaoHackParental\Guardian",     # NUEVA
    r"XiaoHack\Guardian", r"XiaoHack\Notifier", r"XiaoHack\ControlParental",
    r"XiaoHackParental", r"Guardian", r"Notifier"
]

# Patrones para localizar procesos asociados
MATCHES = ("--xh-role", "guardian.py", "notifier.py", "run.py", "webfilter.py", "dnsconfig.py")

# No borrar en fase 1 (se rematan en fase 2)
KEEP_NAMES = {"uninstall.py", "uninstall.bat", "venv"}

# -------------------------------------------------------------------
# Utilidades
# -------------------------------------------------------------------
def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def relaunch_as_admin():
    params = " ".join(f'"{a}"' for a in sys.argv)
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    sys.exit(0)

def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, creationflags=0x08000000)
    except Exception as e:
        log.debug("run(%s) error: %s", cmd, e)

def load_cfg() -> dict:
    try:
        if CONFIG_PATH.exists():
            return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}

def uninstall_requires_pin(cfg: dict) -> bool:
    return bool(cfg.get("uninstall_requires_pin", True))

def verify_pin_gui(cfg: dict) -> bool:
    pin = simpledialog.askstring("Desinstalar XiaoHack", "Introduce el PIN del tutor:", show="*")
    if not pin:
        return False
    stored = (cfg.get("parent_password_hash") or "").strip()
    if stored and bcrypt:
        try:
            if bcrypt.checkpw(pin.encode(), stored.encode()):
                return True
            messagebox.showerror("PIN incorrecto", "El PIN no coincide.")
            return False
        except Exception:
            pass
    phrase = simpledialog.askstring("Confirmación", "Escribe EXACTAMENTE: DESINSTALAR")
    if phrase != "DESINSTALAR":
        messagebox.showwarning("Cancelado", "No se confirmó la desinstalación.")
        return False
    plain = (cfg.get("parent_password_plain") or "").strip()
    return (not plain) or (pin == plain)

def schtasks_stop_delete():
    # 1) Intento directo sobre nombres conocidos (por compat)
    for t in TASKS:
        run(["schtasks", "/End", "/TN", t])
        run(["schtasks", "/Delete", "/TN", t, "/F"])

    # 2) Barrido amplio con PowerShell: cualquier tarea que huela a XiaoHack,
    # Guardian o Notifier (incluye nombres personalizados).
    ps = r'''
try {
  $ts = Get-ScheduledTask | Where-Object {
    $_.TaskName -like '*XiaoHack*' -or
    $_.TaskPath -like '\XiaoHack*' -or
    $_.TaskName -like '*Guardian*' -or
    $_.TaskName -like '*Notifier*'
  }
  foreach ($t in $ts) {
    try { Stop-ScheduledTask     -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue } catch {}
    try { Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false -ErrorAction SilentlyContinue } catch {}
  }
  'OK'
} catch { 'ERR' }
'''
    try:
        run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps])
    except Exception:
        pass

def safe_rmtree(path: Path, retries=8, delay=0.8) -> bool:
    if not path.exists():
        return True
    for _ in range(retries):
        try:
            for root, dirs, files in os.walk(path, topdown=False):
                for n in files:
                    p = Path(root) / n
                    try:
                        os.chmod(p, stat.S_IWRITE)
                    except Exception:
                        pass
                for n in dirs:
                    d = Path(root) / n
                    try:
                        os.chmod(d, stat.S_IWRITE)
                    except Exception:
                        pass
            shutil.rmtree(path, ignore_errors=False)
            return True
        except Exception as e:
            log.debug("safe_rmtree retry: %s", e)
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
    # fallback por marcadores
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
    for lnk in [
        # Escritorio público y del usuario
        LNK_DESK_PANEL_PUB, LNK_DESK_UNINST_PUB,
        LNK_DESK_PANEL_USER, LNK_DESK_UNINST_USER,
        # Menú Inicio (directo y antiguo)
        LNK_MENU_PANEL, LNK_MENU_UNINST,
        PROGRAMS_COMMON / "XiaoHack Control Parental.lnk",
        PROGRAMS_COMMON / "XiaoHack" / "XiaoHack Control Parental.lnk",
        PROGRAMS_COMMON / "XiaoHack" / "Desinstalar XiaoHack.lnk",
        # Startup (por compat)
        COMMON_START / "XiaoHack Notifier.lnk",
        COMMON_START / "XiaoHackParental Notifier.lnk",
    ]:
        try:
            lnk.unlink(missing_ok=True)
        except Exception:
            pass
    # Directorio del menú si queda vacío
    try:
        if LNK_MENU_DIR.exists() and not any(LNK_MENU_DIR.iterdir()):
            LNK_MENU_DIR.rmdir()
    except Exception:
        pass
    
def restore_dns_auto():
    """
    Devuelve los DNS a automático (DHCP) para todas las interfaces.
    Intenta vía app.dnsconfig; si no está disponible, usa PowerShell.
    """
    try:
        from app.dnsconfig import set_dns_auto
        ok, msg = set_dns_auto(interface_alias=None)  # None => todas (en nuestra impl)
        log.info("[dns] Auto via app.dnsconfig: %s", msg or ("OK" if ok else ""))
        return
    except Exception as e:
        log.info("[dns] app.dnsconfig no disponible (%s). Usando fallback PS…", e)

    ps = r'''
$ifaces = Get-DnsClient | Where-Object { $_.AddressFamily -in ('IPv4','IPv6') }
foreach ($i in $ifaces) {
  try {
    Set-DnsClientServerAddress -InterfaceIndex $i.InterfaceIndex -ResetServerAddresses -ErrorAction Stop
  } catch { }
}
"OK"
'''
    try:
        cp = subprocess.run(["PowerShell","-NoProfile","-ExecutionPolicy","Bypass","-Command", ps],
                            capture_output=True, text=True, creationflags=0x08000000)
        log.info("[dns] Auto (fallback PS) rc=%s out=%s err=%s", cp.returncode, (cp.stdout or "").strip(), (cp.stderr or "").strip())
    except Exception as e:
        log.warning("[dns] Fallback PS error: %s", e)


def clear_doh_policies():
    """
    Quita políticas DoH de Brave y Chrome (HKCU/HKLM).
    Primero intenta nuestras APIs; si no, hace fallback por registro.
    """
    # 1) APIs si están
    tried_any = False
    try:
        from app.braveconfig import clear_brave_policy
        ok, msg = clear_brave_policy(scope="BOTH")
        log.info("[doh] Brave clear via API: %s", msg or ("OK" if ok else ""))
        tried_any = True
    except Exception as e:
        log.info("[doh] braveconfig no disponible (%s).", e)

    try:
        from app.chromeconfig import clear_chrome_policy
        ok, msg = clear_chrome_policy(scope="BOTH")
        log.info("[doh] Chrome clear via API: %s", msg or ("OK" if ok else ""))
        tried_any = True
    except Exception as e:
        log.info("[doh] chromeconfig no disponible (%s).", e)

    if tried_any:
        return

    # 2) Fallback por registro (HKCU/HKLM)
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
    try:
        cp = subprocess.run(["PowerShell","-NoProfile","-ExecutionPolicy","Bypass","-Command", ps],
                            capture_output=True, text=True, creationflags=0x08000000)
        log.info("[doh] Fallback PS rc=%s out=%s err=%s", cp.returncode, (cp.stdout or "").strip(), (cp.stderr or "").strip())
    except Exception as e:
        log.warning("[doh] Fallback PS error: %s", e)  

# --------- cierre de procesos con exclusión del propio desinstalador ----------
SELF_PID = os.getpid()
SELF_PARENTS = set()
SELF_CHILDREN = set()
try:
    if psutil:
        proc_self = psutil.Process(SELF_PID)
        SELF_PARENTS = {p.pid for p in proc_self.parents()}
        SELF_CHILDREN = {p.pid for p in proc_self.children(recursive=True)}
except Exception:
    pass

def _exclude_self(p):
    return p.pid in (SELF_PID,) or p.pid in SELF_PARENTS or p.pid in SELF_CHILDREN

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
            hit = (inst in cmd.lower()) or (inst in exe) or (inst in cwd) or any(m in cmd.lower() for m in MATCHES)
            if hit:
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
                p = psutil.Process(pid)
                if p.is_running():
                    try:
                        p.kill()
                    except Exception:
                        pass
            except Exception:
                pass
    return rows

# ----------------------- borrado en dos fases ---------------------------------
def _write_post_cleanup_bat(install_path: str):
    r"""
    Post-limpieza robusta y silenciosa:
      - Se ejecuta desde %TEMP% (evita locks de CWD).
      - Borra %ProgramData%\XiaoHackParental.
      - Borra la carpeta de instalación completa.
      - NO toca LOCALAPPDATA.
      - Reintenta varias veces y no muestra mensajes.
    """
    post_bat = Path(tempfile.gettempdir()) / "xh_post_cleanup.bat"
    progdata = str(DATA_DIR_SYS)         # C:\ProgramData\XiaoHackParental
    install  = str(install_path)         # C:\Program Files\XiaoHackParental

    bat = f"""@echo off
setlocal enableextensions
REM Ir a TEMP para no tener CWD en la carpeta a borrar
pushd "%TEMP%" >nul 2>&1

REM Esperar a que pythonw.exe termine del todo
ping 127.0.0.1 -n 6 >nul

REM ---- ProgramData ----
for /l %%i in (1,1,3) do (
  if exist "{progdata}" rmdir /s /q "{progdata}" >nul 2>&1
  if exist "{progdata}" ping 127.0.0.1 -n 2 >nul
)

REM ---- Carpeta de instalación ----
for /l %%i in (1,1,6) do (
  if exist "{install}" rmdir /s /q "{install}" >nul 2>&1
  if exist "{install}" ping 127.0.0.1 -n 2 >nul
)

popd >nul 2>&1
exit /b 0
"""
    try:
        post_bat.write_text(bat, encoding="ascii")
    except Exception:
        pass
    return post_bat



def delete_folder_two_phase(install_path: str):
    root_dir = Path(install_path)
    # 1) borrar todo menos KEEP_NAMES
    for item in list(root_dir.iterdir()):
        if item.name in KEEP_NAMES:
            continue
        try:
            if item.is_dir():
                safe_rmtree(item)
            else:
                item.unlink(missing_ok=True)
        except Exception as e:
            log.debug("No se pudo borrar %s: %s", item, e)

# --- GUI principal ---
def gui_main():
    if not is_admin():
        relaunch_as_admin()

    cfg = load_cfg()
    if uninstall_requires_pin(cfg):
        if not verify_pin_gui(cfg):
            return

    try:
        marker = json.loads(INSTALL_MARK.read_text(encoding="utf-8"))
        install_path = marker.get("install_path", str(INSTALL_DIR))
    except Exception:
        install_path = str(INSTALL_DIR)

    root = tk.Tk()
    root.title("Desinstalar XiaoHack")
    root.geometry("780x480")
    root.resizable(False, False)

    frm = ttk.Frame(root, padding=12)
    frm.pack(fill="both", expand=True)
    ttk.Label(frm, text=f"Carpeta de instalación: {install_path}").pack(anchor="w", pady=(0, 6))
    ttk.Label(frm, text=f"Datos (sistema): {DATA_DIR_SYS}").pack(anchor="w")

    cols = ("PID", "Nombre", "Comando")
    tree = ttk.Treeview(frm, columns=cols, show="headings", height=11)
    for i, w in zip(cols, (80, 120, 520)):
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
        status.set("Cerrando procesos…")
        root.update_idletasks()
        kill_related(install_path, list_only=False)
        time.sleep(0.5)
        refresh()
        status.set("Procesos cerrados (si había).")

    def stop_tasks():
        status.set("Eliminando tareas programadas…")
        root.update_idletasks()
        schtasks_stop_delete()
        status.set("Tareas programadas eliminadas.")

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
        stop_processes()
        stop_tasks()
        clean_shortcuts()
        revert_hosts_gui()
        status.set("Borrando contenido (fase 1)…")
        root.update_idletasks()
        delete_folder_two_phase(install_path)
        POST_BAT = _write_post_cleanup_bat(install_path)
        messagebox.showinfo(
            "Fase 1 completada",
            "Se ha eliminado el contenido principal.\n"
            "Al cerrar esta ventana, se completará la limpieza final (incluye ProgramData y LocalAppData)."
        )
        status.set("Limpiando políticas DoH (Brave/Chrome)…")
        root.update_idletasks()
        clear_doh_policies()

        status.set("Restaurando DNS a automático…")
        root.update_idletasks()
        restore_dns_auto()

        status.set("Fase 1 lista. Al cerrar se completará la limpieza final.")

    def on_close():
        try:
            if POST_BAT and Path(POST_BAT).exists():
                subprocess.Popen(["cmd", "/c", f'"{POST_BAT}"'], creationflags=0x08000000)
        except Exception as e:
            log.warning("No se pudo ejecutar post-cleanup: %s", e)
        root.destroy()

    ttk.Button(btns, text="🔄 Refrescar", command=refresh).pack(side="left")
    ttk.Button(btns, text="✖ Cerrar procesos", command=stop_processes).pack(side="left", padx=6)
    ttk.Button(btns, text="🕑 Eliminar tareas", command=stop_tasks).pack(side="left", padx=6)
    ttk.Button(btns, text="🗂️ Borrar carpeta", command=delete_folder).pack(side="left", padx=6)
    ttk.Button(btns, text="🧹 Quitar accesos", command=clean_shortcuts).pack(side="left", padx=6)
    ttk.Button(btns, text="🛡 Hosts revert", command=revert_hosts_gui).pack(side="left", padx=6)
    ttk.Button(btns, text="Salir", command=on_close).pack(side="right")

    root.protocol("WM_DELETE_WINDOW", on_close)
    refresh()
    root.mainloop()

# --- fallback consola ---
def console_main():
    if not is_admin():
        relaunch_as_admin()

    cfg = load_cfg()
    if uninstall_requires_pin(cfg):
        try:
            import getpass
            pin = getpass.getpass("PIN: ")
        except Exception:
            pin = ""
        if not pin:
            print("Abortado.")
            return
        stored = (cfg.get("parent_password_hash") or "").strip()
        if stored and bcrypt:
            try:
                if not bcrypt.checkpw(pin.encode(), stored.encode()):
                    print("PIN incorrecto.")
                    return
            except Exception:
                pass
        phrase = input("Escribe DESINSTALAR para confirmar: ").strip()
        if phrase != "DESINSTALAR":
            print("Cancelado.")
            return

    try:
        marker = json.loads(INSTALL_MARK.read_text(encoding="utf-8"))
        install_path = marker.get("install_path", str(INSTALL_DIR))
    except Exception:
        install_path = str(INSTALL_DIR)

    print("Cerrando tareas y procesos…")
    schtasks_stop_delete()
    kill_related(install_path, list_only=False)

    print("Revirtiendo hosts…")
    revert_hosts_if_possible()

    print("Eliminando accesos…")
    remove_shortcuts()
    
    print("Limpiando políticas DoH (Brave/Chrome)…")
    clear_doh_policies()

    print("Restaurando DNS a automático…")
    restore_dns_auto()


    print("Borrando contenido (fase 1)…")
    root_dir = Path(install_path)
    for item in list(root_dir.iterdir()):
        if item.name in KEEP_NAMES:
            continue
        try:
            safe_rmtree(item) if item.is_dir() else item.unlink(missing_ok=True)
        except Exception:
            pass

    # post-cleanup
    post_bat = _write_post_cleanup_bat(install_path)
    try:
        subprocess.Popen(['cmd', '/c', f'"{post_bat}"'], creationflags=0x08000000)
    except Exception:
        pass

    print("Fase 1 completada. Cierra esta consola para completar limpieza (se hará en segundo plano).")

if __name__ == "__main__":
    if _HAS_TK:
        gui_main()
    else:
        console_main()
