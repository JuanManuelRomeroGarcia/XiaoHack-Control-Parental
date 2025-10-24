# uninstall.py — XiaoHack (GUI completa, 2 fases y exclusión de self)
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

# --- AppUserModelID para que Windows use el icono de la app (barra de tareas) ---
try:
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("XiaoHack.Parental.Panel")
except Exception:
    pass

# --- logging básico (fallback si no tienes logs.py) ---
try:
    from logs import configure, get_logger, install_exception_hooks
    configure(level="INFO")
    install_exception_hooks("uninstall-crash")
    log = get_logger("xh.uninstall")
except Exception:
    import logging
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    log=logging.getLogger("xh.uninstall")

# --- deps opcionales ---
_has_tk=True
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, simpledialog
except Exception:
    _has_tk=False
try:
    import psutil # type: ignore
except Exception:
    psutil=None
    log.warning("psutil no disponible; instala con: venv\\Scripts\\python.exe -m pip install psutil")
try:
    import bcrypt # type: ignore
except Exception:
    bcrypt=None

# --- rutas / constantes ---
BASE_DIR      = Path(__file__).resolve().parent
CONFIG_PATH   = BASE_DIR / "config.json"
INSTALL_MARK  = BASE_DIR / "installed.json"
PROGRAMDATA   = Path(os.getenv("PROGRAMDATA", r"C:\ProgramData"))
COMMON_SM     = PROGRAMDATA / r"Microsoft\Windows\Start Menu\Programs"
COMMON_START  = PROGRAMDATA / r"Microsoft\Windows\Start Menu\Programs\StartUp"

TASKS = [r"XiaoHack\Guardian", r"XiaoHack\Notifier", r"XiaoHack\ControlParental", r"XiaoHackParental", r"Guardian", r"Notifier"]
MATCHES = ("--xh-role", "guardian.py", "notifier.py", "run.py", "webfilter.py", "dnsconfig.py")

KEEP_NAMES = {"uninstall.py", "uninstall.bat", "venv"}  # se conservan en 1ª fase

# --- utilidades ---
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def relaunch_as_admin():
    params = " ".join(f'"{a}"' for a in sys.argv)
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    sys.exit(0)

def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, creationflags=0x08000000)

def load_cfg():
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}

def uninstall_requires_pin(cfg): return bool(cfg.get("uninstall_requires_pin", True))

def verify_pin_gui(cfg):
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
    for t in TASKS:
        run(["schtasks","/End","/TN",t])
        run(["schtasks","/Delete","/TN",t,"/F"])

def safe_rmtree(path:Path, retries=8, delay=0.8):
    if not path.exists():
        return True
    for _ in range(retries):
        try:
            for root,dirs,files in os.walk(path, topdown=False):
                for n in files:
                    p = Path(root)/n
                    try: 
                        os.chmod(p, stat.S_IWRITE)
                    except Exception: 
                        pass
                for n in dirs:
                    d = Path(root)/n
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
        from webfilter import rollback_hosts
        rollback_hosts()
        return
    except Exception:
        pass
    # fallback por marcadores
    try:
        hosts=Path(r"C:\Windows\System32\drivers\etc\hosts")
        if hosts.exists():
            import re
            c=hosts.read_text(encoding="utf-8", errors="ignore")
            c=re.sub(r"\n?# === PARENTAL_BEGIN ===.*?# === PARENTAL_END ===\n?","\n",c, flags=re.S)
            hosts.write_text(c, encoding="utf-8")
    except Exception: 
        pass

def remove_shortcuts():
    for lnk in [
        COMMON_START/ "XiaoHack Notifier.lnk",
        COMMON_SM / "XiaoHack" / "XiaoHack Control Parental.lnk",
        COMMON_SM / "XiaoHack" / "Desinstalar XiaoHack.lnk",
        COMMON_SM / "XiaoHack Control Parental.lnk",
        Path(os.path.expandvars(r"%PUBLIC%\Desktop"))/"XiaoHack Parental.lnk",
        Path(os.path.expandvars(r"%USERPROFILE%\Desktop"))/"XiaoHack Parental.lnk",
        Path(os.path.expandvars(r"%PUBLIC%\Desktop"))/"XiaoHack Uninstall.lnk",
        Path(os.path.expandvars(r"%USERPROFILE%\Desktop"))/"XiaoHack Uninstall.lnk",
    ]:
        try: 
            lnk.unlink(missing_ok=True)
        except Exception: 
            pass

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

def kill_related(install_path:str, list_only=False):
    rows=[]
    if not psutil:
        return rows
    inst = install_path.lower()
    for p in psutil.process_iter(attrs=["pid","name","cmdline","exe","cwd"]):
        try:
            if _exclude_self(p):  # no nos disparamos al pie
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
        for pid,_,_ in rows:
            try:
                p=psutil.Process(pid)
                if p.is_running():
                    try:
                        p.kill()
                    except Exception: 
                        pass
            except Exception: 
                pass
    return rows

# ----------------------- borrado en dos fases ---------------------------------
def delete_folder_two_phase(install_path: str):
    root_dir = Path(install_path)
    # 1) Borra todo salvo KEEP_NAMES
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

    # 2) Crear post-cleanup que remata tras cerrar la GUI
    temp_bat = Path(tempfile.gettempdir()) / "xh_post_cleanup.bat"
    bat = f"""@echo off
timeout /t 2 >nul
cd /d "{install_path}"
rmdir /s /q venv
del /f /q uninstall.py
del /f /q uninstall.bat
cd /d "{root_dir.parent}"
rmdir /s /q "{install_path}"
"""
    temp_bat.write_text(bat, encoding="ascii")
    # Lanzamos el bat pero NO cerramos la GUI aún; el usuario puede revisar mensajes
    try:
        subprocess.Popen(['cmd','/c', str(temp_bat)], creationflags=0x08000000)
    except Exception as e:
        log.warning("No se pudo lanzar post-cleanup: %s", e)

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
        install_path = marker.get("install_path", str(BASE_DIR))
    except Exception:
        install_path = str(BASE_DIR)

        root = tk.Tk()
    root.title("Desinstalar XiaoHack")
    root.geometry("760x440")
    root.resizable(False, False)

    frm = ttk.Frame(root, padding=12)
    frm.pack(fill="both", expand=True)
    ttk.Label(frm, text=f"Carpeta de instalación: {install_path}").pack(anchor="w", pady=(0,6))

    cols=("PID","Nombre","Comando")
    tree=ttk.Treeview(frm, columns=cols, show="headings", height=11)
    for i,w in zip(cols,(80,120,520)):
        tree.heading(i, text=i)
        tree.column(i, width=w, anchor="w")
    tree.pack(fill="both", expand=True)

    status = tk.StringVar(value="Listo.")
    ttk.Label(frm, textvariable=status, anchor="w").pack(fill="x", pady=(8,0))

    btns = ttk.Frame(frm)
    btns.pack(fill="x", pady=8)

    def refresh():
        tree.delete(*tree.get_children())
        rows = kill_related(install_path, list_only=True)
        for pid,name,cmd in rows:
            tree.insert("", "end", values=(pid,name,cmd))
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

    # --- nueva fase 2: cleanup al cerrar ventana ---
    POST_BAT = Path(tempfile.gettempdir()) / "xh_post_cleanup.bat"
    def schedule_post_cleanup():
        bat = f"""@echo off
timeout /t 6 >nul
cd /d "{install_path}"
rmdir /s /q venv
del /f /q uninstall.py
del /f /q uninstall.bat
cd /d "{Path(install_path).parent}"
rmdir /s /q "{install_path}"
"""
        POST_BAT.write_text(bat, encoding="ascii")

    def delete_folder():
        # Fase 1: limpiar contenido y programar el post-cleanup
        stop_processes()
        stop_tasks()
        clean_shortcuts()
        revert_hosts_gui()
        status.set("Borrando contenido (fase 1)…")
        root.update_idletasks()
        delete_folder_two_phase(install_path)
        schedule_post_cleanup()
        messagebox.showinfo(
            "Fase 1 completada",
            "Se ha eliminado el contenido principal.\nAl cerrar esta ventana, se completará la limpieza final."
        )
        status.set("Fase 1 lista. Al cerrar se completará la limpieza final.")

    def on_close():
        try:
            if POST_BAT.exists():
                subprocess.Popen(["cmd", "/c", str(POST_BAT)], creationflags=0x08000000)
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

# --- fallback consola (corregido) ---
def console_main():
    if not is_admin():
        relaunch_as_admin()
    cfg = load_cfg()
    if uninstall_requires_pin(cfg):
        try:
            import getpass
            pin=getpass.getpass("PIN: ")
        except Exception:
            pin=""
        if not pin: 
            print("Abortado.")
            return
        stored=(cfg.get("parent_password_hash") or "").strip()
        if stored and bcrypt:
            try:
                if not bcrypt.checkpw(pin.encode(), stored.encode()):
                    print("PIN incorrecto.")
                    return
            except Exception:
                pass
        phrase=input("Escribe DESINSTALAR para confirmar: ").strip()
        if phrase!="DESINSTALAR":
            print("Cancelado.")
            return

    try:
        marker=json.loads(INSTALL_MARK.read_text(encoding="utf-8"))
        install_path=marker.get("install_path", str(BASE_DIR))
    except Exception:
        install_path=str(BASE_DIR)

    print("Cerrando tareas y procesos…")
    schtasks_stop_delete()
    kill_related(install_path, list_only=False)
    print("Revirtiendo hosts…")
    revert_hosts_if_possible()
    print("Eliminando accesos…")
    remove_shortcuts()
    print("Borrando contenido (fase 1)…") 
    # fase 1 consola
    root_dir = Path(install_path)
    for item in list(root_dir.iterdir()):
        if item.name in KEEP_NAMES: 
            continue
        try:
            safe_rmtree(item) if item.is_dir() else item.unlink(missing_ok=True)
        except Exception: 
            pass
    # post-cleanup
    temp_bat = Path(tempfile.gettempdir()) / "xh_post_cleanup.bat"
    temp_bat.write_text(f"""@echo off
timeout /t 2 >nul
cd /d "{install_path}"
rmdir /s /q venv
del /f /q uninstall.py
del /f /q uninstall.bat
cd /d "{root_dir.parent}"
rmdir /s /q "{install_path}"
""", encoding="ascii")
    subprocess.Popen(['cmd','/c', str(temp_bat)], creationflags=0x08000000)
    print("Fase 1 completada. Cierra esta consola para completar limpieza (post-cleanup en segundo plano).")

if __name__=="__main__":
    if _has_tk:
        gui_main()
    else:
        console_main()
