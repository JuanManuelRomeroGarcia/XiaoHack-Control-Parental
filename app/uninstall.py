# uninstall.py — XiaoHack (GUI completa, 2 fases, limpieza ProgramData/LocalAppData y exclusión de self)
from __future__ import annotations
import importlib.util
import os
import sys
import json
import shutil
import ctypes
import stat
from textwrap import shorten
import time
import subprocess
import tempfile
from pathlib import Path
import logging

# === Bootstrap portable (py312) — antes de usar tkinter =======================
try:
    _pydir = os.path.dirname(sys.executable)  # ...\py312 cuando usamos embebido
    try:
        os.add_dll_directory(_pydir)  # asegura carga de tcl/tk DLLs
        os.add_dll_directory(os.path.join(_pydir, "DLLs"))
    except Exception:
        pass
    os.environ.setdefault("TCL_LIBRARY", os.path.join(_pydir, "tcl", "tcl8.6"))
    os.environ.setdefault("TK_LIBRARY",  os.path.join(_pydir, "tcl", "tk8.6"))
except Exception:
    pass
# ============================================================================

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
    # Mensaje ajustado para portable
    log.warning("psutil no disponible; instala con: \"%s\" -m pip install psutil", sys.executable)
try:
    import bcrypt  # type: ignore
except Exception:
    bcrypt = None

# --- RUTAS / POLÍTICA NUEVA ---
PROGRAM_FILES = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
PROGRAM_DATA  = Path(os.environ.get("ProgramData",  r"C:\ProgramData"))

APP_NAME      = "XiaoHackParental"

INSTALL_DIR   = Path(__file__).resolve().parents[1]       # %ProgramFiles%\XiaoHackParental
DATA_DIR_SYS  = PROGRAM_DATA / APP_NAME                   # %ProgramData%\XiaoHackParental

# Config “real” ahora vive en ProgramData:
CONFIG_PATH   = DATA_DIR_SYS / "config.json"
# Marker opcional (si existe):
INSTALL_MARK  = INSTALL_DIR / "installed.json"

# Accesos comunes y escritorio
PROGRAMS_COMMON = PROGRAM_DATA / r"Microsoft\Windows\Start Menu\Programs"
LNK_MENU_DIR    = PROGRAMS_COMMON / "XiaoHack Control Parental"
LNK_MENU_PANEL  = LNK_MENU_DIR / "XiaoHack Control Parental.lnk"
LNK_MENU_UNINST = LNK_MENU_DIR / "Desinstalar XiaoHack Control Parental.lnk"
PUBLIC_DESKTOP  = Path(os.environ.get("PUBLIC", r"C:\Users\Public")) / "Desktop"
USER_DESKTOP    = Path(os.environ.get("USERPROFILE", "")) / "Desktop"
LNK_DESK_PANEL_PUB  = PUBLIC_DESKTOP / "XiaoHack Control Parental.lnk"
LNK_DESK_UNINST_PUB = PUBLIC_DESKTOP / "XiaoHack Control Uninstall.lnk"
LNK_DESK_PANEL_USER  = USER_DESKTOP / "XiaoHack Control Parental.lnk"
LNK_DESK_UNINST_USER = USER_DESKTOP / "XiaoHack Control Uninstall.lnk"

COMMON_START  = PROGRAM_DATA / r"Microsoft\Windows\Start Menu\Programs\StartUp"  # por compat

# Tareas programadas (nueva y heredadas)
TASKS = [
    r"XiaoHackParental\Guardian",     # NUEVA
    r"XiaoHackParental\Notificador",
    r"XiaoHack\Guardian", r"XiaoHack\Notificador", r"XiaoHack\Notifier",
    r"XiaoHack\ControlParental",
    r"XiaoHackParental", r"Guardian", r"Notifier", r"Notificador",
    r"XiaoHack_FinalCleanup",
]

# Patrones para localizar procesos asociados
MATCHES = ("--xh-role", "guardian.py", "notifier.py", "run.py", "webfilter.py", "dnsconfig.py")

# No borrar en fase 1 (se rematan en fase 2)
# Cambiamos 'venv' -> 'py312' para portable
KEEP_NAMES = {"uninstall.py", "uninstall.bat", "py312"}

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

def _ensure_admin_or_relaunch():
    """
    Si no somos admin, relanza el mismo módulo con elevación UAC y sale del proceso actual.
    """ 
    try:
        if ctypes.windll.shell32.IsUserAnAdmin():
            return
    except Exception:
        return  # si falla la detección, seguimos (mejor que bloquear)

    exe = sys.executable  # pythonw.exe embebido (py312)
    params = "-m app.uninstall --elevated 1"
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        sys.exit(0)
    except Exception:
        pass  # si no podemos elevar, seguimos (mostrará errores de permisos si los hay)
    
def _module_exists(modname: str) -> bool:
    try:
        return importlib.util.find_spec(modname) is not None
    except Exception:
        return False

def _safe_log_info(prefix: str, cp) -> None:
    out = shorten((cp.stdout or "").strip(), width=160)
    err = shorten((cp.stderr or "").strip(), width=160)
    log.info("%s rc=%s out=%s err=%s", prefix, cp.returncode, out, err)

def run(cmd, timeout=None):
    """
    Ejecuta un proceso oculto, capturando salida como texto UTF-8 con sustitución.
    Evita UnicodeDecodeError en máquinas con codepage OEM/ANSI.
    """
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

    # 2) Barrido amplio con PowerShell
    ps = r'''
try {
  $ts = Get-ScheduledTask | Where-Object {
    $_.TaskName -like '*XiaoHack*' -or
    $_.TaskPath -like '\XiaoHack*' -or
    $_.TaskName -like '*Guardian*' -or
    $_.TaskName -like '*Notifier*' -or
    $_.TaskName -like '*Notificador*'
  }
  foreach ($t in $ts) {
    try { Stop-ScheduledTask       -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue } catch {}
    try { Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false -ErrorAction SilentlyContinue } catch {}
  }
  'OK'
} catch { 'ERR' }
'''
    try:
        run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps])
    except Exception:
        pass
    
def schtasks_stop_delete_all():
    """
    Elimina cualquier tarea relacionada con XiaoHack/Guardian/Notifier en cualquier ruta.
    También elimina 'XiaoHack_FinalCleanup' heredada de versiones anteriores del uninstaller.
    """
    for name in ("\\XiaoHackParental\\Guardian", "\\XiaoHackParental\\Notificador", "XiaoHack_FinalCleanup"):
        run(["schtasks", "/End", "/TN", name])
        run(["schtasks", "/Delete", "/TN", name, "/F"])

    ps = r'''
try {
  $ts = Get-ScheduledTask | Where-Object {
    $_.TaskName -like '*XiaoHack*' -or
    $_.TaskPath -like '\XiaoHack*' -or
    $_.TaskName -like '*Guardian*' -or
    $_.TaskName -like '*Notifier*' -or
    $_.TaskName -like '*Notificador*'
  }
  foreach ($t in $ts) {
    try { Stop-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue } catch {}
    try { Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false -ErrorAction SilentlyContinue } catch {}
  }
  'OK'
} catch { 'ERR' }
'''
    run(["powershell","-NoProfile","-ExecutionPolicy","Bypass","-Command", ps])

def _ps_ex_list(exclude_pids: set[int] | None) -> str:
    return ",".join(str(p) for p in sorted(exclude_pids or set()))

def kill_xh_processes(exclude_pids: set[int] | None = None):
    """
    Mata guardian/notifier sin tocar el desinstalador (app.uninstall) y respetando exclude_pids.
    Usa WMI (Win32_Process) para poder filtrar por CommandLine.
    """
    ex = set(exclude_pids or set())
    ex.add(os.getpid())
    ex |= SELF_PARENTS
    ex |= SELF_CHILDREN
    ex_list = _ps_ex_list(ex)

    ps = f'''
$ex    = @({ex_list})
$hasEx = $ex.Count -gt 0
$procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {{
  $exe = (($_.ExecutablePath) + '')
  $cmd = (($_.CommandLine) + '')
  $pid = $_.ProcessId
  $isXH  = ($exe -like '*\\XiaoHackParental\\*') -or ($cmd -like '*\\XiaoHackParental\\*')
  $role  = ($cmd -match '--xh-role\\s+(guardian|notifier)') -or
           ($cmd -match 'app\\.guardian') -or
           ($cmd -match 'app\\.notifier') -or
           ($cmd -match 'run_guardian')  -or
           ($cmd -match 'run_notifier')
  $isUninstall = ($cmd -match 'app\\.uninstall')
  $ok = $isXH -and $role -and (-not $isUninstall)
  if ($hasEx) {{ $ok = $ok -and ($ex -notcontains $pid) }}
  $ok
}}
foreach ($p in $procs) {{ try {{ Stop-Process -Id $p.ProcessId -Force }} catch {{}} }}
"OK"
'''.strip()
    run(["powershell","-NoProfile","-ExecutionPolicy","Bypass","-Command", ps])

def close_all_logs():
    """Cierra manejadores de logging (libera %ProgramData%\...\logs\control.log)."""
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
        LNK_DESK_PANEL_PUB, LNK_DESK_UNINST_PUB,
        LNK_DESK_PANEL_USER, LNK_DESK_UNINST_USER,
        LNK_MENU_PANEL, LNK_MENU_UNINST,
        PROGRAMS_COMMON / "XiaoHack Parental.lnk",  # restos antiguos
        PROGRAMS_COMMON / "XiaoHack" / "XiaoHack Control Parental.lnk",
        PROGRAMS_COMMON / "XiaoHack" / "Desinstalar XiaoHack.lnk",
        COMMON_START / "XiaoHack Notifier.lnk",
        COMMON_START / "XiaoHackParental Notifier.lnk",
        COMMON_START / "XiaoHack Control Parental Notifier.lnk",
    ]:
        try:
            lnk.unlink(missing_ok=True)
        except Exception:
            pass
    try:
        if LNK_MENU_DIR.exists() and not any(LNK_MENU_DIR.iterdir()):
            LNK_MENU_DIR.rmdir()
    except Exception:
        pass

def restore_dns_auto():
    """Devuelve los DNS a automático (DHCP) para todas las interfaces."""
    if _module_exists("app.dnsconfig"):
        try:
            from app import dnsconfig
            ok, msg = dnsconfig.set_dns_auto(interface_alias=None)
            log.info("[dns] Auto vía módulo: %s", msg or ("OK" if ok else ""))
            return
        except Exception as e:
            log.warning("[dns] Módulo dnsconfig falló: %s. Fallback PS…", e)
    else:
        log.info("[dns] Módulo app.dnsconfig no empaquetado. Fallback PS…")

    ps = r'''
$ifaces = Get-DnsClient | Where-Object { $_.AddressFamily -in ('IPv4','IPv6') }
foreach ($i in $ifaces) {
  try { Set-DnsClientServerAddress -InterfaceIndex $i.InterfaceIndex -ResetServerAddresses -ErrorAction Stop } catch {}
}
"OK"
'''
    cp = run(["PowerShell","-NoProfile","-ExecutionPolicy","Bypass","-Command", ps])
    _safe_log_info("[dns] Auto (fallback PS)", cp)

def clear_doh_policies():
    """Quita políticas DoH de Brave y Chrome (HKCU/HKLM)."""
    did_brave = False
    if _module_exists("app.braveconfig"):
        try:
            from app import braveconfig
            ok, msg = braveconfig.clear_brave_policy(scope="BOTH")
            log.info("[doh] Brave vía módulo: %s", msg or ("OK" if ok else ""))
            did_brave = True
        except Exception as e:
            log.warning("[doh] braveconfig falló: %s. Fallback PS…", e)
    else:
        log.info("[doh] app.braveconfig no empaquetado. Fallback PS…")

    did_chrome = False
    if _module_exists("app.chromeconfig"):
        try:
            from app import chromeconfig
            ok, msg = chromeconfig.clear_chrome_policy(scope="BOTH")
            log.info("[doh] Chrome vía módulo: %s", msg or ("OK" if ok else ""))
            did_chrome = True
        except Exception as e:
            log.warning("[doh] chromeconfig falló: %s. Fallback PS…", e)
    else:
        log.info("[doh] app.chromeconfig no empaquetado. Fallback PS…")

    if not (did_brave and did_chrome):
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
        cp = run(["PowerShell","-NoProfile","-ExecutionPolicy","Bypass","-Command", ps])
        _safe_log_info("[doh] Fallback PS", cp)

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

# NUEVO: marcado de borrado en arranque (sin tareas programadas)
MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004
def _movefileex_delete_on_reboot(path: str) -> bool:
    """Marca un archivo o directorio para borrado en el próximo arranque."""
    try:
        k32 = ctypes.windll.kernel32
        from ctypes import wintypes
        k32.MoveFileExW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
        k32.MoveFileExW.restype = wintypes.BOOL
        # Prefijo \\?\ para rutas largas/Unicode
        p = "\\\\?\\" + path
        return bool(k32.MoveFileExW(p, None, MOVEFILE_DELAY_UNTIL_REBOOT))
    except Exception as e:
        log.debug("MoveFileExW failed for %s: %s", path, e)
        return False

def mark_tree_for_delete_on_reboot(root: str | Path) -> int:
    """
    Recorre el árbol y marca archivos y carpetas para borrado al reiniciar.
    Devuelve el número de elementos marcados.
    """
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
    except Exception as e:
        log.debug("mark_tree_for_delete_on_reboot error: %s", e)
    return count

def _write_post_cleanup_bat(install_path: str):
    """
    Phase 2 desde %TEMP% (ASCII-only BAT, UTF-8):
      - Kill procesos que apunten a install path.
      - Quita atributos, takeown/icacls.
      - Borra ficheros duros (guardian.db*, control.log, uninstall*).
      - Remove-Item + rmdir con reintentos.
      - **SIN** programar ninguna tarea: si quedan restos, se marcarán para borrado al reiniciar desde Python.
    """
    post_bat = Path(tempfile.gettempdir()) / "xh_post_cleanup.bat"
    progdata = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "XiaoHackParental")
    install  = str(install_path)

    bat = f"""@echo off
setlocal enableextensions
pushd "%TEMP%" >nul 2>&1

rem --- kill leftover processes pointing to install path ---
powershell -NoProfile -ExecutionPolicy Bypass -Command "$b='{install}'.ToLower(); Get-CimInstance Win32_Process | ?{{ (($_.ExecutablePath+'') -and $_.ExecutablePath.ToLower().StartsWith($b)) -or (($_.CommandLine+'').ToLower().Contains($b)) }} | %%{{ try {{ Stop-Process -Id $_.ProcessId -Force }} catch {{}} }}" >nul 2>&1
ping 127.0.0.1 -n 3 >nul

set "SIDADM=S-1-5-32-544"

for %%D in ("{progdata}" "{install}") do call :CLEAN "%%~fD"
goto :EOF

:CLEAN
set "_TARGET=%~1"
if not exist "%_TARGET%" exit /b 0

attrib -r -s -h "%_TARGET%\\*" /s /d >nul 2>&1

for /l %%i in (1 1 8) do (
  if exist "%_TARGET%" (
    takeown /f "%_TARGET%" /r /d y >nul 2>&1
    icacls "%_TARGET%" /grant "*%SIDADM%:(OI)(CI)F" /t /c /q >nul 2>&1

    del /f /q "%_TARGET%\\guardian.db"       >nul 2>&1
    del /f /q "%_TARGET%\\guardian.db-wal"   >nul 2>&1
    del /f /q "%_TARGET%\\guardian.db-shm"   >nul 2>&1
    del /f /q "%_TARGET%\\logs\\control.log" >nul 2>&1
    del /f /q "%_TARGET%\\uninstall*"        >nul 2>&1

    powershell -NoProfile -ExecutionPolicy Bypass -Command "Remove-Item -LiteralPath '%_TARGET%' -Recurse -Force -ErrorAction SilentlyContinue" >nul 2>&1
    rmdir /s /q "%_TARGET%" >nul 2>&1
    if exist "%_TARGET%" ping 127.0.0.1 -n 2 >nul
  )
)
exit /b 0
"""
    try:
        post_bat.write_text(bat, encoding="utf-8", newline="\r\n")
        log.info("post-bat OK -> %s (%d bytes)", post_bat, post_bat.stat().st_size)
    except Exception as e:
        log.error("post-bat write failed: %s", e)
    return post_bat

def _launch_post_cleanup(post_bat_path: str, install_path: str):
    """
    Ejecuta el BAT si existe. **Sin** programar tarea.
    Si falla, ejecuta un PowerShell inline de limpieza sin tareas.
    """
    try:
        p = Path(post_bat_path)
        sz = p.stat().st_size if p.exists() else 0
    except Exception:
        sz = 0

    if sz >= 64:
        try:
            subprocess.Popen(["cmd", "/c", f'"{post_bat_path}"'], creationflags=0x08000000)
            return
        except Exception as e:
            log.warning("post-bat exec failed: %s", e)

    progdata = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "XiaoHackParental")
    install  = str(install_path)
    ps = rf'''
$b = "{install}".ToLower()
try {{
  Get-CimInstance Win32_Process | ?{{ (($_.ExecutablePath+'') -and $_.ExecutablePath.ToLower().StartsWith($b)) -or (($_.CommandLine+'').ToLower().Contains($b)) }} |
    %%{{ try {{ Stop-Process -Id $_.ProcessId -Force }} catch {{}} }}
}} catch {{}}
$paths = @("{progdata}","{install}")
foreach ($t in $paths) {{
  if (-not (Test-Path $t)) {{ continue }}
  try {{ attrib -r -s -h "$t\*" /s /d }} catch {{}}
  for ($i=0; $i -lt 8; $i++) {{
    try {{ takeown /f "$t" /r /d y | Out-Null }} catch {{}}
    try {{ icacls "$t" /grant "*S-1-5-32-544:(OI)(CI)F" /t /c /q | Out-Null }} catch {{}}
    foreach ($f in @("guardian.db","guardian.db-wal","guardian.db-shm","logs\\control.log")) {{
      try {{ Remove-Item -LiteralPath (Join-Path $t $f) -Force -ErrorAction SilentlyContinue }} catch {{}}
    }}
    try {{ Remove-Item -LiteralPath $t -Recurse -Force -ErrorAction SilentlyContinue }} catch {{}}
    if (Test-Path $t) {{ Start-Sleep -Milliseconds 800 }} else {{ break }}
  }}
}}
'''
    try:
        subprocess.Popen(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-Command", ps],
            creationflags=0x08000000
        )
    except Exception as e:
        log.error("Fallback PS inline failed: %s", e)

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
        except Exception as e:
            log.debug("No se pudo borrar %s: %s", item, e)

# --- GUI principal ---
def gui_main():
    _ensure_admin_or_relaunch()

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
    root.title("Desinstalador Control Parental XiaoHack")
    root.geometry("780x480")
    root.resizable(True, True)

    frm = ttk.Frame(root, padding=12)
    frm.pack(fill="both", expand=True)
    ttk.Label(frm, text=f"Carpeta de instalación: {install_path}").pack(anchor="w", pady=(0, 6))
    ttk.Label(frm, text=f"Datos (sistema): {DATA_DIR_SYS}").pack(anchor="w")

    cols = ("PID", "Nombre", "Comando")
    tree = ttk.Treeview(frm, columns=cols, show="headings", height=11)
    for i, w in zip(cols, (80, 80, 520)):
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
        kill_xh_processes()
        time.sleep(0.6)
        refresh()
        status.set("Procesos cerrados (si había).")

    def stop_tasks():
        status.set("Eliminando tareas programadas…")
        root.update_idletasks()
        schtasks_stop_delete_all()
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

        status.set("Cerrando procesos…")
        root.update_idletasks()
        stop_processes()

        status.set("Eliminando tareas programadas…")
        root.update_idletasks()
        stop_tasks()

        status.set("Cerrando logs…")
        root.update_idletasks()
        close_all_logs()

        status.set("Eliminando accesos directos…")
        root.update_idletasks()
        clean_shortcuts()

        status.set("Revirtiendo hosts…")
        root.update_idletasks()
        revert_hosts_gui()

        status.set("Limpiando políticas DoH (Brave/Chrome)…")
        root.update_idletasks()
        clear_doh_policies()

        status.set("Restaurando DNS a automático…")
        root.update_idletasks()
        restore_dns_auto()

        status.set("Borrando contenido (fase 1)…")
        root.update_idletasks()
        delete_folder_two_phase(install_path)

        # Fase 2: post-cleanup (sin tareas)
        POST_BAT = _write_post_cleanup_bat(install_path)
        try:
            _launch_post_cleanup(POST_BAT, install_path)
        except Exception as e:
            log.warning("No se pudo ejecutar post-cleanup: %s", e)

        # Comprobación tras un breve margen y, si quedan restos, marcar para borrado al reiniciar.
        root.after(800, lambda: None)
        root.update_idletasks()
        time.sleep(0.8)

        still_exists = any(Path(p).exists() for p in (DATA_DIR_SYS, Path(install_path)))
        if still_exists:
            n = 0
            if Path(install_path).exists():
                n += mark_tree_for_delete_on_reboot(install_path)
            if DATA_DIR_SYS.exists():
                n += mark_tree_for_delete_on_reboot(DATA_DIR_SYS)
            log.info("Marcados %d elementos para borrado al reiniciar.", n)
            status.set("Limpieza pendiente marcada para el próximo arranque (sin tareas).")
            messagebox.showinfo(
                "Limpieza programada al reiniciar",
                "Se han marcado los restos para borrarse en el próximo arranque del sistema.\n"
                "No se ha creado ninguna tarea programada."
            )
        else:
            status.set("Limpieza completada.")
            messagebox.showinfo("Completado", "Se ha eliminado XiaoHack Parental correctamente.")

        root.after(200, root.destroy)

    def on_close():
        try:
            if POST_BAT and Path(POST_BAT).exists():
                _launch_post_cleanup(POST_BAT, install_path)
        except Exception as e:
            log.warning("No se pudo ejecutar post-cleanup en cierre: %s", e)
        root.destroy()

    ttk.Button(btns, text="🔄 Refrescar", command=refresh).pack(side="left")
    ttk.Button(btns, text="✖ Cerrar procesos", command=stop_processes).pack(side="left", padx=6)
    ttk.Button(btns, text="🕑 Eliminar tareas", command=stop_tasks).pack(side="left", padx=6)
    ttk.Button(btns, text="🧹 Quitar accesos", command=clean_shortcuts).pack(side="left", padx=6)
    ttk.Button(btns, text="🛡 Hosts revert", command=revert_hosts_gui).pack(side="left", padx=6)
    ttk.Button(btns, text="🗂️ Borrar carpeta", command=delete_folder).pack(side="left", padx=6)
    ttk.Button(btns, text="Salir", command=on_close).pack(side="right")
    
    root.protocol("WM_DELETE_WINDOW", on_close)
    refresh()
    root.mainloop()

# --- fallback consola ---
def console_main():
    _ensure_admin_or_relaunch()

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
    schtasks_stop_delete_all()
    kill_xh_processes()
    close_all_logs()
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

    POST_BAT = _write_post_cleanup_bat(install_path)
    try:
        _launch_post_cleanup(POST_BAT, install_path)
    except Exception:
        pass

    time.sleep(0.8)
    remaining = []
    if Path(install_path).exists():
        remaining.append(install_path)
    if DATA_DIR_SYS.exists():
        remaining.append(str(DATA_DIR_SYS))

    if remaining:
        total = 0
        for p in remaining:
            total += mark_tree_for_delete_on_reboot(p)
        print(f"Quedan restos. Marcados {total} elementos para borrado al reiniciar (sin tareas).")
    else:
        print("Limpieza completada.")

    print("Puedes cerrar esta ventana.")
    
if __name__ == "__main__":
    if _HAS_TK:
        gui_main()
    else:
        console_main()
