# xiao_gui/services.py — helpers para la GUI del Panel (tareas, updater, etc.)
from __future__ import annotations
import os
import json
import subprocess
import threading
from pathlib import Path
from tkinter import messagebox
# Helpers de runtime/rutas (proporcionados en utils/runtime.py)
from utils.runtime import (
    install_root,
    datadir_system,
    control_log_path,
    python_for_console,
    python_for_windowed,
    uninstaller_path,
    task_fullname_guardian,
    task_fullname_notifier,
)

from app.logs import get_logger
log = get_logger("gui.services")


# ---------------------------------------------------------------------------
# Descubrimiento de instalación (más exhaustivo; deja install_root() como fast-path)
# ---------------------------------------------------------------------------
def find_install_root() -> Path:
    """
    Busca la raíz de instalación del runtime.
    Orden:
      1) ENV XH_INSTALL_DIR
      2) installed.json cercano a este paquete
      3) ascenso de carpetas hasta hallar updater.py o VERSION
      4) install_root() (helper de runtime)
      5) cwd (fallback)
    """
    # 1) ENV
    inst = os.environ.get("XH_INSTALL_DIR", "").strip('" ').strip()
    if inst:
        p = Path(inst)
        if (p / "updater.py").exists() or (p / "VERSION").exists() or (p / "VERSION.json").exists(): 
            return p

    # 2) installed.json cerca de este paquete
    try:
        here = Path(__file__).resolve()
        for up in [here.parents[1], here.parents[2], here.parents[3]]:
            mk = up / "installed.json"
            if mk.exists():
                try:
                    data = json.loads(mk.read_text(encoding="utf-8", errors="ignore"))
                    ip = Path(data.get("install_path", ""))
                    if ip.exists():
                        return ip
                except Exception:
                    pass
    except Exception:
        pass

    # 3) ascenso
    try:
        p = Path(__file__).resolve()
        for _ in range(8):
            if (p / "updater.py").exists() or (p / "VERSION").exists() or (p / "VERSION.json").exists(): 
                return p
            if p.parent == p:
                break
            p = p.parent
    except Exception:
        pass

    # 4) helper de runtime
    try:
        p = install_root()
        if (p / "updater.py").exists() or (p / "VERSION").exists() or (p / "VERSION.json").exists():           
            return p
    except Exception:
        pass

    # 5) cwd
    return Path.cwd()


# ---------------------------------------------------------------------------
# Updater — chequeo no bloqueante y aplicación (con elevación si hace falta)
# ---------------------------------------------------------------------------
def check_update_and_maybe_apply_async(root_tk) -> None:
    """
    Lanza un hilo que:
      - ejecuta updater (como módulo si está en app/, como script si está en raíz)
      - si hay update, pregunta al tutor; si acepta, ejecuta --apply
    """
    def _run():
        base = find_install_root()

        py_console = Path(python_for_console())
        py_window  = Path(python_for_windowed())

        # ¿Está en app/? -> usamos -m app.updater
        cmd_check = [str(py_console), "-m", "app.updater", "--check"]
        cmd_apply = [str(py_window),  "-m", "app.updater", "--apply"]

        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"

        try:
            log.info("Updater --check: cmd=%s  cwd=%s", cmd_check, base)
            out = subprocess.check_output(
            cmd_check, stderr=subprocess.STDOUT, cwd=str(base), env=env, timeout=300,
            creationflags=0x08000000 
        )
            res = json.loads(out.decode("utf-8", "ignore"))

            if res.get("update_available"):
                latest = res.get("latest") or "desconocida"

                def _apply():
                    try:
                        log.info("Updater --apply: cmd=%s", cmd_apply)
                        subprocess.check_call(cmd_apply, cwd=str(base), env=env,
                                              creationflags=0x08000000
                                              )
                        messagebox.showinfo(
                            "Actualización",
                            "Actualización instalada correctamente.\nReinicia el Panel para ver los cambios."
                        )
                    except subprocess.CalledProcessError as e:
                        msg = (e.output or b"").decode("utf-8", "ignore")
                        messagebox.showerror("Actualización", f"No se pudo actualizar (rc={e.returncode}).\n{msg}")
                    except Exception as e:
                        messagebox.showerror("Actualización", f"No se pudo actualizar:\n{e}")

                def _ask():
                    if messagebox.askyesno(
                        "Actualización disponible",
                        f"Hay una nueva versión {latest}.\n¿Quieres instalarla ahora?"
                    ):
                        _apply()

                root_tk.after(0, _ask)

        except subprocess.CalledProcessError as e:
            msg = (e.output or b"").decode("utf-8", "ignore")
            rc  = e.returncode
            log.error("Updater --check falló: rc=%s out=%s", rc, msg)
            try:
                root_tk.after(0, lambda rc=rc, msg=msg: messagebox.showerror(
                    "Actualizaciones", f"Error: Updater falló (rc={rc}).\n{msg}"
                ))
            except Exception:
                pass
        except Exception as e:
            log.error("Updater sin salida: %s", e, exc_info=True)
            et, es = type(e).__name__, str(e)
            try:
                root_tk.after(0, lambda et=et, es=es: messagebox.showerror(
                    "Actualizaciones", f"Error: Updater sin salida ({et}: {es})."
                ))
            except Exception:
                pass

    threading.Thread(target=_run, daemon=True).start()


def auto_check_updates_once(root):
    """
    Chequeo no bloqueante: autodetecta si el updater va como módulo (-m app.updater)
    o como script (updater.py en raíz).
    """
    from utils.runtime import find_install_root, venv_executables
    import os
    import json
    import subprocess
    from pathlib import Path

    def _run():
        base = find_install_root(Path(__file__).resolve())

        py_console, py_window = venv_executables(base)


        cmd_check = [str(py_console), "-m", "app.updater", "--check"]
        cmd_apply = [str(py_window),  "-m", "app.updater", "--apply"]

        # Log del updater (por si algo falla)
        try:
            _logdir = Path(os.getenv("ProgramData", r"C:\ProgramData")) / "XiaoHackParental" / "logs"
            _logdir.mkdir(parents=True, exist_ok=True)
            gui_log = _logdir / "updater_gui.log"
        except Exception:
            gui_log = None

        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"

        def _write_log(line: str):
            log.info(line)
            try:
                if gui_log:
                    prev = gui_log.read_text(encoding="utf-8") if gui_log.exists() else ""
                    gui_log.write_text(prev + line + "\n", encoding="utf-8")
            except Exception:
                pass

        try:
            _write_log(f"[check] cmd={cmd_check} cwd={base}")
            out = subprocess.check_output(cmd_check, stderr=subprocess.STDOUT, cwd=str(base), env=env, timeout=180, creationflags=0x08000000)
            txt = out.decode("utf-8", "ignore")
            _write_log(f"[check] stdout:\n{txt}")
            res = json.loads(txt)

            if res.get("update_available"):
                latest = res.get("latest") or "desconocida"

                def _apply():
                    try:
                        _write_log(f"[apply] cmd={cmd_apply}")
                        subprocess.check_call(cmd_apply, cwd=str(base), env=env, creationflags=0x08000000)
                        messagebox.showinfo(
                            "Actualización",
                            "Actualización instalada correctamente.\nReinicia el Panel para ver los cambios."
                        )
                        _write_log("[apply] OK")
                    except subprocess.CalledProcessError as e:
                        msg = (e.output or b"").decode("utf-8", "ignore") if hasattr(e, "output") else str(e)
                        _write_log(f"[apply] ERROR rc={getattr(e,'returncode',None)}\n{msg}")
                        messagebox.showerror("Actualización", f"No se pudo actualizar (rc={getattr(e,'returncode',None)}):\n{msg}")
                    except Exception as e:
                        _write_log(f"[apply] ERROR gen: {e!r}")
                        messagebox.showerror("Actualización", f"No se pudo actualizar:\n{e}")

                root.after(0, lambda: (
                    messagebox.askyesno("Actualización disponible",
                                        f"Hay una nueva versión {latest}.\n¿Quieres instalarla ahora?")
                    and _apply()
                ))

        except subprocess.CalledProcessError as e:
            msg = (e.output or b"").decode("utf-8", "ignore") if hasattr(e, "output") else ""
            rc = getattr(e, "returncode", None)
            _write_log(f"[check] ERROR rc={rc}\n{msg}")
            try:
                messagebox.showerror("Actualizaciones", f"El updater falló (rc={rc}).\n\nSalida:\n{msg}")
            except Exception:
                pass
        except json.JSONDecodeError as e:
            _txt = locals().get("txt", "")
            _write_log(f"[check] JSON inválido: {e}\nRAW:\n{_txt}")
            try:
                messagebox.showerror("Actualizaciones", "El updater devolvió una respuesta no válida.\nRevisa updater_gui.log")
            except Exception:
                pass
        except Exception as e:
            _write_log(f"[check] ERROR gen: {e!r}")
            try:
                messagebox.showerror("Actualizaciones", f"Error ejecutando el updater:\n{e}")
            except Exception:
                pass

    threading.Thread(target=_run, daemon=True).start()



def run_updater_apply_ui() -> None:
    """Lanza la aplicación del update (UI-friendly) como módulo, sin exigir updater.py físico."""
    base = find_install_root()
    pyw = Path(python_for_windowed())
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    try:
        subprocess.check_call(
            [str(pyw), "-m", "app.updater", "--apply"],
            cwd=str(base),
            env=env,
            creationflags=0x08000000
        )
        messagebox.showinfo(
            "Actualización",
            "Actualización instalada correctamente.\nReinicia el Panel para ver los cambios."
        )
    except subprocess.CalledProcessError as e:
        msg = (getattr(e, "output", b"") or b"").decode("utf-8", "ignore")
        messagebox.showerror("Actualización", f"No se pudo actualizar (rc={e.returncode}).\n{msg}")
    except Exception as e:
        messagebox.showerror("Actualización", f"No se pudo actualizar:\n{e}")



# ---------------------------------------------------------------------------
# Uninstaller
# ---------------------------------------------------------------------------
def launch_uninstaller_ui() -> None:
    """
    Lanza el desinstalador (elevará si hace falta).
    """
    base = find_install_root()
    uni = uninstaller_path()
    if not uni.exists():
        messagebox.showerror("Desinstalar", f"No se encontró uninstall.py en:\n{uni}")
        return

    py_window = Path(python_for_windowed())
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    try:
        subprocess.Popen([str(py_window), str(uni)], cwd=str(base), env=env, creationflags=0x08000000)
    except Exception as e:
        messagebox.showerror("Desinstalar", f"No se pudo iniciar el desinstalador:\n{e}")


# ---------------------------------------------------------------------------
# Tareas programadas: consulta y control (Guardian / Notifier)
# ---------------------------------------------------------------------------
def _query_task_fullname(kind: str) -> str:
    if kind.lower() == "guardian":
        return task_fullname_guardian()
    if kind.lower() == "notifier":
        return task_fullname_notifier()
    return kind  # nombre literal

def query_task_state(kind_or_fullname: str) -> dict:
    """
    Devuelve un dict con la información de schtasks /Query /V /FO LIST
    { 'Exists': bool, 'State': 'Running/Ready/…', 'Next Run Time': '…', ... }
    """
    name = _query_task_fullname(kind_or_fullname)
    try:
        cp = subprocess.run(
            ["schtasks", "/Query", "/TN", name, "/FO", "LIST", "/V"],
            capture_output=True, text=True, creationflags=0x08000000
        )
        out = (cp.stdout or "") + (cp.stderr or "")
        if "ERROR:" in out and cp.returncode:
            return {"Exists": False, "Raw": out}
        info = {"Exists": True, "Raw": out}
        for line in out.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                info[k.strip()] = v.strip()
        return info
    except Exception as e:
        return {"Exists": False, "Error": str(e)}

def start_service(kind_or_fullname: str) -> bool:
    """
    Intenta arrancar la tarea (p.ej., 'guardian' → XiaoHackParental\\Guardian).
    """
    name = _query_task_fullname(kind_or_fullname)
    try:
        cp = subprocess.run(["schtasks", "/Run", "/TN", name], capture_output=True, text=True, creationflags=0x08000000)
        if cp.returncode == 0:
            log.info("Tarea iniciada: %s", name)
            return True
        log.warning("schtasks /Run rc=%s out=%s err=%s", cp.returncode, cp.stdout, cp.stderr)
        return False
    except Exception as e:
        log.error("start_service error: %s", e)
        return False

def stop_service(kind_or_fullname: str) -> bool:
    """
    Intenta detener la tarea (best-effort).
    """
    name = _query_task_fullname(kind_or_fullname)
    try:
        cp = subprocess.run(["schtasks", "/End", "/TN", name], capture_output=True, text=True, creationflags=0x08000000)
        if cp.returncode == 0:
            log.info("Tarea detenida: %s", name)
            return True
        log.warning("schtasks /End rc=%s out=%s err=%s", cp.returncode, cp.stdout, cp.stderr)
        return False
    except Exception as e:
        log.error("stop_service error: %s", e)
        return False


# ---------------------------------------------------------------------------
# Utilidades varias
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Notifier (overlay de bloqueos): estado / iniciar / detener
# ---------------------------------------------------------------------------
def _find_notifier_script() -> Path:
    """Busca notifier.py en la instalación (raíz o app/), similar a updater_path()."""
    root = find_install_root()
    cand = [root / "notifier.py", root / "app" / "notifier.py"]
    for c in cand:
        if c.exists():
            return c
    return cand[0]

def notifier_status() -> dict:
    """
    Devuelve {'exists': bool, 'running': bool, 'pids': [..]}.
    Usa psutil si está; si no, tasklist como fallback.
    """
    script = _find_notifier_script()
    exists = script.exists()
    running = False
    pids = []

    try:
        import psutil  # type: ignore
        for p in psutil.process_iter(attrs=["pid","name","cmdline"]):
            try:
                cmd = " ".join(p.info.get("cmdline") or [])
                if "--xh-role" in cmd and "notifier" in cmd.lower():
                    running = True
                    pids.append(p.info["pid"])
                elif "notifier.py" in cmd.replace("\\", "/").lower():
                    running = True
                    pids.append(p.info["pid"])
            except Exception:
                continue
        return {"exists": exists, "running": running, "pids": pids}
    except Exception:
        # Fallback sin psutil
        try:
            out = subprocess.check_output(["tasklist", "/FO", "CSV"], text=True, creationflags=0x08000000)
            for line in out.splitlines():
                l1 = line.lower()
                if "pythonw.exe" in l1 or "python.exe" in l1:
                    if "notifier" in l1:
                        running = True
                        # no tenemos PID fiable en este fallback sin parseo completo
                        break
        except Exception:
            pass
        return {"exists": exists, "running": running, "pids": pids}

def start_notifier() -> bool:
    """Lanza el Notifier en segundo plano con pythonw.exe."""
    script = _find_notifier_script()
    if not script.exists():
        return False
    pyw = Path(python_for_windowed())
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    try:
        subprocess.Popen([str(pyw), str(script), "--xh-role", "notifier"], cwd=str(find_install_root()),
                         env=env, creationflags=0x08000000)
        return True
    except Exception:
        return False

def stop_notifier() -> bool:
    """Intenta terminar cualquier proceso del Notifier."""
    ok = False
    try:
        import psutil  # type: ignore
        for p in psutil.process_iter(attrs=["pid","name","cmdline"]):
            try:
                cmd = " ".join(p.info.get("cmdline") or [])
                if ("--xh-role" in cmd and "notifier" in cmd.lower()) or ("notifier.py" in cmd.lower()):
                    try:
                        p.terminate()
                        ok = True
                    except Exception:
                        pass
            except Exception:
                continue
        return ok
    except Exception:
        # Fallback best-effort: mata pythonw con filtro de ventana no fiable (evitamos).
        # Devolvemos False para no dar falsa sensación.
        return False


def open_logs_folder():
    """Abre la carpeta de logs del sistema (ProgramData\\XiaoHackParental\\logs)."""
    try:
        import webbrowser
        logs_dir = datadir_system() / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        webbrowser.open(str(logs_dir))
    except Exception as e:
        log.error("open_logs_folder error: %s", e)

def open_control_log():
    """Abre el archivo control.log con el visor por defecto."""
    try:
        import webbrowser
        webbrowser.open(str(control_log_path()))
    except Exception as e:
        log.error("open_control_log error: %s", e)
