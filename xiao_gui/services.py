# xiao_gui/services.py — helpers para la GUI del Panel (tareas, updater, etc.)
from __future__ import annotations
import os
import json
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
import time
from tkinter import messagebox
# Helpers de runtime/rutas (proporcionados en utils/runtime.py)
from utils.runtime import (
    install_root,
    datadir_system,
    python_for_console,
    python_for_windowed,
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
      3) ascenso de carpetas hasta hallar app/ o VERSION(.json)
      4) install_root() (helper de runtime)
      5) cwd (fallback)
    """
    # 1) ENV
    inst = os.environ.get("XH_INSTALL_DIR", "").strip('" ').strip()
    if inst:
        p = Path(inst)
        if (p / "app").is_dir() or (p / "VERSION").exists() or (p / "VERSION.json").exists():
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
            if (p / "app").is_dir() or (p / "VERSION").exists() or (p / "VERSION.json").exists():
                return p
            if p.parent == p:
                break
            p = p.parent
    except Exception:
        pass

    # 4) helper de runtime
    try:
        p = install_root()
        if (p / "app").is_dir() or (p / "VERSION").exists() or (p / "VERSION.json").exists():
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
    Chequeo no bloqueante: autodetecta si el updater va como módulo (-m app.updater).
    """
    import json
    import subprocess
    from pathlib import Path

    def _run():
        base = find_install_root()  # ← antes pasaba un Path inválido
        py_console = Path(python_for_console())
        py_window  = Path(python_for_windowed())

        cmd_check = [str(py_console), "-m", "app.updater", "--check"]
        cmd_apply = [str(py_window),  "-m", "app.updater", "--apply"]

        # Log del updater (por si algo falla)
        try:
            _logdir = datadir_system() / "logs"
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
            out = subprocess.check_output(
                cmd_check, stderr=subprocess.STDOUT, cwd=str(base), env=env,
                timeout=180, creationflags=0x08000000
            )
            txt = out.decode("utf-8", "ignore")
            _write_log(f"[check] stdout:\n{txt}")
            res = json.loads(txt)

            if res.get("update_available"):
                latest = res.get("latest") or "desconocida"

                def _apply():
                    try:
                        _write_log(f"[apply] cmd={cmd_apply}")
                        subprocess.check_call(
                            cmd_apply, cwd=str(base), env=env,
                            creationflags=0x08000000
                        )
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
    """
    Aplica la actualización (sin ventana) y, al terminar, muestra:
    'Actualizada — ¿Relanzar ahora?'. Si aceptas, relanza y cierra este panel.
    """
    base = find_install_root()

    pyw = Path(python_for_windowed())  # venv\Scripts\pythonw.exe (sin consola)
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    # Modo manual: el updater NO cierra ni relanza; solo aplica y deja resultado
    env["XH_MANUAL_RELAUNCH"] = "1"

    # Identidad del panel y plan de relanzado (mismos args que ahora)
    env["XH_GUI_PID"] = str(os.getpid())
    env["XH_GUI_EXE"] = sys.executable
    run_py = base / "run.py"
    env["XH_GUI_SCRIPT"] = str(run_py) if run_py.exists() else ""
    try:
        env["XH_GUI_ARGS_JSON"] = json.dumps(sys.argv[1:], ensure_ascii=False)
    except Exception:
        env["XH_GUI_ARGS_JSON"] = "[]"

    # Ejecutar updater y esperar (sin ventana)
    try:
        subprocess.check_call(
            [str(pyw), "-m", "app.updater", "--apply"],
            cwd=str(base),
            env=env,
            creationflags=0x08000000,  # CREATE_NO_WINDOW
        )
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Actualización", f"No se pudo actualizar (rc={e.returncode}).")
        return
    except Exception as e:
        messagebox.showerror("Actualización", f"No se pudo actualizar:\n{e}")
        return

    # Leer resultado para mostrar versión destino (si existe)
    latest = None
    try:
        from utils.runtime import datadir_system
        res_path = (datadir_system() / "logs" / "updater_result.json")
        if res_path.exists():
            data = json.loads(res_path.read_text(encoding="utf-8", errors="ignore"))
            latest = data.get("latest")
    except Exception:
        pass

    ver_txt = f" a la versión {latest}" if latest else ""
    if messagebox.askyesno("Actualización instalada",
                           f"Se ha actualizado{ver_txt}.\n\n¿Relanzar el Panel ahora?"):
        # Relanzar con los mismos parámetros del acceso directo
        try:
            args = json.loads(env.get("XH_GUI_ARGS_JSON", "[]"))
        except Exception:
            args = sys.argv[1:]
        cmd = [str(pyw)]
        if run_py.exists():
            cmd += [str(run_py)] + list(args)
        else:
            cmd += ["-m", "xiao_gui.app"]
        subprocess.Popen(cmd, cwd=str(base), creationflags=0x08000000)
        os._exit(0)  # cerrar este proceso GUI
    else:
        messagebox.showinfo("Actualización", "Podrás abrir el Panel más tarde desde el acceso directo.")


# ---------------------------------------------------------------------------
# Uninstaller (rutas nuevas y fallback)
# ---------------------------------------------------------------------------
def launch_uninstaller_ui() -> None:
    """
    Lanza el desinstalador con pythonw -m app.uninstall (sin consola).
    Tras lanzarlo, cierra el Panel para liberar el intérprete/archivos.
    """

    base = find_install_root()
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"

    try:
        pyw = Path(python_for_windowed())
    except Exception:
        pyw = None

    if pyw and pyw.exists():
        # CREATE_NO_WINDOW por si algún entorno cae en python.exe
        CREATE_NO_WINDOW = 0x08000000
        subprocess.Popen([str(pyw), "-m", "app.uninstall"],
                         cwd=str(base), env=env, creationflags=CREATE_NO_WINDOW)
    else:
        messagebox.showerror(
            "Desinstalar",
            "No se encontró el desinstalador.\nReinstala con el instalador actual y vuelve a intentarlo."
        )
        return

    # Cerrar el Panel (si existe UI Tk activa)
    try:
        import tkinter as tk
        root = tk._default_root
        if root is not None:
            root.after(50, root.destroy)
    except Exception:
        pass



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
    Considera python.exe/pythonw.exe con '-m app.notifier' o 'notifier.py',
    filtrado al USUARIO ACTUAL.
    """
    root = find_install_root()
    bat = root / "run_notifier.bat"
    exists = bat.exists()
    running = False
    pids = []

    try:
        import psutil
        import getpass  # type: ignore
        me = getpass.getuser().lower()
        for p in psutil.process_iter(attrs=["pid","name","username","cmdline"]):
            try:
                user = (p.info.get("username") or "").lower()
                if user and (me not in user):
                    continue  # solo sesión actual
                name = (p.info.get("name") or "").lower()
                if name not in ("python.exe", "pythonw.exe"):
                    continue
                cmd = " ".join(p.info.get("cmdline") or []).lower().replace("\\", "/")
                if ("-m app.notifier" in cmd) or ("/app/notifier.py" in cmd) or (" notifier.py" in cmd):
                    running = True
                    pids.append(int(p.info["pid"]))
            except Exception:
                continue
    except Exception:
        # Fallback muy básico sin psutil:
        try:
            out = subprocess.check_output(["tasklist", "/FO", "CSV"], text=True, creationflags=0x08000000)
            for line in out.splitlines():
                l1 = line.lower()
                if ("pythonw.exe" in l1 or "python.exe" in l1) and "notifier" in l1:
                    running = True
                    break
        except Exception:
            pass

    return {"exists": exists, "running": running, "pids": pids}

def start_notifier() -> bool:
    """
    Lanza el Notifier vía run_notifier.bat (oculto, sesión actual),
    sin tocar APPDATA/LOCALAPPDATA.
    """
    root = find_install_root()
    bat = root / "run_notifier.bat"
    if not bat.exists():
        log.error("run_notifier.bat no existe: %s", bat)
        return False

    comspec = os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe")
    try:
        subprocess.Popen([comspec, "/c", str(bat)],
                         cwd=str(root),
                         creationflags=0x08000000,  # CREATE_NO_WINDOW
                         close_fds=True)
    except Exception as e:
        log.error("start_notifier Popen error: %s", e)
        return False

    # pequeña espera y verificación
    for _ in range(10):
        time.sleep(0.2)
        if notifier_status().get("running"):
            return True
    return False

def stop_notifier() -> bool:
    """
    Termina cualquier Notifier de la sesión actual (pythonw/python con '-m app.notifier' o 'notifier.py').
    """
    ok_any = False
    try:
        import psutil
        import getpass  # type: ignore
        me = getpass.getuser().lower()
        targets = []
        for p in psutil.process_iter(attrs=["pid","name","username","cmdline"]):
            try:
                user = (p.info.get("username") or "").lower()
                if user and (me not in user):
                    continue
                name = (p.info.get("name") or "").lower()
                if name not in ("python.exe", "pythonw.exe"):
                    continue
                cmd = " ".join(p.info.get("cmdline") or []).lower().replace("\\", "/")
                if ("-m app.notifier" in cmd) or ("/app/notifier.py" in cmd) or (" notifier.py" in cmd):
                    targets.append(p)
            except Exception:
                continue

        for p in targets:
            try:
                p.terminate()
            except Exception:
                pass
        gone, alive = psutil.wait_procs(targets, timeout=2.0)
        for p in alive:
            try:
                p.kill()
            except Exception:
                pass
        ok_any = bool(gone) and not alive

    except Exception as e:
        log.warning("stop_notifier psutil fallback: %s", e)
        # Fallback best-effort (puede matar otros python del usuario, ÚSALO solo si hace falta)
        try:
            subprocess.run(["taskkill", "/F", "/IM", "pythonw.exe"], capture_output=True, text=True, creationflags=0x08000000)
            subprocess.run(["taskkill", "/F", "/IM", "python.exe"],  capture_output=True, text=True, creationflags=0x08000000)
        except Exception:
            pass

    # Comprobar estado final
    time.sleep(0.3)
    return not notifier_status().get("running", False) or ok_any



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
    """
    Abre ProgramData\XiaoHackParental\logs\control.log con el visor por defecto.
    Crea el fichero si no existe.
    """
    try:
        p = datadir_system() / "logs" / "control.log"
        p.parent.mkdir(parents=True, exist_ok=True)
        if not p.exists():
            p.write_text("", encoding="utf-8")
        os.startfile(str(p))
    except Exception as e:
        log.error("open_control_log error: %s", e)
        raise

def diagnose_notifications(auto_fix: bool = False) -> dict:
    """
    Ejecuta un runner temporal con python.exe que añade la INSTALL_DIR a sys.path
    y llama a app.notifier.diagnose_notification_env(...).
    Devuelve: { ok, rc, stdout, stderr, data(dict|None) }.
    """
    import os
    import json
    import subprocess
    import tempfile
    from pathlib import Path
    from utils.runtime import find_install_root, python_for_console

    base = Path(find_install_root())  # p.ej. C:\Program Files\XiaoHackParental
    py = python_for_console()

    # Forzar consola (python.exe), nunca pythonw.exe
    try:
        p = Path(py)
        if p.name.lower() == "pythonw.exe":
            py = str(p.with_name("python.exe"))
    except Exception:
        pass
    if not py or not os.path.exists(py):
        cand = base / "venv" / "Scripts" / "python.exe"
        py = str(cand)

    # Runner: añade la ruta de instalación a sys.path y ejecuta el diagnóstico
    base_str = str(base)  # sin barra final
    code = (
        "import sys, json\n"
        f"sys.path.insert(0, r'{base_str}')\n"
        "from app.notifier import diagnose_notification_env\n"
        f"print(json.dumps(diagnose_notification_env(auto_fix={str(bool(auto_fix))}), ensure_ascii=False))\n"
    )

    tmp_script = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as fh:
            fh.write(code)
            tmp_script = fh.name

        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"

        CREATE_NO_WINDOW = 0x08000000
        proc = subprocess.run(
            [py, "-X", "utf8", tmp_script],
            cwd=str(base),                    # no imprescindible, pero coherente
            env=env,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=12,
            creationflags=CREATE_NO_WINDOW,
        )
    except Exception as e:
        return {"ok": False, "rc": None, "stdout": "", "stderr": str(e), "data": None}
    finally:
        if tmp_script:
            try:
                os.remove(tmp_script)
            except Exception:
                pass

    out = proc.stdout or ""
    err = proc.stderr or ""
    data = None
    if out.strip():
        try:
            data = json.loads(out)
        except Exception:
            data = None

    return {"ok": proc.returncode == 0, "rc": proc.returncode, "stdout": out, "stderr": err, "data": data}

def notifier_test_toast() -> dict:
    """
    Lanza: pythonw -m app.notifier --test
    Devuelve { ok, rc, stdout, stderr }.
    """
    base = Path(find_install_root())
    py_console = Path(python_for_console())

    # Preferimos pythonw.exe para que no parpadee consola
    if py_console.name.lower() == "python.exe":
        pyw = py_console.with_name("pythonw.exe")
    else:
        pyw = py_console
    if not pyw.exists():
        pyw = base / "venv" / "Scripts" / "pythonw.exe"

    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"

    CREATE_NO_WINDOW = 0x08000000
    try:
        proc = subprocess.run(
            [str(pyw), "-m", "app.notifier", "--test"],
            cwd=str(base),
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=CREATE_NO_WINDOW,
        )
    except Exception as e:
        return {"ok": False, "rc": None, "stdout": "", "stderr": str(e)}
    return {"ok": proc.returncode == 0, "rc": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}

def notifier_regenerate_aumid() -> dict:
    """
    Ejecuta un runner temporal que llama a:
      ensure_aumid_ready(); diagnose_notification_env()
    Devuelve { ok, rc, stdout, stderr, data } donde data es el dict del diagnóstico.
    """
    base = Path(find_install_root())
    py = Path(python_for_console())
    if py.name.lower() == "pythonw.exe":
        py = py.with_name("python.exe")
    if not py.exists():
        py = base / "venv" / "Scripts" / "python.exe"

    code = (
        "import sys, json\n"
        f"sys.path.insert(0, r'{str(base)}')\n"
        "from app.notifier import ensure_aumid_ready, diagnose_notification_env\n"
        "ensure_aumid_ready()\n"
        "print(json.dumps(diagnose_notification_env(auto_fix=False), ensure_ascii=False))\n"
    )

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as fh:
            fh.write(code)
            tmp_path = fh.name

        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"

        CREATE_NO_WINDOW = 0x08000000
        proc = subprocess.run(
            [str(py), "-X", "utf8", tmp_path],
            cwd=str(base),
            env=env,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            creationflags=CREATE_NO_WINDOW,
        )
    except Exception as e:
        return {"ok": False, "rc": None, "stdout": "", "stderr": str(e), "data": None}
    finally:
        if tmp_path:
            try:
                os.remove(tmp_path)
            except Exception:
                pass

    out = proc.stdout or ""
    err = proc.stderr or ""
    data = None
    if out.strip():
        try:
            data = json.loads(out)
        except Exception:
            data = None
    return {"ok": proc.returncode == 0, "rc": proc.returncode, "stdout": out, "stderr": err, "data": data}