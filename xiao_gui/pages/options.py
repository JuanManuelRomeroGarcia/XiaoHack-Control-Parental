# xiao_gui/pages/options.py — XiaoHack GUI: pestaña Opciones (revisado)
import json
import os
import sys  # noqa: F401
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path  # noqa: F401

from logs import get_logger
from utils.tk_safe import after_safe
from xiao_gui.services import restart_guardian

# Conservamos los imports pero ya no dependemos de ellos para lo crítico;
# dejamos el fallback interno con schtasks por robustez.
try:
    from ..services import (
        query_task_state, start_service, stop_service, open_task_scheduler,
        query_notifier_state, start_notifier, stop_notifier, restart_notifier, open_notifier_log
    )
except Exception:
    query_task_state = start_service = stop_service = open_task_scheduler = None
    query_notifier_state = start_notifier = stop_notifier = restart_notifier = open_notifier_log = None

from ..dialogs import set_new_pin_hash

try:
    from utils.async_tasks import TaskGate, submit_limited
except Exception:
    from concurrent.futures import ThreadPoolExecutor
    _EXEC = ThreadPoolExecutor(max_workers=2)
    class TaskGate:
        def __init__(self): self._rev = 0
        def next_rev(self):
            self._rev += 1
            return self._rev
        def is_current(self, rev): return rev == self._rev
    def submit_limited(fn, *a, **k): return _EXEC.submit(fn, *a, **k)

log = get_logger("gui.options")

# ----------------- Constantes / helpers locales -----------------
TASK_PATH = "\\XiaoHackParental\\"
TASK_BARE = "Guardian"
TASK_NOTIFIER = "Notificador"

def _task_full_name_for_schtasks() -> str:
    # schtasks espera "Carpeta\Nombre" sin barra doble inicial
    return f"{TASK_PATH.strip('\\\\')}\\{TASK_BARE}"

def _task_full_name_notif() -> str:
    return f"{TASK_PATH.strip('\\\\')}\\{TASK_NOTIFIER}"

def _run(*cmd):
    """Ejecuta un proceso en silencio y devuelve (rc,out,err)."""
    p = subprocess.run(cmd, capture_output=True, text=True, creationflags=0x08000000)
    return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()

def _install_dir(cfg: dict) -> str:
    # Usamos el valor de config si viene; si no, ProgramData fijo
    d = (cfg or {}).get("install_path")
    if d and os.path.isdir(d):
        return d
    return os.path.join(os.getenv("ProgramData", r"C:\ProgramData"), "XiaoHackParental")

def _venv_python(cfg: dict) -> str:
    return os.path.join(_install_dir(cfg), "venv", "Scripts", "python.exe")

def _run_guardian_bat(cfg: dict) -> str:
    return os.path.join(_install_dir(cfg), "run_guardian.bat")

def _xh_root() -> Path:
    # raíz del runtime (donde está updater.py y VERSION)
    return Path(__file__).resolve().parents[2]

def _read_version() -> str:
    try:
        return (_xh_root() / "VERSION").read_text(encoding="utf-8").strip()
    except Exception:
        return "0.0.0"

def _python_exe() -> str:
    # usa el mismo intérprete que corre la app (pythonw.exe/ python.exe del venv)
    return sys.executable or str(_xh_root() / "venv" / "Scripts" / "python.exe")

def _run_updater(args):
    """Ejecuta updater.py y devuelve el JSON como dict."""
    up = str(_xh_root() / "updater.py")
    cmd = [_python_exe(), up] + args
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=300)
        return json.loads(out.decode("utf-8", "ignore"))
    except subprocess.CalledProcessError as e:
        try:
            return json.loads(e.output.decode("utf-8", "ignore"))
        except Exception:
            return {"error": f"Updater fallo: {e}"}
    except Exception as e:
        return {"error": str(e)}

# ---------- Guardian: consultas/acciones de tarea ----------
def _query_task_state_local() -> str:
    tn = _task_full_name_for_schtasks()
    rc, out, err = _run("schtasks", "/Query", "/TN", tn, "/V", "/FO", "LIST")
    if rc != 0:
        return "No instalada"

    state_text, last_text = "", ""
    for line in out.splitlines():
        ls = line.strip()
        if ls.startswith("Estado:") or ls.startswith("Status:"):
            state_text = ls.split(":", 1)[1].strip()
        elif (ls.startswith("Último resultado:") or ls.startswith("Ultimo resultado:")
              or ls.startswith("Last Run Result:")):
            last_text = ls.split(":", 1)[1].strip()

    # Normalización robusta para ES/EN y códigos 0x41300/0x41301
    lt = last_text.upper().replace("0X", "0x")
    if "0x41301" in lt or state_text.lower() in ("en ejecución", "running"):
        return state_text or "En ejecución"
    if "0x41300" in lt or state_text.lower() in ("listo", "ready"):
        return state_text or "Listo"
    return state_text or "Instalada"

def _stop_task():
    tn = _task_full_name_for_schtasks()
    rc, out, err = _run("schtasks", "/End", "/TN", tn)
    if rc != 0:  # si no estaba corriendo, lo consideramos OK
        rc = 0
    return rc, out, err

# ---------- Notifier: consultas/acciones de tarea ----------
def _task_full_name_notif() -> str:
    return f"{TASK_PATH.strip('\\\\')}\\{TASK_NOTIFIER}"

def _query_notifier_state_local() -> str:
    tn = _task_full_name_notif()
    rc, out, err = _run("schtasks", "/Query", "/TN", tn, "/V", "/FO", "LIST")
    if rc != 0:
        return "No instalada"

    state_text, last_text = "", ""
    for line in out.splitlines():
        ls = line.strip()
        if ls.startswith("Estado:") or ls.startswith("Status:"):
            state_text = ls.split(":", 1)[1].strip()
        elif (ls.startswith("Último resultado:") or ls.startswith("Ultimo resultado:")
              or ls.startswith("Last Run Result:")):
            last_text = ls.split(":", 1)[1].strip()

    lt = (last_text or "").upper().replace("0X", "0x")
    if "0x41301" in lt or state_text.lower() in ("en ejecución", "running"):
        return state_text or "En ejecución"
    if "0x41300" in lt or state_text.lower() in ("listo", "ready"):
        return state_text or "Listo"
    return state_text or "Instalada"

def _create_or_update_and_run_notifier(cfg: dict):
    """
    Crea la tarea 'Notificador' como ONLOGON del usuario actual (para toasts),
    y la ejecuta. Si ya existía, la sobrescribe.
    """
    tn = _task_full_name_notif()
    pyw = os.path.join(_install_dir(cfg), "venv", "Scripts", "pythonw.exe")
    script = os.path.join(_install_dir(cfg), "notifier.py")

    _run("schtasks", "/Delete", "/TN", tn, "/F")
    rc, out, err = _run("schtasks", "/Create",
                        "/TN", tn,
                        "/TR", f"\"{pyw}\" \"{script}\" --xh-role notifier",
                        "/SC", "ONLOGON",
                        "/RL", "LIMITED",
                        "/RU", os.getenv("USERNAME", ""),
                        "/F")
    if rc == 0:
        _run("schtasks", "/Run", "/TN", tn)
    return rc, out, err

def _run_notifier_task_or_create(cfg: dict):
    tn = _task_full_name_notif()
    rc_q, _, _ = _run("schtasks", "/Query", "/TN", tn)
    if rc_q == 0:
        return _run("schtasks", "/Run", "/TN", tn)
    return _create_or_update_and_run_notifier(cfg)

def _stop_notifier_task():
    tn = _task_full_name_notif()
    rc, out, err = _run("schtasks", "/End", "/TN", tn)
    if rc != 0:
        rc = 0
    return rc, out, err

def _open_task_scheduler_local():
    # Abre el Programador de tareas enfocado a nuestra carpeta
    # (si no, abre el MMC estándar)
    try:
        os.startfile("taskschd.msc")
        return 0, "", ""
    except Exception as e:
        return 1, "", str(e)

def _open_control_log(cfg: dict):
    log_path = os.path.join(_install_dir(cfg), "logs", "control.log")
    if os.path.exists(log_path):
        try:
            os.startfile(log_path)
            return 0, "", ""
        except Exception as e:
            return 1, "", str(e)
    return 1, "", "control.log no encontrado"

def _launch_uninstaller(cfg: dict):
    py = _venv_python(cfg)
    uni = os.path.join(_install_dir(cfg), "uninstall.py")
    if not os.path.exists(uni):
        return 1, "", "uninstall.py no encontrado"
    try:
        subprocess.Popen([py, uni], creationflags=0x08000000)
        return 0, "", ""
    except Exception as e:
        return 1, "", str(e)


class OptionsPage(ttk.Frame):
    def __init__(self, master, cfg: dict, ui_dark_var: tk.BooleanVar,
                 on_toggle_theme, on_save_cfg):
        super().__init__(master)
        self.cfg = cfg
        self.ui_dark = ui_dark_var
        self.on_toggle_theme = on_toggle_theme
        self.on_save_cfg = on_save_cfg
        self._gate = TaskGate()
        self._build()
        log.debug("OptionsPage inicializada.")
        self.on_show_async() 

    # ---------------- Hooks de navegación ----------------
    def on_show_async(self, rev=None):
        rev = self._gate.next_rev() if rev is None else rev
        log.debug("OptionsPage on_show_async rev=%s", rev)
        submit_limited(self._task_refresh_service, rev)
        submit_limited(self._task_refresh_notifier, rev)

    def refresh_lite(self):
        pass

    # ---------------- Construcción UI --------------------
    def _build(self):
        pad = {"padx": 6, "pady": 6}

        # --- PIN ---
        top = ttk.Frame(self)
        top.grid(row=0, column=0, sticky="ew")
        top.grid_columnconfigure(2, weight=1)

        ttk.Label(top, text="Cambiar PIN del tutor").grid(row=0, column=0, sticky="w", **pad)
        ttk.Button(top, text="Cambiar PIN", command=self._change_pin).grid(row=0, column=1, sticky="w", **pad)

        # Botón desinstalar desde app (a petición)
        ttk.Button(top, text="Desinstalar XiaoHack…", command=self._uninstall_from_app)\
            .grid(row=0, column=3, sticky="e", padx=12)

        ttk.Separator(self).grid(row=1, column=0, columnspan=6, sticky="ew", padx=6, pady=12)

        # --- Apariencia ---
        ttk.Label(self, text="Apariencia").grid(row=2, column=0, sticky="w", **pad)
        ttk.Checkbutton(self, text="Tema oscuro", variable=self.ui_dark, command=self.on_toggle_theme)\
            .grid(row=2, column=1, sticky="w", **pad)

        ttk.Separator(self).grid(row=3, column=0, columnspan=6, sticky="ew", padx=6, pady=12)

        # --- Servicio (guardian / tarea programada) ---
        ttk.Label(self, text="Servicio (tarea programada): XiaoHackParental\\Guardian").grid(row=4, column=0, sticky="w", **pad)
        self.var_srv = tk.StringVar(value="Estado: (desconocido)")
        ttk.Label(self, textvariable=self.var_srv).grid(row=5, column=0, sticky="w", **pad)

        btns_srv = ttk.Frame(self)
        btns_srv.grid(row=6, column=0, sticky="w", **pad)
        ttk.Button(btns_srv, text="Iniciar servicio", command=self._start_service).grid(row=0, column=0, padx=4)
        ttk.Button(btns_srv, text="Detener servicio", command=self._stop_service).grid(row=0, column=1, padx=4)
        ttk.Button(btns_srv, text="Reiniciar servicio", command=self._restart_guardian).grid(row=0, column=2, padx=4)
        ttk.Button(btns_srv, text="Refrescar estado", command=self.refresh_service).grid(row=0, column=3, padx=4)
        ttk.Button(btns_srv, text="Abrir Programador de tareas", command=self._open_task_scheduler).grid(row=0, column=4, padx=4)

        ttk.Separator(self).grid(row=7, column=0, columnspan=6, sticky="ew", padx=6, pady=12)

        # === Notifier (usuario actual) ===
        ttk.Label(self, text="Notifier (usuario actual)").grid(row=8, column=0, sticky="w", **pad)
        self.var_notif = tk.StringVar(value="Estado: (desconocido)")
        ttk.Label(self, textvariable=self.var_notif).grid(row=9, column=0, sticky="w", **pad)

        btns_notif = ttk.Frame(self)
        btns_notif.grid(row=10, column=0, sticky="w", **pad)
        ttk.Button(btns_notif, text="Iniciar Notifier", command=self._start_notifier).grid(row=0, column=0, padx=4)
        ttk.Button(btns_notif, text="Detener Notifier", command=self._stop_notifier).grid(row=0, column=1, padx=4)
        ttk.Button(btns_notif, text="Reiniciar Notifier", command=self._restart_notifier).grid(row=0, column=2, padx=4)
        ttk.Button(btns_notif, text="Abrir log (control.log)", command=self._open_control_log).grid(row=0, column=3, padx=4)
        
        ttk.Separator(self).grid(row=11, column=0, columnspan=6, sticky="ew", padx=6, pady=12)

        # === Actualizaciones ===
        upd = ttk.LabelFrame(self, text="Actualizaciones")
        upd.grid(row=12, column=0, sticky="ew", padx=6, pady=6)
        upd.grid_columnconfigure(1, weight=1)

        self.var_cur = tk.StringVar(value=_read_version())
        self.var_lat = tk.StringVar(value="—")
        self.var_upd = tk.StringVar(value="Sin comprobar")

        ttk.Label(upd, text="Versión instalada:").grid(row=0, column=0, sticky="w", padx=6, pady=4)
        ttk.Label(upd, textvariable=self.var_cur).grid(row=0, column=1, sticky="w", padx=6)

        ttk.Label(upd, text="Última versión:").grid(row=1, column=0, sticky="w", padx=6, pady=4)
        ttk.Label(upd, textvariable=self.var_lat).grid(row=1, column=1, sticky="w", padx=6)

        ttk.Label(upd, text="Estado:").grid(row=2, column=0, sticky="w", padx=6, pady=4)
        ttk.Label(upd, textvariable=self.var_upd).grid(row=2, column=1, sticky="w", padx=6)

        btns_upd = ttk.Frame(upd)
        btns_upd.grid(row=3, column=0, columnspan=2, sticky="w", padx=6, pady=(6, 4))

        self.btn_check = ttk.Button(btns_upd, text="Comprobar", command=self._on_check_updates)
        self.btn_apply = ttk.Button(btns_upd, text="Actualizar", command=self._on_apply_update, state="disabled")
        self.btn_check.pack(side="left", padx=4)
        self.btn_apply.pack(side="left", padx=4)

        # Comprobación automática tras abrir la pestaña
        self.after(1200, self._auto_check_updates)

    # ---------------- PIN ----------------
    def _change_pin(self):
        log.info("Cambio de PIN solicitado.")
        newh = set_new_pin_hash(self)
        if newh:
            self.cfg["parent_password_hash"] = newh
            # persistir por callback del shell principal
            if callable(self.on_save_cfg):
                self.on_save_cfg(self.cfg)
            messagebox.showinfo("OK", "PIN actualizado.")
            log.info("PIN actualizado y guardado en configuración.")
        else:
            log.debug("Cambio de PIN cancelado o inválido.")
            
    # ---------------- Actualizaciones ----------------
    def _set_upd_busy(self, busy: bool, msg: str = None):
        st = "disabled" if busy else "normal"
        self.btn_check.configure(state=st)
        # solo habilitar "Actualizar" si había update disponible
        if busy:
            self.btn_apply.configure(state="disabled")
        self.var_upd.set(msg or ("Trabajando…" if busy else "Listo"))

    def _auto_check_updates(self):
        if self.var_lat.get() == "—":  # solo si no se ha hecho ya
            self._on_check_updates()

    def _on_check_updates(self):
        def work():
            self._set_upd_busy(True, "Comprobando…")
            res = _run_updater(["--check"])
            self.after(0, self._after_check_updates, res)
        threading.Thread(target=work, daemon=True).start()

    def _after_check_updates(self, res: dict):
        self._set_upd_busy(False)
        if not isinstance(res, dict):
            messagebox.showerror("Actualizaciones", f"Respuesta inválida: {res}")
            return
        if res.get("error"):
            self.var_upd.set("Error")
            messagebox.showerror("Actualizaciones", f"Error: {res['error']}")
            return

        cur = res.get("current") or _read_version()
        lat = res.get("latest") or "—"
        upd = bool(res.get("update_available"))

        self.var_cur.set(cur)
        self.var_lat.set(lat)
        self.var_upd.set("Actualización disponible" if upd else "Al día")
        self.btn_apply.configure(state=("normal" if upd else "disabled"))

        if upd:
            if messagebox.askyesno("Actualización disponible",
                                   f"Se encontró la versión {lat}.\n¿Quieres instalarla ahora?"):
                self._on_apply_update()

    def _on_apply_update(self):
        def work():
            self._set_upd_busy(True, "Descargando e instalando…")
            res = _run_updater(["--apply"])
            self.after(0, self._after_apply_update, res)
        threading.Thread(target=work, daemon=True).start()

    def _after_apply_update(self, res: dict):
        self._set_upd_busy(False)
        if res.get("error"):
            self.var_upd.set("Error al actualizar")
            messagebox.showerror("Actualizar", f"No se pudo actualizar:\n{res['error']}")
            return

        latest = res.get("latest") or self.var_lat.get()
        self.var_cur.set(latest)
        self.var_lat.set(latest)
        self.var_upd.set("Actualizado")
        messagebox.showinfo("Actualizar", "Actualización aplicada correctamente.\nReinicia el Panel para ver cambios.")


    # ---------------- Servicio ----------------
    def refresh_service(self):
        rev = self._gate.next_rev()
        log.debug("Refrescando estado del servicio (rev=%s)", rev)
        submit_limited(self._task_refresh_service, rev)

    def _task_refresh_service(self, rev=None):
        try:
            if query_task_state:
                state = query_task_state()
            else:
                state = _query_task_state_local()
            text = f"Estado: {state}"
            log.debug("Estado actual del servicio: %s", state)
        except Exception as e:
            text = f"Estado: error ({type(e).__name__})"
            log.error("Error leyendo estado del servicio: %s", e, exc_info=True)

        def _apply():
            if rev is not None and not self._gate.is_current(rev):
                return
            if not self.winfo_exists():
                return
            self.var_srv.set(text)
        after_safe(self, 0, _apply)

    def _start_service(self):
        """
        Iniciar la tarea 'Guardian'.
        - Si la tarea existe, se hace 'schtasks /Run'.
        - Si no existe, se crea (ONSTART / SYSTEM) y se intenta ejecutar.
        Esta versión evita borrar/recrear la tarea cada vez para que Start funcione tras Stop.
        """
        log.info("Iniciando servicio guardian…")
        rev = self._gate.next_rev()

        def _work():
            tn = _task_full_name_for_schtasks()
            # 1) Si existe, solo ejecutarla
            rc, out, err = _run("schtasks", "/Query", "/TN", tn)
            if rc == 0:
                rc, out, err = _run("schtasks", "/Run", "/TN", tn)
            else:
                # 2) No existe: crearla y luego arrancarla
                run_bat = _run_guardian_bat(self.cfg)
                rc_create, out_create, err_create = _run("schtasks", "/Create",
                                                        "/TN", tn,
                                                        "/TR", f"\"{run_bat}\"",
                                                        "/SC", "ONSTART",
                                                        "/RU", "SYSTEM",
                                                        "/RL", "HIGHEST",
                                                        "/F")
                if rc_create == 0:
                    rc, out, err = _run("schtasks", "/Run", "/TN", tn)
                else:
                    rc, out, err = rc_create, out_create, err_create

            log.debug("start_service rc=%d out=%s err=%s", rc, out, err)

            def _post():
                if not self._gate.is_current(rev) or not self.winfo_exists():
                    return
                if rc == 0:
                    self.after(1200, self.refresh_service)
                    messagebox.showinfo("OK", "Servicio iniciado.")
                    log.info("Servicio guardian iniciado correctamente.")
                else:
                    msg = err or out or "(sin detalles)"
                    messagebox.showerror("Error al iniciar", f"No se pudo iniciar la tarea.\n\nCódigo: {rc}\n{msg}")
                    log.error("Error al iniciar servicio: %s", msg)
                    self.after(200, self.refresh_service)

            self.after(0, _post)

        submit_limited(_work)

    def _stop_service(self):
        log.info("Deteniendo servicio guardian...")
        rev = self._gate.next_rev()
        def _work():
            if stop_service:
                rc, out, err = stop_service()
            else:
                rc, out, err = _stop_task()
            log.debug("stop_service rc=%d out=%s err=%s", rc, out, err)
            def _post():
                if not self._gate.is_current(rev) or not self.winfo_exists(): 
                    return
                if rc == 0:
                    self.after(800, self.refresh_service)
                    messagebox.showinfo("OK", "Servicio detenido.")
                    log.info("Servicio detenido correctamente.")
                else:
                    msg = err or out or "(sin detalles)"
                    messagebox.showerror("Error al detener",
                        f"No se pudo detener la tarea.\n\nCódigo: {rc}\n{msg}")
                    log.error("Error al detener servicio: %s", msg)
                    self.after(200, self.refresh_service)
            self.after(0, _post)
        submit_limited(_work)

    def _open_task_scheduler(self):
        if open_task_scheduler:
            open_task_scheduler()
            return
        _open_task_scheduler_local()
        
    def _create_or_update_and_run_task(cfg: dict):
        tn = _task_full_name_for_schtasks()
        run_bat = _run_guardian_bat(cfg)
        _run("schtasks", "/Delete", "/TN", tn, "/F")
        rc, out, err = _run("schtasks", "/Create",
                            "/TN", tn,
                            "/TR", f"\"{run_bat}\"",
                            "/SC", "ONSTART",
                            "/RU", "SYSTEM",
                            "/RL", "HIGHEST",
                            "/F")
        if rc == 0:
            _run("schtasks", "/Run", "/TN", tn)
        return rc, out, err

        
    def _restart_guardian(self):
        log.info("Reiniciando guardian...")
        rev = self._gate.next_rev()
        def _work():
            if restart_guardian:
                rc, out, err = restart_guardian()
            else:
                # fallback mínimo si no tenemos helpers
                _stop_task()
                _run("schtasks", "/Run", "/TN", _task_full_name_for_schtasks())
                rc, out, err = 0, "", ""
            log.debug("restart_guardian rc=%d out=%s err=%s", rc, out, err)
            def _post():
                if not self._gate.is_current(rev) or not self.winfo_exists(): 
                    return
                if rc == 0:
                    self.after(800, self.refresh_service)
                    messagebox.showinfo("OK", "Guardian reiniciado.")
                    log.info("Guardian reiniciado correctamente.")
                else:
                    msg = err or out or "(sin detalles)"
                    messagebox.showerror("Error", f"No se pudo reiniciar: {msg}")
                    log.error("Error al reiniciar guardian: %s", msg)
            self.after(0, _post)
        submit_limited(_work)

    # ---------------- Notifier (idéntico a Guardian, vía tarea) ----------------
    def refresh_notifier(self):
        rev = self._gate.next_rev()
        log.debug("Refrescando estado del notifier (rev=%s)", rev)
        submit_limited(self._task_refresh_notifier, rev)

    def _task_refresh_notifier(self, rev=None):
        try:
            if query_notifier_state:
                st = query_notifier_state()
            else:
                st = _query_notifier_state_local()
            text = f"Estado: {st}"
            log.debug("Estado actual notifier: %s", st)
        except Exception as e:
            text = f"Estado: error ({type(e).__name__})"
            log.error("Error leyendo estado notifier: %s", e, exc_info=True)

        def _apply():
            if rev is not None and not self._gate.is_current(rev):
                return
            if not self.winfo_exists():
                return
            self.var_notif.set(text)
        after_safe(self, 0, _apply)

    def _start_notifier(self):
        log.info("Iniciando notifier (tarea)…")
        rev = self._gate.next_rev()
        def _work():
            if start_notifier:
                rc, out, err = start_notifier()
            else:
                rc, out, err = _run_notifier_task_or_create(self.cfg)
            log.debug("start_notifier rc=%d out=%s err=%s", rc, out, err)
            def _post():
                if not self._gate.is_current(rev) or not self.winfo_exists(): 
                    return
                if rc == 0:
                    self.after(900, self.refresh_notifier)
                    messagebox.showinfo("OK", "Notifier iniciado (tarea).")
                    log.info("Notifier iniciado correctamente (tarea).")
                else:
                    msg = err or out or "(sin detalles)"
                    messagebox.showerror("Error", f"No se pudo iniciar: {msg}")
                    log.error("Error al iniciar notifier: %s", msg)
            self.after(0, _post)
        submit_limited(_work)

    def _stop_notifier(self):
        log.info("Deteniendo notifier (tarea)…")
        rev = self._gate.next_rev()
        def _work():
            if stop_notifier:
                rc, out, err = stop_notifier()
            else:
                rc, out, err = _stop_notifier_task()
            log.debug("stop_notifier rc=%d out=%s err=%s", rc, out, err)
            def _post():
                if not self._gate.is_current(rev) or not self.winfo_exists(): 
                    return
                if rc == 0:
                    self.after(600, self.refresh_notifier)
                    messagebox.showinfo("OK", "Notifier detenido.")
                    log.info("Notifier detenido correctamente.")
                else:
                    msg = err or out or "(sin detalles)"
                    messagebox.showerror("Error", f"No se pudo detener: {msg}")
                    log.error("Error al detener notifier: %s", msg)
            self.after(0, _post)
        submit_limited(_work)

    def _restart_notifier(self):
        log.info("Reiniciando notifier (tarea)…")
        rev = self._gate.next_rev()
        def _work():
            if restart_notifier:
                rc, out, err = restart_notifier()
            else:
                _stop_notifier_task()
                rc, out, err = _run_notifier_task_or_create(self.cfg)
            log.debug("restart_notifier rc=%d out=%s err=%s", rc, out, err)
            def _post():
                if not self._gate.is_current(rev) or not self.winfo_exists(): 
                    return
                if rc == 0:
                    self.after(900, self.refresh_notifier)
                    messagebox.showinfo("OK", "Notifier reiniciado.")
                    log.info("Notifier reiniciado correctamente.")
                else:
                    msg = err or out or "(sin detalles)"
                    messagebox.showerror("Error", f"No se pudo reiniciar: {msg}")
                    log.error("Error al reiniciar notifier: %s", msg)
            self.after(0, _post)
        submit_limited(_work)

    def _open_control_log(self):
        log.debug("Abriendo control.log…")
        rev = self._gate.next_rev()
        def _work():
            # Si el módulo services tiene función, úsala; si no, abrimos control.log directo
            if open_notifier_log:
                rc, out, err = open_notifier_log()
            else:
                rc, out, err = _open_control_log(self.cfg)
            log.debug("open_control_log rc=%d out=%s err=%s", rc, out, err)
            def _post():
                if not self._gate.is_current(rev) or not self.winfo_exists():
                    return
                if rc != 0:
                    msg = err or out or "(sin detalles)"
                    messagebox.showerror("Error", f"No se pudo abrir el log: {msg}")
                    log.error("Error abriendo control.log: %s", msg)
            self.after(0, _post)
        submit_limited(_work)

    # ---------------- Desinstalar desde la app ----------------
    def _uninstall_from_app(self):
        if messagebox.askyesno("Desinstalar", "¿Quieres abrir el desinstalador de XiaoHack?"):
            rc, out, err = _launch_uninstaller(self.cfg)
            if rc != 0:
                messagebox.showerror("Error", f"No se pudo abrir el desinstalador.\n{err or out or ''}")
            else:
                messagebox.showinfo("Desinstalador", "Se abrió el desinstalador. Sigue los pasos en la ventana nueva.")
