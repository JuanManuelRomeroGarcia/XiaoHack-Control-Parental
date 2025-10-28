# xiao_gui/pages/options.py — XiaoHack GUI: pestaña Opciones (limpia y consolidada)
from __future__ import annotations

import json
import os
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, messagebox

from app.logs import get_logger
from ..dialogs import set_new_pin_hash

# Fallbacks suaves si las utilidades no están (tests/dev)
try:
    from utils.tk_safe import after_safe
except Exception:
    def after_safe(widget, ms, fn):
        try:
            widget.after(ms, fn)
        except Exception:
            pass

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

# Helpers consolidados del runtime/servicios
from utils.runtime import read_version, find_install_root, updater_path, python_for_console
from xiao_gui.services import (
    run_updater_apply_ui,
    launch_uninstaller_ui,
    query_task_state, start_service, stop_service,
    open_control_log,
    notifier_status, start_notifier, stop_notifier,
)

log = get_logger("gui.options")


# ---------------------------------------------------------------------------
# utilidades locales
# ---------------------------------------------------------------------------
def _open_task_scheduler_local():
    """Abre el Programador de tareas."""
    try:
        os.startfile("taskschd.msc")
        return 0, "", ""
    except Exception as e:
        return 1, "", str(e)

def _read_version_fallback() -> str:
    try:
        return read_version()
    except Exception:
        try:
            root = find_install_root()
            return (root / "VERSION").read_text(encoding="utf-8").strip()
        except Exception:
            return "0.0.0"


# =====================================================================
#                                UI
# =====================================================================
class OptionsPage(ttk.Frame):
    def __init__(self, master, cfg: dict, ui_dark_var: tk.BooleanVar,
                 on_toggle_theme, on_save_cfg):
        super().__init__(master)
        self.cfg = cfg or {}
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
        submit_limited(self._task_refresh_service, rev)
        self.after(300, self.refresh_notifier)
        self.after(1200, self._auto_check_updates)

    def refresh_lite(self):
        pass

    # ---------------- Construcción UI --------------------
    def _build(self):
        pad = {"padx": 6, "pady": 6}
        row = 0

        # --- PIN / Desinstalar ---
        top = ttk.Frame(self)
        top.grid(row=row, column=0, sticky="ew")
        top.grid_columnconfigure(2, weight=1)
        ttk.Label(top, text="Cambiar PIN del tutor").grid(row=0, column=0, sticky="w", **pad)
        ttk.Button(top, text="Cambiar PIN", command=self._change_pin).grid(row=0, column=1, sticky="w", **pad)
        ttk.Button(top, text="Desinstalar XiaoHack…", command=self._uninstall_from_app).grid(row=0, column=3, sticky="e", padx=12)
        row += 1

        ttk.Separator(self).grid(row=row, column=0, sticky="ew", padx=6, pady=12)
        row += 1

        # --- Apariencia ---
        ttk.Label(self, text="Apariencia").grid(row=row, column=0, sticky="w", **pad)
        ttk.Checkbutton(self, text="Tema oscuro", variable=self.ui_dark, command=self.on_toggle_theme)\
            .grid(row=row, column=0, sticky="e", padx=140, pady=6)
        row += 1

        ttk.Separator(self).grid(row=row, column=0, sticky="ew", padx=6, pady=12)
        row += 1

        # --- Servicio Guardian ---
        ttk.Label(self, text="Servicio (tarea programada): XiaoHackParental\\Guardian").grid(row=row, column=0, sticky="w", **pad)
        row += 1

        self.var_srv = tk.StringVar(value="Estado: (desconocido)")
        ttk.Label(self, textvariable=self.var_srv).grid(row=row, column=0, sticky="w", **pad)
        row += 1

        btns_srv = ttk.Frame(self)
        btns_srv.grid(row=row, column=0, sticky="w", **pad)
        ttk.Button(btns_srv, text="Iniciar servicio", command=self._start_service).grid(row=0, column=0, padx=4)
        ttk.Button(btns_srv, text="Detener servicio", command=self._stop_service).grid(row=0, column=1, padx=4)
        ttk.Button(btns_srv, text="Reiniciar servicio", command=self._restart_guardian).grid(row=0, column=2, padx=4)
        ttk.Button(btns_srv, text="Refrescar estado", command=self.refresh_service).grid(row=0, column=3, padx=4)
        ttk.Button(btns_srv, text="Abrir Programador de tareas", command=self._open_task_scheduler).grid(row=0, column=4, padx=4)
        row += 1

        ttk.Separator(self).grid(row=row, column=0, sticky="ew", padx=6, pady=12)
        row += 1

        # --- Notifier ---
        ttk.Label(self, text="Notifier (superposición de bloqueos)").grid(row=row, column=0, sticky="w", **pad)
        row += 1

        self.var_notif = tk.StringVar(value="Estado: (desconocido)")
        ttk.Label(self, textvariable=self.var_notif).grid(row=row, column=0, sticky="w", **pad)
        row += 1

        btns_not = ttk.Frame(self)
        btns_not.grid(row=row, column=0, sticky="w", **pad)
        ttk.Button(btns_not, text="Iniciar Notifier", command=self._start_notifier).grid(row=0, column=0, padx=4)
        ttk.Button(btns_not, text="Detener Notifier", command=self._stop_notifier).grid(row=0, column=1, padx=4)
        ttk.Button(btns_not, text="Reiniciar Notifier", command=self._restart_notifier).grid(row=0, column=2, padx=4)
        ttk.Button(btns_not, text="Refrescar estado", command=self.refresh_notifier).grid(row=0, column=3, padx=4)
        row += 1

        ttk.Separator(self).grid(row=row, column=0, sticky="ew", padx=6, pady=12)
        row += 1

        # --- Logs ---
        ttk.Label(self, text="Registros y notificaciones").grid(row=row, column=0, sticky="w", **pad)
        ttk.Button(self, text="Abrir control.log", command=self._open_control_log).grid(row=row, column=0, sticky="e", padx=170, pady=6)
        row += 1

        ttk.Separator(self).grid(row=row, column=0, sticky="ew", padx=6, pady=12)
        row += 1

        # === Actualizaciones ===
        upd = ttk.LabelFrame(self, text="Actualizaciones")
        upd.grid(row=row, column=0, sticky="ew", padx=6, pady=6)
        upd.grid_columnconfigure(1, weight=1)

        self.var_cur = tk.StringVar(value=_read_version_fallback())
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

    # ---------------- PIN ----------------
    def _change_pin(self):
        log.info("Cambio de PIN solicitado.")
        newh = set_new_pin_hash(self)
        if newh:
            self.cfg["parent_password_hash"] = newh
            if callable(self.on_save_cfg):
                self.on_save_cfg(self.cfg)
            messagebox.showinfo("OK", "PIN actualizado.")
            log.info("PIN actualizado y guardado en configuración.")
        else:
            log.debug("Cambio de PIN cancelado o inválido.")

    # ---------------- Servicio (Guardian) ----------------
    def refresh_service(self):
        rev = self._gate.next_rev()
        submit_limited(self._task_refresh_service, rev)

    def _task_refresh_service(self, rev=None):
        try:
            st = query_task_state("guardian")
            if isinstance(st, dict):
                state = st.get("State") or st.get("Estado") or ("Running" if st.get("Exists") else "No instalada")
            else:
                state = str(st)
            text = f"Estado: {state}"
        except Exception as e:
            text = f"Estado: error ({type(e).__name__})"
            log.error("Error leyendo estado servicio: %s", e, exc_info=True)

        def _apply():
            if rev is not None and not self._gate.is_current(rev):
                return
            if not self.winfo_exists():
                return
            self.var_srv.set(text)

        after_safe(self, 0, _apply)

    def _start_service(self):
        log.info("Iniciando servicio…")
        rev = self._gate.next_rev()
        def _work():
            ok = start_service("guardian")
            def _post():
                if not self._gate.is_current(rev) or not self.winfo_exists():
                    return
                if ok:
                    self.after(1200, self.refresh_service)
                    messagebox.showinfo("OK", "Servicio iniciado.")
                else:
                    messagebox.showerror("Error", "No se pudo iniciar la tarea.")
                    self.after(200, self.refresh_service)
            self.after(0, _post)
        submit_limited(_work)

    def _stop_service(self):
        log.info("Deteniendo servicio…")
        rev = self._gate.next_rev()
        def _work():
            ok = stop_service("guardian")
            def _post():
                if not self._gate.is_current(rev) or not self.winfo_exists():
                    return
                if ok:
                    self.after(800, self.refresh_service)
                    messagebox.showinfo("OK", "Servicio detenido.")
                else:
                    messagebox.showerror("Error", "No se pudo detener la tarea.")
                    self.after(200, self.refresh_service)
            self.after(0, _post)
        submit_limited(_work)

    def _restart_guardian(self):
        log.info("Reiniciando servicio…")
        self._stop_service()
        self.after(900, self._start_service)

    def _open_task_scheduler(self):
        _open_task_scheduler_local()

    def _open_control_log(self):
        try:
            open_control_log()
        except Exception:
            messagebox.showerror("Error", "No se pudo abrir el control.log")

    # ---------------- Notifier ----------------
    def refresh_notifier(self):
        try:
            st = notifier_status()
            if not st.get("exists"):
                self.var_notif.set("Estado: no instalado (script no encontrado)")
            else:
                self.var_notif.set("Estado: ejecutándose" if st.get("running") else "Estado: detenido")
        except Exception as e:
            self.var_notif.set(f"Estado: error ({type(e).__name__})")
            log.error("Error leyendo estado Notifier: %s", e, exc_info=True)

    def _start_notifier(self):
        ok = start_notifier()
        if ok:
            self.after(800, self.refresh_notifier)
            messagebox.showinfo("Notifier", "Notifier iniciado.")
        else:
            messagebox.showerror("Notifier", "No se pudo iniciar el Notifier.")

    def _stop_notifier(self):
        ok = stop_notifier()
        if ok:
            self.after(600, self.refresh_notifier)
            messagebox.showinfo("Notifier", "Notifier detenido.")
        else:
            messagebox.showerror("Notifier", "No se pudo detener el Notifier (o no estaba activo).")

    def _restart_notifier(self):
        self._stop_notifier()
        self.after(900, self._start_notifier)

    # ---------------- Actualizaciones ----------------
    def _set_upd_busy(self, busy: bool, msg: str | None = None):
        st = "disabled" if busy else "normal"
        self.btn_check.configure(state=st)
        if busy:
            self.btn_apply.configure(state="disabled")
        self.var_upd.set(msg or ("Trabajando…" if busy else "Listo"))

    def _auto_check_updates(self):
        if self.var_lat.get() == "—":
            self._on_check_updates()

    def _on_check_updates(self):
        """Comprueba updater.py --check en hilo y actualiza la UI (con logs detallados)."""
        self._set_upd_busy(True, "Comprobando…")

        def work():
            from pathlib import Path as _P
            base = find_install_root()
            up = updater_path()
            py = python_for_console()

            # Log a archivo
            logdir = _P(os.getenv("ProgramData", r"C:\ProgramData")) / "XiaoHackParental" / "logs"
            logdir.mkdir(parents=True, exist_ok=True)
            gui_log = logdir / "updater_gui.log"

            def _w(line: str):
                try:
                    gui_log.write_text(
                        (gui_log.read_text(encoding="utf-8") if gui_log.exists() else "") + line + "\n",
                        encoding="utf-8"
                    )
                except Exception:
                    pass
                log.info(line)

            if not up.exists():
                res = {"error": f"Updater no encontrado: {up}"}
                return self.after(0, self._after_check_updates, res)

            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"
            env["PYTHONUTF8"] = "1"

            cmd = [py, str(up), "--check"]
            _w(f"[check] cwd={base} cmd={' '.join(cmd)}")

            # Usamos run para capturar stdout+stderr y rc
            proc = subprocess.run(
                cmd, cwd=str(base), env=env,
                capture_output=True, text=True, timeout=180,
                creationflags=0x08000000 
            )
            out = (proc.stdout or "")
            err = (proc.stderr or "")
            rc  = proc.returncode
            _w(f"[check] rc={rc}")
            if out:
                _w("[check] stdout:\n" + out.strip())
            if err:
                _w("[check] stderr:\n" + err.strip())

            if rc != 0:
                # Devolvemos las primeras líneas para mostrar en dialog
                snippet = (out or err).strip().splitlines()[:15]
                res = {"error": f"rc={rc}", "snippet": "\n".join(snippet)}
                return self.after(0, self._after_check_updates, res)

            # JSON OK
            try:
                data = json.loads(out)
                res = {"ok": True, **data}
            except Exception as e:
                res = {"error": f"JSON inválido: {e}", "snippet": out[:1000]}
            self.after(0, self._after_check_updates, res)

        threading.Thread(target=work, daemon=True).start()


    def _after_check_updates(self, res: dict | None):
        self._set_upd_busy(False)
        if not isinstance(res, dict) or res.get("error"):
            self.var_upd.set("Error")
            extra = ""
            if isinstance(res, dict) and res.get("snippet"):
                extra = "\n\nSalida:\n" + res["snippet"]
            msg = (res.get("error") if isinstance(res, dict) else "Sin respuesta del updater.") + extra
            messagebox.showerror("Actualizaciones", f"Error al comprobar: {msg}")
            return

        cur = res.get("current") or _read_version_fallback()
        lat = res.get("latest") or "—"
        upd = bool(res.get("update_available"))

        self.var_cur.set(cur)
        self.var_lat.set(lat)
        self.var_upd.set("Actualización disponible" if upd else "Al día")
        self.btn_apply.configure(state=("normal" if upd else "disabled"))

        if upd and messagebox.askyesno(
            "Actualización disponible",
            f"Se encontró la versión {lat}.\n¿Quieres instalarla ahora?"
        ):
            self._on_apply_update()

    def _on_apply_update(self):
        def work():
            self._set_upd_busy(True, "Descargando e instalando…")
            try:
                run_updater_apply_ui()
                res = {"ok": True}
            except Exception as e:
                res = {"error": str(e)}
            self.after(0, self._after_apply_update, res)
        threading.Thread(target=work, daemon=True).start()

    def _after_apply_update(self, res: dict):
        self._set_upd_busy(False)
        if res.get("error"):
            self.var_upd.set("Error al actualizar")
            messagebox.showerror("Actualizar", f"No se pudo actualizar:\n{res['error']}")
            return

        latest = self.var_lat.get()
        if latest and latest != "—":
            self.var_cur.set(latest)
        self.var_upd.set("Actualizado")
        messagebox.showinfo("Actualizar", "Actualización aplicada correctamente.\nReinicia el Panel para ver cambios.")

    # ---------------- Desinstalar ----------------
    def _uninstall_from_app(self):
        if messagebox.askyesno("Desinstalar", "¿Quieres abrir el desinstalador de XiaoHack?"):
            try:
                launch_uninstaller_ui()
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo abrir el desinstalador:\n{e}")
