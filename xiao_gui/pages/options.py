# xiao_gui/pages/options.py — XiaoHack GUI: pestaña Opciones (limpia y consolidada)
from __future__ import annotations

import getpass
import json
import os
from pathlib import Path
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
from utils.runtime import read_version, find_install_root, python_for_console
from xiao_gui.services import (
    notifier_regenerate_aumid,
    notifier_test_toast,
    run_updater_apply_ui,
    launch_uninstaller_ui,
    query_task_state, start_service, stop_service,
    open_control_log,
    diagnose_notifications,
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
    # Intenta primero runtime.read_version(); si falla, lee JSON y luego texto
    try:
        return read_version()
    except Exception:
        pass
    try:
        root = find_install_root()
        vjson = (root / "VERSION.json")
        if vjson.exists():
            data = json.loads(vjson.read_text(encoding="utf-8-sig"))
            v = str(data.get("version", "")).strip()
            if v.lower().startswith("v"):
                v = v[1:].strip()
            if v:
                return v
        vtxt = (root / "VERSION")
        if vtxt.exists():
            v = vtxt.read_text(encoding="utf-8-sig").lstrip("\ufeff").strip()
            if v.lower().startswith("v"):
                v = v[1:].strip()
            if v:
                return v
    except Exception:
        pass
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
        self.after(450, self.refresh_notifier_task_info)
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
        
        # --- Tarea Notifier (per-user; Task Scheduler) ---
        ttk.Separator(self).grid(row=row, column=0, sticky="ew", padx=6, pady=(10,6))
        row += 1
        ttk.Label(self, text="Tarea Notifier (per-user)").grid(row=row, column=0, sticky="w", padx=6, pady=2)
        row += 1

        self.var_notif_task = tk.StringVar(value="Tarea: (desconocido)")
        self.var_notif_task2 = tk.StringVar(value="")
        ttk.Label(self, textvariable=self.var_notif_task).grid(row=row, column=0, sticky="w", padx=6, pady=2)
        row += 1
        ttk.Label(self, textvariable=self.var_notif_task2).grid(row=row, column=0, sticky="w", padx=6, pady=(0,6))
        row += 1

        btns_nt_task = ttk.Frame(self)
        btns_nt_task.grid(row=row, column=0, sticky="w", padx=6, pady=(0,6))
        ttk.Button(btns_nt_task, text="Recrear desde XML", command=self._recreate_notifier_task).grid(row=0, column=0, padx=4)
        ttk.Button(btns_nt_task, text="Ejecutar ahora", command=self._run_notifier_task).grid(row=0, column=1, padx=4)
        ttk.Button(btns_nt_task, text="Detener", command=self._end_notifier_task).grid(row=0, column=2, padx=4)
        ttk.Button(btns_nt_task, text="Abrir Programador", command=self._open_task_scheduler).grid(row=0, column=3, padx=4)
        row += 1
         # --- Diagnóstico de notificaciones ---
        row += 1
        diag_frm = ttk.Frame(self)
        diag_frm.grid(row=row, column=0, sticky="w", padx=6, pady=(0,6))
        self.var_diag_fix = tk.BooleanVar(value=False)
        ttk.Checkbutton(diag_frm, text="Auto-arreglar si es posible", variable=self.var_diag_fix).grid(row=0, column=0, padx=(0,8))
        ttk.Button(diag_frm, text="Diagnosticar notificaciones", command=self._on_diag_notifs).grid(row=0, column=1)
        row += 1
        # --- Herramientas Notifier ---
        row += 1
        tools_frm = ttk.Frame(self)
        tools_frm.grid(row=row, column=0, sticky="w", padx=6, pady=(0,6))
        ttk.Button(tools_frm, text="Toast de prueba", command=self._on_test_toast).grid(row=0, column=0, padx=(0,8))
        ttk.Button(tools_frm, text="Regenerar AppID/atajo", command=self._on_regen_aumid).grid(row=0, column=1)
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
        
    def _on_diag_notifs(self):
        auto_fix = bool(self.var_diag_fix.get())
        log.info("Diagnóstico de notificaciones (auto_fix=%s)…", auto_fix)

        def _work():
            res = diagnose_notifications(auto_fix=auto_fix)  # llama a services.py
            def _ui():
                if not self.winfo_exists():
                    return
                if not res.get("ok"):
                    messagebox.showerror("Diagnóstico",
                        f"Fallo al ejecutar diagnóstico (rc={res.get('rc')}):\n{res.get('stderr') or res.get('stdout') or 'Sin salida.'}")
                    return

                d = res.get("data") or {}
                # Campos esperados
                app_id     = d.get("app_id")
                aumid_ok   = bool(d.get("has_shortcut"))
                winrt_ok   = bool(d.get("winrt_available"))
                toast_g    = d.get("toast_enabled")
                toast_app  = d.get("app_enabled")
                qh         = bool(d.get("quiet_hours_active"))
                lnk_path   = d.get("shortcut_path")

                lines = []
                lines.append(f"AUMID: {app_id}")
                lines.append(f"Acceso directo (.lnk): {'OK' if aumid_ok else 'FALTA'}")
                if lnk_path:
                    lines.append(f" - {lnk_path}")
                lines.append(f"WinRT disponible: {'sí' if winrt_ok else 'no'}")
                if toast_g is not None:
                    lines.append(f"Notificaciones globales (ToastEnabled): {'ON' if toast_g==1 else 'OFF'}")
                else:
                    lines.append("Notificaciones globales: (sin clave, se usa valor por defecto)")
                if toast_app is not None:
                    lines.append(f"Notificaciones para la app: {'ON' if toast_app==1 else 'OFF'}")
                else:
                    lines.append("Notificaciones para la app: (sin clave, se usa valor por defecto)")
                lines.append(f"No molestar / Focus Assist activo: {'sí' if qh else 'no'}")

                advice = []
                if not aumid_ok:
                    advice.append("➤ Falta el acceso directo en Menú Inicio. Pulsa “Iniciar Notifier” para regenerarlo o reinicia Notifier.")
                if toast_g == 0:
                    advice.append("➤ Las notificaciones globales están desactivadas. Actívalas en Configuración → Sistema → Notificaciones.")
                if toast_app == 0:
                    advice.append("➤ Las notificaciones para XiaoHack están desactivadas. Actívalas en Configuración → Sistema → Notificaciones → XiaoHack Control Parental.")
                if qh:
                    advice.append("➤ El modo “No molestar” está activo. Desactívalo para ver toasts inmediatamente.")

                msg = "\n".join(lines)
                if advice:
                    msg += "\n\nRecomendaciones:\n" + "\n".join(advice)

                if auto_fix:
                    msg = "Se intentó auto-arreglo cuando era posible.\n\n" + msg

                messagebox.showinfo("Diagnóstico de notificaciones", msg)

            self.after(0, _ui)

        # Ejecuta sin bloquear UI
        threading.Thread(target=_work, daemon=True).start()
        
    def _on_test_toast(self):
        def work():
            res = notifier_test_toast()
            def ui():
                if not self.winfo_exists():
                    return
                if res.get("ok"):
                    messagebox.showinfo("Toast de prueba", "Enviado. Si las notificaciones no estaban silenciadas, deberías ver el aviso al instante.")
                else:
                    messagebox.showerror("Toast de prueba", f"Fallo (rc={res.get('rc')}):\n{res.get('stderr') or res.get('stdout') or 'Sin salida.'}")
            self.after(0, ui)
        threading.Thread(target=work, daemon=True).start()

    def _on_regen_aumid(self):
        def work():
            res = notifier_regenerate_aumid()
            def ui():
                if not self.winfo_exists():
                    return
                if not res.get("ok"):
                    messagebox.showerror("Regenerar AppID/atajo",
                                        f"Fallo (rc={res.get('rc')}):\n{res.get('stderr') or res.get('stdout') or 'Sin salida.'}")
                    return
                d = res.get("data") or {}
                lines = [
                    f"AUMID: {d.get('app_id')}",
                    f"Acceso directo (.lnk): {'OK' if d.get('has_shortcut') else 'FALTA'}",
                    d.get('shortcut_path',''),
                    f"WinRT disponible: {'sí' if d.get('winrt_available') else 'no'}",
                    f"Notificaciones globales: {('ON' if d.get('toast_enabled')==1 else ('OFF' if d.get('toast_enabled')==0 else '(sin clave)'))}",
                    f"Notificaciones para la app: {('ON' if d.get('app_enabled')==1 else ('OFF' if d.get('app_enabled')==0 else '(sin clave)'))}",
                    f"No molestar / Focus Assist activo: {'sí' if d.get('quiet_hours_active') else 'no'}",
                ]
                messagebox.showinfo("Regenerar AppID/atajo", "\n".join([s for s in lines if s]))
            self.after(0, ui)
        threading.Thread(target=work, daemon=True).start()

    # =============== Gestión de tarea Notifier (per-user) =================

    def _notifier_task_name(self) -> str:
        u = os.getenv("USERNAME") or getpass.getuser() or "User"
        return f"XiaoHack Notifier - {u}"

    def refresh_notifier_task_info(self):
        """Consulta la tarea per-user vía PowerShell y actualiza etiquetas."""
        rev = self._gate.next_rev()
        def _work():
            name = self._notifier_task_name()
            # PowerShell para obtener State, LastRunTime y LastTaskResult
            ps = (
                f"$n='{name}';"
                "$t=Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue;"
                "if(-not $t){'NX'}"
                "else{ $s=$t.State; $i=$t|Get-ScheduledTaskInfo; "
                "'{0}|{1}|{2}' -f $s, $i.LastRunTime, $i.LastTaskResult }"
            )
            try:
                proc = subprocess.run(
                    ["powershell","-NoProfile","-ExecutionPolicy","Bypass","-Command", ps],
                    capture_output=True, text=True, timeout=15, creationflags=0x08000000
                )
                out = (proc.stdout or "").strip()
            except Exception as e:
                out = f"ERR|{type(e).__name__}|"

            def _ui():
                if not self._gate.is_current(rev) or not self.winfo_exists():
                    return
                name = self._notifier_task_name()
                if out == "NX":
                    self.var_notif_task.set(f"Tarea: {name} — (no existe)")
                    self.var_notif_task2.set("Pulsa «Recrear desde XML».")
                    return
                if out.startswith("ERR|"):
                    self.var_notif_task.set(f"Tarea: {name} — (error)")
                    self.var_notif_task2.set(out)
                    return
                # Esperado: "State|LastRunTime|LastTaskResult"
                parts = out.split("|", 2)
                state = parts[0] if len(parts) > 0 else "?"
                last  = parts[1] if len(parts) > 1 else "?"
                code  = parts[2] if len(parts) > 2 else "?"
                self.var_notif_task.set(f"Tarea: {name} — Estado: {state}")
                self.var_notif_task2.set(f"Última ejecución: {last}  •  Código: {code}")
            self.after(0, _ui)
        submit_limited(_work)

    def _recreate_notifier_task(self):
        """Crea/actualiza la tarea per-user desde el XML del paquete."""
        root = find_install_root()
        xml = Path(root) / "assets" / "tasks" / "task_notifier_global.xml"
        name = self._notifier_task_name()
        if not xml.exists():
            messagebox.showerror("Notifier", f"Falta el XML:\n{xml}")
            return
        try:
            subprocess.run(["schtasks","/Create","/TN", name, "/XML", str(xml), "/F"],
                           check=True, capture_output=True, text=True, creationflags=0x08000000)
            messagebox.showinfo("Notifier", "Tarea creada/actualizada.")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Notifier", f"No se pudo crear la tarea:\n{e.stderr or e.stdout or e}")
        finally:
            self.after(300, self.refresh_notifier_task_info)

    def _run_notifier_task(self):
        name = self._notifier_task_name()
        try:
            subprocess.run(["schtasks","/Run","/TN", name],
                           check=True, capture_output=True, text=True, creationflags=0x08000000)
            self.after(800, self.refresh_notifier_task_info)
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Notifier", f"No se pudo ejecutar la tarea:\n{e.stderr or e.stdout or e}")

    def _end_notifier_task(self):
        name = self._notifier_task_name()
        try:
            subprocess.run(["schtasks","/End","/TN", name],
                           check=False, capture_output=True, text=True, creationflags=0x08000000)
        finally:
            self.after(600, self.refresh_notifier_task_info)


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
        """Comprueba actualizaciones en hilo y actualiza la UI (sin exigir updater.py)."""
        self._set_upd_busy(True, "Comprobando…")

        def work():
            from pathlib import Path as _P
            base = find_install_root()
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

            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"
            env["PYTHONUTF8"] = "1"

            # SIEMPRE como módulo (evita depender de un archivo físico)
            cmd = [py, "-m", "app.updater", "--check"]
            _w(f"[check] cwd={base} cmd={' '.join(cmd)}")

            proc = subprocess.run(
                cmd, cwd=str(base), env=env,
                capture_output=True, text=True, timeout=180,
                creationflags=0x08000000  # oculta ventana
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
                snippet = (out or err).strip().splitlines()[:15]
                res = {"error": f"rc={rc}", "snippet": "\n".join(snippet)}
                return self.after(0, self._after_check_updates, res)

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
