# xiao_gui/pages/time_page.py — Pestaña "Tiempo de juego"
from __future__ import annotations
import re
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
from typing import List

from app.logs import get_logger
from app.storage import load_state, save_state, now_epoch, load_config, save_config, get_alerts_cfg

# --- scheduler: soporta app.scheduler y fallback a scheduler de raíz ---
try:
    from app.scheduler import is_play_allowed, build_example_schedules
except Exception:
    from scheduler import is_play_allowed, build_example_schedules  # type: ignore

# --- after_safe fallback ---
try:
    from utils.tk_safe import after_safe  # asegura after() si el widget ya no existe
except Exception:
    def after_safe(widget, ms, fn):
        try:
            widget.after(ms, fn)
        except Exception:
            pass

# --- TaskGate: control de concurrencia sin bloquear la UI ---
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

log = get_logger("gui.time")

DAYS_ORDER  = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
DAYS_LABELS = {"mon": "Lun", "tue": "Mar", "wed": "Mié", "thu": "Jue",
               "fri": "Vie", "sat": "Sáb", "sun": "Dom"}
TIME_RE = re.compile(r"^(?:[01]\d|2[0-3]):[0-5]\d$")


class TimePage(ttk.Frame):
    """Control de tiempo de juego: sesión manual + horarios semanales."""

    def __init__(self, master, cfg: dict):
        super().__init__(master)
        self.cfg = cfg or {}
        self._pending_schedules: List[dict] | None = None
        self._inplace_editor = None
        self._gate = TaskGate()
        self._build()
        self.on_show_async(None)
        log.debug("TimePage inicializada.")

    # ---------------- Integración con app.py ----------------
    def on_show_async(self, rev=None):
        rev = self._gate.next_rev() if rev is None else rev
        log.debug("on_show_async lanzado (rev=%s)", rev)

        def _work_reload(rev_local):
            try:
                cfg = load_config()
                st = load_state()  # noqa: F841
                def _apply():
                    if not self._gate.is_current(rev_local) or not self.winfo_exists():
                        return
                    self.cfg = cfg
                    self._reload_tree_from_cfg()
                    self._refresh_status_label()
                    self._load_alerts_form()
                    self._update_alerts_checkbox_label()
                    log.debug("Recarga completada (rev=%s)", rev_local)
                after_safe(self, 0, _apply)
            except Exception as e:
                log.error("Error en recarga inicial: %s", e, exc_info=True)
        submit_limited(_work_reload, rev)

    def refresh_lite(self):
        log.debug("Refresco ligero de estado.")
        self._refresh_status_label()

    # ---------------- Construcción UI ----------------
    def _build(self):
        pad = {"padx": 6, "pady": 6}

        # --- Avisos ON/OFF ---
        self.chk_alerts_var = tk.IntVar(value=1)
        self.chk_alerts = ttk.Checkbutton(
            self, text="Permitir avisos y cuenta atrás final", variable=self.chk_alerts_var
        )
        self.chk_alerts.grid(row=0, column=0, columnspan=2, sticky="w", **pad)

        # === Alertas y banners (arriba) ===
        lf_alerts = ttk.LabelFrame(self, text="Alertas y banners")
        lf_alerts.grid(row=1, column=0, columnspan=4, sticky="ew", padx=6, pady=(6, 8))
        lf_alerts.columnconfigure(1, weight=1)
        lf_alerts.columnconfigure(3, weight=1)

        ttk.Label(lf_alerts, text="Aviso 1 (min):").grid(row=0, column=0, sticky="w", padx=6, pady=4)
        self.ent_aviso1 = ttk.Entry(lf_alerts, width=8)
        self.ent_aviso1.grid(row=0, column=1, sticky="w", padx=6, pady=4)

        ttk.Label(lf_alerts, text="Aviso 2 (min):").grid(row=0, column=2, sticky="w", padx=6, pady=4)
        self.ent_aviso2 = ttk.Entry(lf_alerts, width=8)
        self.ent_aviso2.grid(row=0, column=3, sticky="w", padx=6, pady=4)

        ttk.Label(lf_alerts, text="TTL aviso (s):").grid(row=1, column=0, sticky="w", padx=6, pady=4)
        self.ent_ttl_aviso = ttk.Entry(lf_alerts, width=8)
        self.ent_ttl_aviso.grid(row=1, column=1, sticky="w", padx=6, pady=4)

        ttk.Label(lf_alerts, text="TTL cierre (s):").grid(row=1, column=2, sticky="w", padx=6, pady=4)
        self.ent_ttl_cierre = ttk.Entry(lf_alerts, width=8)
        self.ent_ttl_cierre.grid(row=1, column=3, sticky="w", padx=6, pady=4)

        ttk.Button(lf_alerts, text="Guardar alertas", command=self._save_alerts)\
            .grid(row=2, column=3, sticky="e", padx=6, pady=(4, 2))

        # Cargar valores actuales y actualizar etiqueta del check
        self._load_alerts_form()
        self._update_alerts_checkbox_label()

        # --- Duración sesión manual ---
        ttk.Label(self, text="Permitir jugar durante (minutos):").grid(row=2, column=0, sticky="w", **pad)
        self.ent_minutes = ttk.Entry(self, width=10)
        self.ent_minutes.insert(0, "30")
        self.ent_minutes.grid(row=2, column=1, sticky="w", **pad)

        # Nota informativa
        ttk.Label(self, text="(Usa la 'Lista blanca de juegos' de la pestaña Aplicaciones/Juegos.)")\
            .grid(row=3, column=0, columnspan=2, sticky="w", **pad)

        # --- Controles de sesión manual ---
        ttk.Button(self, text="Permitir jugar ahora", command=self._start).grid(row=4, column=0, sticky="w", **pad)
        ttk.Button(self, text="Cancelar sesión", command=self._stop).grid(row=4, column=1, sticky="w", **pad)
        ttk.Button(self, text="Prueba: último minuto (overlay)",
                command=self._start_last_minute_test).grid(row=4, column=2, sticky="w", **pad)

        ttk.Separator(self, orient="horizontal").grid(row=5, column=0, columnspan=4, sticky="ew", **pad)

        # --- Toggle global de tiempo de juego ---
        self._playtime_enabled = tk.BooleanVar(value=bool(load_config().get("playtime_enabled", True)))
        self.btn_toggle = ttk.Button(self, text=self._toggle_btn_text(), command=self._toggle_playtime)
        self.btn_toggle.grid(row=6, column=0, sticky="w", **pad)

        # --- Editor de horarios (compacto) ---
        ttk.Label(self, text="Horarios permitidos (edición):").grid(row=7, column=0, sticky="w", **pad)
        btns = ttk.Frame(self)
        btns.grid(row=7, column=1, columnspan=3, sticky="e", **pad)
        ttk.Button(btns, text="Añadir tramo", command=self._add_schedule_dialog).pack(side="left", padx=3)
        ttk.Button(btns, text="Editar seleccionado", command=self._edit_selected_schedule).pack(side="left", padx=3)
        ttk.Button(btns, text="Eliminar seleccionado", command=self._delete_selected_schedule).pack(side="left", padx=3)
        ttk.Button(btns, text="Guardar horarios", command=self._save_schedules).pack(side="left", padx=3)

        self.tree = ttk.Treeview(self, columns=("days", "from", "to"), show="headings", height=6)  # compacto
        for c, t in zip(("days", "from", "to"), ("Días", "Desde", "Hasta")):
            self.tree.heading(c, text=t)
        self.tree.column("days", width=280, anchor="w")
        self.tree.column("from", width=90, anchor="center")
        self.tree.column("to", width=90, anchor="center")
        self.tree.grid(row=8, column=0, columnspan=4, sticky="nsew", padx=6)
        vs = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=vs.set)
        vs.grid(row=8, column=4, sticky="ns", pady=6)
        self.tree.bind("<Double-1>", self._on_tree_double_click)

        ttk.Button(self, text="Refrescar estado ahora", command=self._signal_schedules_changed)\
            .grid(row=9, column=3, sticky="e", **pad)

        self.lbl_status = ttk.Label(self, text="")
        self.lbl_status.grid(row=10, column=0, columnspan=4, sticky="w", **pad)

        exf = ttk.Frame(self)
        exf.grid(row=11, column=0, columnspan=4, sticky="w", **pad)
        ttk.Button(exf, text="Cargar ejemplo (L–V 18–19 + S/D mañana/tarde)",
                command=self._load_example_schedules).pack(side="left")

        self._reload_tree_from_cfg()
        self._refresh_status_label()

        # Que el árbol pueda crecer si la ventana se agranda
        self.grid_rowconfigure(8, weight=1)
        self.grid_columnconfigure(0, weight=1)


    # ---------------- Schedules helpers ----------------
    def _load_alerts_form(self):
        """Rellena los campos de aviso/TTL desde config.json."""
        try:
            alerts = get_alerts_cfg(load_config())
        except Exception:
            alerts = {"aviso1_sec": 600, "aviso2_sec": 300, "aviso3_sec": 60,
                      "flash_ttl": 7, "close_banner_ttl": 10}

        a1_min = max(1, int(round(int(alerts.get("aviso1_sec", 600)) / 60)))
        a2_min = max(1, int(round(int(alerts.get("aviso2_sec", 300)) / 60)))
        ttl_av = int(alerts.get("flash_ttl", 7))
        ttl_c  = int(alerts.get("close_banner_ttl", 10))

        self.ent_aviso1.delete(0, tk.END)
        self.ent_aviso1.insert(0, str(a1_min))
        self.ent_aviso2.delete(0, tk.END)
        self.ent_aviso2.insert(0, str(a2_min))
        self.ent_ttl_aviso.delete(0, tk.END)
        self.ent_ttl_aviso.insert(0, str(ttl_av))
        self.ent_ttl_cierre.delete(0, tk.END)
        self.ent_ttl_cierre.insert(0, str(ttl_c))

    def _save_alerts(self):
        """Valida y guarda en config.json. (El normalizado final lo hace storage.py)."""
        try:
            a1_min = int(self.ent_aviso1.get().strip())
            a2_min = int(self.ent_aviso2.get().strip())
            ttl_av = int(self.ent_ttl_aviso.get().strip())
            ttl_c  = int(self.ent_ttl_cierre.get().strip())
        except Exception:
            messagebox.showerror("Error", "Valores inválidos. Usa números enteros.")
            return

        # Reglas básicas
        if not (1 <= a1_min <= 1440 and 1 <= a2_min <= 1440):
            messagebox.showerror("Error", "Avisos en minutos: 1–1440.")
            return
        if not (1 <= ttl_av <= 60 and 1 <= ttl_c <= 60):
            messagebox.showerror("Error", "TTLs en segundos: 1–60.")
            return
        if a2_min > a1_min:
            a2_min = a1_min  # mantener orden lógico

        cfg = load_config()
        alerts = dict(cfg.get("alerts") or {})
        alerts.update({
            "aviso1_sec": a1_min * 60,
            "aviso2_sec": a2_min * 60,
            "aviso3_sec": 60,            # último minuto fijo
            "flash_ttl":  ttl_av,
            "close_banner_ttl": ttl_c,
        })
        cfg["alerts"] = alerts
        save_config(cfg)

        # Señal suave para que guardian/notifier capten cambios pronto
        try:
            st = load_state()
            st["alerts_changed_at"] = now_epoch()
            save_state(st)
        except Exception:
            pass

        self._update_alerts_checkbox_label()
        messagebox.showinfo("OK", "Alertas guardadas.")

        log.info("Alertas actualizadas: aviso1=%sm, aviso2=%sm, ttl_aviso=%ss, ttl_cierre=%ss",
                 a1_min, a2_min, ttl_av, ttl_c)

    def _update_alerts_checkbox_label(self):
        """Actualiza etiqueta: 'Avisos X/Y/1 min y cuenta atrás final'."""
        try:
            alerts = get_alerts_cfg(load_config())
            a1_min = max(1, int(round(int(alerts.get("aviso1_sec", 600)) / 60)))
            a2_min = max(1, int(round(int(alerts.get("aviso2_sec", 300)) / 60)))
            text = f"Avisos {a1_min}/{a2_min}/1 min y cuenta atrás final"
        except Exception:
            text = "Permitir avisos cuenta atrás final"
        try:
            self.chk_alerts.configure(text=text)
        except Exception:
            pass
    
    def _reload_tree_from_cfg(self):
        try:
            self._pending_schedules = list(load_config().get("schedules", []))
            self._reload_tree_from_pending()
            log.debug("Horarios recargados (%d tramos).", len(self._pending_schedules))
        except Exception as e:
            log.error("Error recargando horarios: %s", e, exc_info=True)

    def _reload_tree_from_pending(self):
        self.tree.delete(*self.tree.get_children())
        for sch in (self._pending_schedules or []):
            dlabel = self._days_to_label(sch.get("days", []))
            self.tree.insert("", "end", values=(dlabel, sch.get("from",""), sch.get("to","")))

    def _days_to_label(self, days_list):
        days_set = set((d or "").lower()[:3] for d in days_list)
        ordered = [DAYS_LABELS[d] for d in DAYS_ORDER if d in days_set]
        return ", ".join(ordered) if ordered else "-"

    def _toggle_btn_text(self):
        return "Desactivar control de tiempo" if self._playtime_enabled.get() else "Activar control de tiempo"

    # ---------------- Toggle global ----------------
    def _toggle_playtime(self):
        cfg = load_config()
        enabled = not bool(cfg.get("playtime_enabled", True))
        cfg["playtime_enabled"] = enabled
        save_config(cfg)
        log.info("Control de tiempo %s.", "activado" if enabled else "desactivado")
        self._signal_schedules_changed()
        self._playtime_enabled.set(enabled)
        self.btn_toggle.configure(text=self._toggle_btn_text())
        messagebox.showinfo("OK", f"Control de tiempo {'activado' if enabled else 'desactivado'}.")
        self._refresh_status_label()

    # ---------------- Sesión manual ----------------
    def _start(self):
        try:
            mins = int(self.ent_minutes.get().strip())
            if mins <= 0 or mins > 480:
                raise ValueError
        except Exception:
            messagebox.showerror("Error", "Minutos inválidos (1–480).")
            log.warning("Entrada inválida de minutos para sesión manual.")
            return

        st = load_state()
        st["play_until"] = now_epoch() + mins * 60
        st["play_alerts"] = {
            "enabled": bool(self.chk_alerts_var.get()),
            "m10": False, "m5": False, "m1": False, "countdown_started": False,
        }
        st["play_countdown"] = 0
        st["play_end_notified"] = False
        save_state(st)
        log.info("Sesión manual iniciada por %d minutos (avisos=%s).", mins, bool(self.chk_alerts_var.get()))
        messagebox.showinfo("OK", f"Sesión iniciada por {mins} minutos.")
        self._refresh_status_label()

    def _start_last_minute_test(self):
        """Fuerza una sesión de 60s con avisos -> debe verse el overlay de cuenta atrás al final."""
        st = load_state()
        st["play_until"] = now_epoch() + 60
        st["play_alerts"] = {
            "enabled": True,
            "m10": True,  # marcados para que solo entre en 5/1 y countdown
            "m5": True,
            "m1": False,
            "countdown_started": False,
        }
        st["play_countdown"] = 0
        st["play_end_notified"] = False
        save_state(st)
        log.info("PRUEBA overlay último minuto: sesión de 60s creada.")
        messagebox.showinfo("Prueba", "Se creó una sesión de 60s.\nAl final debe aparecer la ventana de cuenta atrás.")

    def _stop(self):
        st = load_state()
        st["play_until"] = 0
        st["play_whitelist"] = []
        st["play_alerts"] = {
            "enabled": True, "m10": False, "m5": False, "m1": False, "countdown_started": False,
        }
        st["play_countdown"] = 0
        st["play_end_notified"] = False
        save_state(st)
        log.info("Sesión manual cancelada por el usuario.")
        messagebox.showinfo("OK", "Sesión cancelada.")
        self._refresh_status_label()

    # ---------------- Guardar / Señal ----------------
    def _save_schedules(self):
        scheds = list(self._pending_schedules or [])
        for s in scheds:
            if not s.get("days") or not TIME_RE.match(s.get("from","")) or not TIME_RE.match(s.get("to","")):
                messagebox.showerror("Error", "Hay tramos inválidos. Revísalos.")
                log.warning("Intento de guardar horarios con tramos inválidos.")
                return
            if s["from"] > s["to"]:
                messagebox.showerror("Error", "Un tramo cruza medianoche. Divide en dos tramos.")
                log.warning("Intento de guardar tramo cruzando medianoche.")
                return

        cfg = load_config()
        cfg["schedules"] = scheds
        save_config(cfg)
        self._signal_schedules_changed()
        messagebox.showinfo("OK", "Horarios guardados y aplicados.")
        log.info("Horarios guardados (%d tramos).", len(scheds))
        self._reload_tree_from_cfg()
        self._refresh_status_label()

    def _signal_schedules_changed(self):
        st = load_state()
        st["schedules_changed_at"] = now_epoch()
        save_state(st)
        log.debug("Signal 'schedules_changed_at' actualizado.")
        self._refresh_status_label()

    # ---------------- Refresco de estado ----------------
    def _refresh_status_label(self):
        try:
            cfg = load_config()
            st = load_state()
            now = datetime.now()
            allowed = is_play_allowed(cfg, st, now)
            until = int(st.get("play_until") or 0)
            remaining = max(0, until - now_epoch())
            mm, ss = divmod(remaining, 60)
            enabled = bool(cfg.get("playtime_enabled", True))
            wl = (cfg.get("game_whitelist") or [])

            if not enabled:
                msg = "Control de tiempo: Desactivado — bloqueos base activos."
                self.lbl_status.configure(text=msg)
                return

            extra = ""
            if allowed and until <= 0 and not wl:
                extra = " — Nota: whitelist vacía (no hay juegos permitidos)."

            msg = f"Control de tiempo: Activado — Ahora permitido: {'Sí' if allowed else 'No'}{extra}"
            if until > 0 and remaining > 0:
                msg += f" — Sesión manual restante: {mm}m {ss}s"
            elif until > 0 and remaining <= 0:
                msg += " — Sesión manual finalizada."
            self.lbl_status.configure(text=msg)
        except Exception as e:
            log.error("Error refrescando estado: %s", e, exc_info=True)

    # ---------------- Treeview: añadir/editar/borrar ----------------
    def _add_schedule_dialog(self, preset: dict | None = None):
        dlg = _ScheduleDialog(self, preset)
        self.wait_window(dlg.top)
        if not dlg.result:
            return
        new_item = dlg.result
        if not self._pending_schedules:
            self._pending_schedules = []
        self._pending_schedules.append(new_item)
        log.info("Tramo añadido: %s %s-%s", new_item["days"], new_item["from"], new_item["to"])
        self._reload_tree_from_pending()

    def _edit_selected_schedule(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Sin selección", "Selecciona un tramo primero.")
            return
        idx = self.tree.index(sel[0])
        try:
            preset = dict(self._pending_schedules[idx])
        except Exception:
            return
        dlg = _ScheduleDialog(self, preset)
        self.wait_window(dlg.top)
        if not dlg.result:
            return
        self._pending_schedules[idx] = dlg.result
        log.info("Tramo editado (idx=%d): %s %s-%s", idx, dlg.result["days"], dlg.result["from"], dlg.result["to"])
        self._reload_tree_from_pending()

    def _delete_selected_schedule(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Sin selección", "Selecciona un tramo primero.")
            return
        idx = self.tree.index(sel[0])
        try:
            removed = self._pending_schedules.pop(idx)
            log.info("Tramo eliminado (idx=%d): %s %s-%s", idx, removed["days"], removed["from"], removed["to"])
        except Exception:
            pass
        self._reload_tree_from_pending()

    def _on_tree_double_click(self, _event):
        self._edit_selected_schedule()

    def _load_example_schedules(self):
        try:
            cfg = load_config()
            cfg["schedules"] = build_example_schedules()
            save_config(cfg)
            log.info("Cargados horarios de ejemplo.")
            self._reload_tree_from_cfg()
            self._signal_schedules_changed()
            messagebox.showinfo("OK", "Ejemplo cargado. (L–V 18–19, S/D mañana y tarde)")
        except Exception as e:
            log.error("Error cargando ejemplo: %s", e, exc_info=True)
            messagebox.showerror("Error", f"No se pudo cargar el ejemplo:\n{e}")


# ---------------- Diálogo de tramo horario ----------------
class _ScheduleDialog:
    def __init__(self, parent: TimePage, preset: dict | None):
        self.parent = parent
        self.result = None

        self.top = tk.Toplevel(parent)
        self.top.title("Tramo horario")
        self.top.transient(parent)
        self.top.grab_set()
        try:
            self.top.attributes("-topmost", True)
            self.top.after(50, lambda: self.top.attributes("-topmost", False))
        except Exception:
            pass

        pad = {"padx": 8, "pady": 6}
        ttk.Label(self.top, text="Días permitidos:").grid(row=0, column=0, sticky="w", **pad)

        self.day_vars = {d: tk.BooleanVar(value=False) for d in DAYS_ORDER}
        days_frame = ttk.Frame(self.top)
        days_frame.grid(row=1, column=0, columnspan=3, sticky="w", **pad)

        for i, d in enumerate(DAYS_ORDER):
            ttk.Checkbutton(days_frame, text=DAYS_LABELS[d], variable=self.day_vars[d]).grid(row=0, column=i, sticky="w", padx=4)

        ttk.Label(self.top, text="Desde (HH:MM):").grid(row=2, column=0, sticky="w", **pad)
        self.ent_from = ttk.Entry(self.top, width=8)
        self.ent_from.grid(row=2, column=1, sticky="w", **pad)
        ttk.Label(self.top, text="Hasta (HH:MM):").grid(row=3, column=0, sticky="w", **pad)
        self.ent_to = ttk.Entry(self.top, width=8)
        self.ent_to.grid(row=3, column=1, sticky="w", **pad)

        btns = ttk.Frame(self.top)
        btns.grid(row=4, column=0, columnspan=3, sticky="e", **pad)
        ttk.Button(btns, text="Aceptar", command=self._ok).pack(side="left", padx=4)
        ttk.Button(btns, text="Cancelar", command=self._cancel).pack(side="left", padx=4)

        # Rellenar preset si lo hay
        if preset:
            days = [d[:3].lower() for d in preset.get("days", [])]
            for d in DAYS_ORDER:
                self.day_vars[d].set(d in days)
            self.ent_from.insert(0, preset.get("from", ""))
            self.ent_to.insert(0, preset.get("to", ""))
        else:
            self.ent_from.insert(0, "18:00")
            self.ent_to.insert(0, "19:00")

        # focus
        self.ent_from.focus_set()
        self.top.bind("<Return>", lambda _e: self._ok())
        self.top.bind("<Escape>", lambda _e: self._cancel())

    def _ok(self):
        days = [d for d in DAYS_ORDER if self.day_vars[d].get()]
        f = self.ent_from.get().strip()
        t = self.ent_to.get().strip()
        if not days:
            messagebox.showerror("Error", "Selecciona al menos un día.", parent=self.top)
            return
        if not TIME_RE.match(f) or not TIME_RE.match(t):
            messagebox.showerror("Error", "Formato de hora inválido (HH:MM).", parent=self.top)
            return
        if f > t:
            messagebox.showerror("Error", "El tramo cruza medianoche (divide en dos).", parent=self.top)
            return
        self.result = {"days": days, "from": f, "to": t}
        self.top.destroy()

    def _cancel(self):
        self.top.destroy()
