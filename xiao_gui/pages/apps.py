# pages/apps.py — XiaoHack GUI — Pestaña Aplicaciones/Juegos (depurada)
from __future__ import annotations

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from app.logs import get_logger
from app.storage import load_config, save_config, update_config  # normaliza y guarda  # noqa: F401
from xiao_gui.icon_manager import IconManager

# Fallbacks suaves si utils no está disponible aún
try:
    from utils.tk_safe import after_safe  # asegura after() contra widgets destruidos
except Exception:
    def after_safe(widget, ms, func):
        # Fallback: mejor esfuerzo
        try:
            widget.after(ms, func)
        except Exception:
            pass

try:
    from utils.async_tasks import TaskGate
except Exception:
    class TaskGate:
        def __init__(self): self._rev = 0
        def next_rev(self):
            self._rev += 1
            return self._rev
        def is_current(self, rev): return rev == self._rev

# Bloqueo de prueba vía auditoría (sustituye a test_app.utils.log_block_event_for_test)
try:
    from app.audit import AuditLogger
    _AUDIT = AuditLogger()
except Exception:
    _AUDIT = None

log = get_logger("gui.apps")


class AppsPage(ttk.Frame):
    """Pestaña de Aplicaciones/Juegos (sin UI de whitelist)."""

    def __init__(self, master, cfg: dict, dark: bool):
        super().__init__(master)
        self.cfg = cfg
        self.dark = dark

        self.iconman = IconManager()
        self._icon_h = 22
        self._img_refs: dict[str, tk.PhotoImage] = {}    # iid -> PhotoImage (evitar GC)
        self._rules_ctx_menu: tk.Menu | None = None      # menú contextual
        self._gate = TaskGate()                          # anti-carreras al entrar/salir

        self._cfg_snapshot = self._snapshot_from_cfg(cfg)
        self._build()
        log.debug("AppsPage inicializada (blocked=%d)", len(cfg.get("blocked_apps", [])))

    # --------- Hooks para app.py ----------
    def on_show_async(self, rev=None):
        """Llamado al entrar en la pestaña. Ligero, sin bloquear la UI."""
        if rev is None:
            rev = self._gate.next_rev()
        new_cfg = load_config()
        new_snap = self._snapshot_from_cfg(new_cfg)
        if new_snap != self._cfg_snapshot:
            log.info("Config actualizada en disco; recargando reglas de apps.")
            self._cfg_snapshot = new_snap
            self.cfg = new_cfg

            def _apply():
                if not self._gate.is_current(rev) or not self.winfo_exists():
                    return
                self._reload_from_cfg()

            after_safe(self, 0, _apply)

    def refresh_lite(self):  # compat
        pass

    def has_unsaved_changes(self) -> bool:
        current = self.collect()
        base = {
            "blocked_apps":           sorted(self.cfg.get("blocked_apps", []) or []),
            "blocked_executables":    sorted(self.cfg.get("blocked_executables", []) or []),
            "blocked_paths":          sorted(self.cfg.get("blocked_paths", []) or []),
        }
        mine = {
            "blocked_apps":           sorted(current["blocked_apps"]),
            "blocked_executables":    sorted(current["blocked_executables"]),
            "blocked_paths":          sorted(current["blocked_paths"]),
        }
        dirty = mine != base
        if dirty:
            log.debug("Cambios sin guardar detectados en pestaña Apps.")
        return dirty

    # -------------------------------------
    def _build(self):
        pad = {"padx": 8, "pady": 6}
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        frame_rules = ttk.LabelFrame(self, text="Reglas de bloqueo")
        frame_rules.grid(row=0, column=0, sticky="nsew", **pad)
        frame_rules.grid_columnconfigure(0, weight=1)
        frame_rules.grid_rowconfigure(0, weight=1)

        cols = ("tipo", "valor", "detalle")
        self.tv = ttk.Treeview(frame_rules, columns=cols, show="tree headings")
        self.tv.heading("#0", text="Elemento")
        self.tv.column("#0", width=220, anchor="w")
        for c, t in zip(cols, ("Tipo", "Valor", "Detalle")):
            self.tv.heading(c, text=t)
        self.tv.column("tipo", width=120, anchor="w")
        self.tv.column("valor", width=300, anchor="w")
        self.tv.column("detalle", width=240, anchor="w")

        vsb = ttk.Scrollbar(frame_rules, orient="vertical", command=self.tv.yview)
        hsb = ttk.Scrollbar(frame_rules, orient="horizontal", command=self.tv.xview)
        self.tv.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tv.grid(row=0, column=0, sticky="nsew", padx=6, pady=(6, 0))
        vsb.grid(row=0, column=1, sticky="ns", pady=(6, 0))
        hsb.grid(row=1, column=0, sticky="ew",  padx=6, pady=(0, 6))

        # Cargar datos iniciales
        self._reload_from_cfg()

        # Controles inferiores
        controls = ttk.Frame(frame_rules)
        controls.grid(row=2, column=0, columnspan=2, sticky="ew", padx=6, pady=6)
        for c in range(0, 7):
            controls.grid_columnconfigure(c, weight=1)

        ttk.Label(controls, text="Nombre (.exe):").grid(row=0, column=0, sticky="w", **pad)
        ent_name = ttk.Entry(controls)
        ent_name.grid(row=0, column=1, sticky="ew", **pad)

        ttk.Label(controls, text="Ruta exacta (.exe):").grid(row=1, column=0, sticky="w", **pad)
        ent_path = ttk.Entry(controls)
        ent_path.grid(row=1, column=1, sticky="ew", **pad)

        ttk.Label(controls, text="Carpeta:").grid(row=2, column=0, sticky="w", **pad)
        ent_folder = ttk.Entry(controls)
        ent_folder.grid(row=2, column=1, sticky="ew", **pad)

        # Funciones locales ---------------------
        def add_name_text():
            v = ent_name.get().strip()
            if v:
                self._insert_rule("Nombre", v, "Bloqueo por nombre (.exe)")
                log.info("Añadida regla por nombre: %s", v)
                ent_name.delete(0, "end")

        def add_name_exe():
            p = filedialog.askopenfilename(
                title="Selecciona .exe (añadir por NOMBRE)",
                filetypes=[("Aplicaciones", "*.exe")],
            )
            if p:
                n = os.path.basename(p)
                self._insert_rule("Nombre", n, "Bloqueo por nombre (.exe)")
                log.info("Añadida regla por nombre desde archivo: %s", n)

        def add_path_text():
            v = ent_path.get().strip()
            if v:
                self._insert_rule("Ruta", os.path.normpath(v), "Bloqueo por ruta exacta")
                log.info("Añadida regla por ruta manual: %s", v)
                ent_path.delete(0, "end")

        def add_path_exe():
            p = filedialog.askopenfilename(
                title="Selecciona .exe (bloquear por RUTA exacta)",
                filetypes=[("Aplicaciones", "*.exe")],
            )
            if p:
                self._insert_rule("Ruta", os.path.normpath(p), "Bloqueo por ruta exacta")
                log.info("Añadida regla por ruta desde archivo: %s", p)

        def add_folder_text():
            v = ent_folder.get().strip()
            if v:
                self._insert_rule("Carpeta", os.path.normpath(v), "Bloqueo por carpeta")
                log.info("Añadida regla de carpeta: %s", v)
                ent_folder.delete(0, "end")

        def add_folder_browse():
            d = filedialog.askdirectory(title="Selecciona carpeta a bloquear")
            if d:
                self._insert_rule("Carpeta", os.path.normpath(d), "Bloqueo por carpeta")
                log.info("Añadida carpeta bloqueada: %s", d)

        def add_folder_from_exe():
            p = filedialog.askopenfilename(
                title="Selecciona .exe (bloquear su carpeta)",
                filetypes=[("Aplicaciones", "*.exe")],
            )
            if p:
                folder = os.path.dirname(p)
                self._insert_rule("Carpeta", os.path.normpath(folder), "Bloqueo por carpeta")
                log.info("Añadida carpeta desde exe: %s", folder)

        def remove_selected():
            sel = self.tv.selection()
            if not sel:
                messagebox.showwarning("Sin selección", "Selecciona una o varias reglas primero.")
                return
            for iid in sel:
                self._img_refs.pop(iid, None)
                self.tv.delete(iid)
            log.info("Eliminadas %d reglas seleccionadas.", len(sel))

        # Botones
        ttk.Button(controls, text="Añadir nombre", command=add_name_text).grid(row=0, column=2, **pad)
        ttk.Button(controls, text="Desde .exe…", command=add_name_exe).grid(row=0, column=3, **pad)
        ttk.Button(controls, text="Añadir ruta", command=add_path_text).grid(row=1, column=2, **pad)
        ttk.Button(controls, text="Buscar .exe…", command=add_path_exe).grid(row=1, column=3, **pad)
        ttk.Button(controls, text="Añadir carpeta", command=add_folder_text).grid(row=2, column=2, **pad)
        ttk.Button(controls, text="Buscar carpeta…", command=add_folder_browse).grid(row=2, column=3, **pad)
        ttk.Button(controls, text="Desde .exe → carpeta…", command=add_folder_from_exe).grid(row=2, column=4, **pad)
        ttk.Button(controls, text="Eliminar seleccionados", command=remove_selected).grid(row=3, column=0, **pad)
        ttk.Button(controls, text="Añadir a Lista Blanca", command=self._add_selected_to_whitelist).grid(row=3, column=1, **pad)

        # Menú contextual y atajo
        self._rules_ctx_menu = tk.Menu(self, tearoff=0)
        self._rules_ctx_menu.add_command(label="Añadir a Lista Blanca", command=self._add_selected_to_whitelist)
        self.tv.bind("<Button-3>", self._show_rules_context_menu)
        self.bind_all("<Control-w>", lambda e: self._add_selected_to_whitelist())

        # Botón de prueba (inserta evento de bloqueo en auditoría si disponible)
        ttk.Button(
            self,
            text="Probar notificación de bloqueo",
            command=self._test_block_notification,
        ).grid(row=2, column=0, sticky="w", **pad)

    # ---- helpers ----
    def _snapshot_from_cfg(self, cfg: dict) -> dict:
        return {
            "blocked_apps": tuple(sorted(cfg.get("blocked_apps", []) or [])),
            "blocked_executables": tuple(sorted(cfg.get("blocked_executables", []) or [])),
            "blocked_paths": tuple(sorted(cfg.get("blocked_paths", []) or [])),
        }

    def _reload_from_cfg(self):
        """Borra el árbol y lo repuebla desde self.cfg."""
        for iid in self.tv.get_children(""):
            self._img_refs.pop(iid, None)
            self.tv.delete(iid)
        total = 0
        for n in self.cfg.get("blocked_apps", []):
            self._insert_rule("Nombre", n, "Bloqueo por nombre (.exe)")
            total += 1
        for p in self.cfg.get("blocked_executables", []):
            self._insert_rule("Ruta", os.path.normpath(p), "Bloqueo por ruta exacta")
            total += 1
        for p in self.cfg.get("blocked_paths", []):
            self._insert_rule("Carpeta", os.path.normpath(p), "Bloqueo por carpeta")
            total += 1
        log.info("Reglas recargadas: %d entradas.", total)

    def _insert_rule(self, tipo: str, valor: str, detalle: str):
        try:
            img = self.iconman.icon_for_entry(tipo, valor, max_h=self._icon_h)
            text = self.iconman.label_for_entry(tipo, valor)
            iid = self.tv.insert("", "end", text=text, image=img, values=(tipo, valor, detalle))
            if img:
                self._img_refs[iid] = img
        except Exception as e:
            log.error("Error insertando regla (%s %s): %s", tipo, valor, e)

    def _exe_from_rule(self, tipo: str, valor: str) -> str | None:
        if tipo == "Nombre":
            return valor.strip()
        if tipo == "Ruta":
            base = os.path.basename(valor.strip())
            return base if base else None
        return None

    def _add_selected_to_whitelist(self):
        sel = self.tv.selection()
        if not sel:
            messagebox.showwarning("Sin selección", "Selecciona una o varias reglas primero.")
            return
        names: list[str] = []
        for iid in sel:
            tipo, valor, _ = self.tv.item(iid, "values")
            n = self._exe_from_rule(tipo, valor)
            if n:
                names.append(n)
        if not names:
            messagebox.showinfo("Nada que añadir", "Las reglas seleccionadas no contienen ejecutables identificables.")
            return
        added = self._add_to_whitelist_storage(names)
        if added:
            messagebox.showinfo("Añadido a la Lista Blanca", "Se añadieron: " + ", ".join(added))
            log.info("Añadidos a lista blanca: %s", ", ".join(added))
        else:
            messagebox.showinfo("Sin cambios", "Todos los elementos ya estaban en la Lista Blanca.")

    def _add_to_whitelist_storage(self, names: list[str]) -> list[str]:
        """Fusiona con storage evitando duplicados. Devuelve los realmente añadidos (antes→después)."""
        try:
            # Snapshot previo (para calcular “added” con precisión)
            cfg0 = load_config()
            prev = set(cfg0.get("game_whitelist", []) or [])

            def _mut(cfg):
                cur = set(cfg.get("game_whitelist", []) or [])
                for n in (x.strip() for x in names):
                    if n:
                        cur.add(n)
                cfg["game_whitelist"] = sorted(cur)
                return cfg

            cfg = update_config(_mut)   # normaliza y guarda
            self.cfg = cfg
            self._cfg_snapshot = self._snapshot_from_cfg(cfg)

            after = set(cfg.get("game_whitelist", []) or [])
            added = sorted(after - prev)
            return added
        except Exception as e:
            log.error("Error actualizando lista blanca: %s", e, exc_info=True)
            return []

    def _show_rules_context_menu(self, event):
        row = self.tv.identify_row(event.y)
        if row and row not in self.tv.selection():
            self.tv.selection_set(row)
        try:
            self._rules_ctx_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self._rules_ctx_menu.grab_release()

    def collect(self) -> dict:
        """Devuelve las reglas actuales (bloqueos)."""
        ba, be, bp = [], [], []

        def dedupe(seq):
            seen, out = set(), []
            for x in seq:
                if x not in seen:
                    seen.add(x)
                    out.append(x)
            return out

        for iid in self.tv.get_children(""):
            tipo, valor, _ = self.tv.item(iid, "values")
            if not valor:
                continue
            if tipo == "Nombre":
                ba.append(valor.strip())
            elif tipo == "Ruta":
                be.append(os.path.normpath(valor.strip()))
            elif tipo == "Carpeta":
                bp.append(os.path.normpath(valor.strip()))
        return {
            "blocked_apps": dedupe(ba),
            "blocked_executables": dedupe(be),
            "blocked_paths": dedupe(bp),
        }

    def _save_rules(self):
        """Guarda bloqueos en storage sin tocar game_whitelist."""
        try:
            data = self.collect()

            def _mut(cfg):
                cfg["blocked_apps"] = data["blocked_apps"]
                cfg["blocked_executables"] = data["blocked_executables"]
                cfg["blocked_paths"] = data["blocked_paths"]
                return cfg

            cfg = update_config(_mut)  # normaliza y guarda
            self.cfg = cfg
            self._cfg_snapshot = self._snapshot_from_cfg(cfg)
            messagebox.showinfo("OK", "Reglas guardadas correctamente.\nSe aplicarán en unos segundos.")
            log.info(
                "Reglas guardadas (%d total).",
                len(data["blocked_apps"]) + len(data["blocked_executables"]) + len(data["blocked_paths"]),
            )
        except Exception as e:
            messagebox.showerror("Error", f"No se pudieron guardar las reglas:\n{e}")
            log.error("Error guardando reglas: %s", e, exc_info=True)

    def _test_block_notification(self):
        """Inserta un evento de bloqueo de prueba para que el Notifier lo muestre."""
        try:
            if _AUDIT is None:
                raise RuntimeError("AuditLogger no disponible")
            _AUDIT.log_block("AplicacionDePrueba.exe", reason="test/gui")
            messagebox.showinfo(
                "OK",
                "Se insertó un bloqueo de prueba.\nSi el Notifier está activo, verás la notificación en unos segundos.",
            )
        except Exception as e:
            log.error("No se pudo registrar el bloqueo de prueba: %s", e)
            messagebox.showerror("Error", f"No se pudo registrar el bloqueo de prueba:\n{e}")

    def apply_theme(self, dark: bool):
        self.dark = dark
