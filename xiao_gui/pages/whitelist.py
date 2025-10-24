# xiao_gui/pages/whitelist.py — Pestaña "Lista Blanca de juegos"
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from storage import load_config
from logs import get_logger
from utils.tk_safe import after_safe
from xiao_gui.icon_manager import IconManager

# Gate opcional
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

log = get_logger("gui.whitelist")


class GameWhitelistPage(ttk.Frame):
    """Gestión de la lista blanca de juegos (.exe)"""

    def __init__(self, master, cfg: dict, dark: bool):
        super().__init__(master)
        self.cfg = cfg or {}
        self.dark = dark

        self.iconman = IconManager()
        self._icon_h = 22
        self._img_refs: dict[str, tk.PhotoImage] = {}

        self._gate = TaskGate()
        self._cfg_snapshot = tuple(sorted(self.cfg.get("game_whitelist", []) or []))

        self._build()
        self.on_show_async(None)
        log.debug("WhitelistPage inicializada con %d elementos.", len(self._cfg_snapshot))

    # ---------------------- Integración con app.py ----------------------
    def on_show_async(self, rev=None):
        rev = self._gate.next_rev() if rev is None else rev
        log.debug("on_show_async lanzado (rev=%s)", rev)

        def _work(rev_local: int):
            try:
                cfg = load_config()
                new_list = tuple(sorted(cfg.get("game_whitelist", []) or []))
                err = None
            except Exception as e:
                cfg, new_list, err = None, None, e

            def _apply():
                if not self.winfo_exists() or (rev_local and not self._gate.is_current(rev_local)):
                    return
                if err:
                    log.error("Error al leer configuración: %s", err, exc_info=True)
                    messagebox.showwarning("Aviso", f"No se pudo leer la configuración:\n{type(err).__name__}: {err}")
                    return
                if new_list != self._cfg_snapshot:
                    self._repoblar(new_list or ())
                    self.cfg = cfg or {}
                    self._cfg_snapshot = new_list or ()
                    log.info("Lista Blanca actualizada desde disco (%d elementos).", len(new_list or []))
            after_safe(self, 0, _apply)

        submit_limited(_work, rev)

    def refresh_lite(self):
        """Refresco rápido (sin IO)"""
        current = tuple(sorted(self.get_whitelist()))
        if current != self._cfg_snapshot:
            log.debug("Desfase detectado en refresh_lite (UI=%d, cfg=%d).", len(current), len(self._cfg_snapshot))
            self._repoblar(self._cfg_snapshot)

    def has_unsaved_changes(self) -> bool:
        current = tuple(sorted(self.get_whitelist()))
        diff = current != self._cfg_snapshot
        if diff:
            log.debug("Detectados cambios no guardados en la lista blanca.")
        return diff

    # ----------------------------- UI ----------------------------------
    def _build(self):
        pad = {"padx": 8, "pady": 6}
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        frm = ttk.LabelFrame(self, text="Lista blanca de juegos (.exe permitidos)")
        frm.grid(row=0, column=0, sticky="nsew", **pad)
        frm.grid_columnconfigure(0, weight=1)
        frm.grid_rowconfigure(0, weight=1)

        cols = ("tipo", "valor", "detalle")
        self.tv = ttk.Treeview(frm, columns=cols, show="tree headings")
        self.tv.heading("#0", text="Elemento")
        self.tv.column("#0", width=260, anchor="w")

        for c, t in zip(cols, ("Tipo", "Valor", "Detalle")):
            self.tv.heading(c, text=t)
        self.tv.column("tipo", width=120, anchor="w")
        self.tv.column("valor", width=320, anchor="w")
        self.tv.column("detalle", width=240, anchor="w")

        vsb = ttk.Scrollbar(frm, orient="vertical", command=self.tv.yview)
        hsb = ttk.Scrollbar(frm, orient="horizontal", command=self.tv.xview)
        self.tv.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tv.grid(row=0, column=0, sticky="nsew", padx=6, pady=(6, 0))
        vsb.grid(row=0, column=1, sticky="ns", pady=(6, 0))
        hsb.grid(row=1, column=0, sticky="ew", padx=6, pady=(0, 6))

        self._ctx = tk.Menu(self, tearoff=0)
        self._ctx.add_command(label="Eliminar", command=self._remove_selected)
        self.tv.bind("<Button-3>", self._show_ctx_menu)

        # Poblado inicial
        for name in self.cfg.get("game_whitelist", []):
            self._insert_item(name)

        # --- Controles inferiores ---
        ctr = ttk.Frame(frm)
        ctr.grid(row=2, column=0, columnspan=2, sticky="ew", padx=6, pady=6)
        for c in range(0, 6):
            ctr.grid_columnconfigure(c, weight=1)

        ttk.Label(ctr, text="Nombre (.exe):").grid(row=0, column=0, sticky="w", **pad)
        self._ent = ttk.Entry(ctr)
        self._ent.grid(row=0, column=1, sticky="ew", **pad)

        ttk.Button(ctr, text="Añadir nombre", command=self._add_text).grid(row=0, column=2, **pad)
        ttk.Button(ctr, text="Desde .exe…", command=self._add_from_exe).grid(row=0, column=3, **pad)
        ttk.Button(ctr, text="Eliminar", command=self._remove_selected).grid(row=0, column=4, **pad)

        ttk.Label(self, text="La Lista Blanca tiene prioridad sobre el bloqueo por NOMBRE (.exe).")\
           .grid(row=1, column=0, sticky="w", **pad)

    # ----------------------------- Helpers -----------------------------
    def _show_ctx_menu(self, event):
        row = self.tv.identify_row(event.y)
        if row and row not in self.tv.selection():
            self.tv.selection_set(row)
        try:
            self._ctx.tk_popup(event.x_root, event.y_root)
        finally:
            self._ctx.grab_release()

    def _insert_item(self, exe_name: str):
        exe_name = exe_name.strip()
        if not exe_name or self._exists(exe_name):
            return
        img = self.iconman.icon_for_entry("Nombre", exe_name, max_h=self._icon_h)
        text = self.iconman.label_for_entry("Nombre", exe_name)
        iid = self.tv.insert("", "end", text=text, image=img,
                             values=("Nombre", exe_name, "Permitido (Lista Blanca)"))
        if img:
            self._img_refs[iid] = img
        log.debug("Añadido a la lista blanca: %s", exe_name)

    def _exists(self, exe_name: str) -> bool:
        for iid in self.tv.get_children(""):
            _tipo, _valor, _ = self.tv.item(iid, "values")
            if str(_valor).lower() == exe_name.lower():
                return True
        return False

    def _remove_selected(self):
        sel = self.tv.selection()
        if not sel:
            return
        for iid in sel:
            _tipo, val, _ = self.tv.item(iid, "values")
            log.info("Eliminado de lista blanca: %s", val)
            self._img_refs.pop(iid, None)
            self.tv.delete(iid)

    def _add_text(self):
        v = self._ent.get().strip()
        if v:
            self._insert_item(v)
            self._ent.delete(0, "end")
            log.info("Elemento añadido manualmente: %s", v)

    def _add_from_exe(self):
        p = filedialog.askopenfilename(title="Seleccionar .exe para Lista Blanca",
                                       filetypes=[("Aplicaciones", "*.exe")])
        if p:
            exe = os.path.basename(p)
            self._insert_item(exe)
            log.info("Añadido desde archivo: %s", exe)

    # ----------------------------- API pública -----------------------------
    def get_whitelist(self):
        out = []
        for iid in self.tv.get_children(""):
            _tipo, _valor, _ = self.tv.item(iid, "values")
            if _valor:
                out.append(_valor)
        return out

    def reload_from_storage(self):
        try:
            cfg = load_config()
            items = tuple(sorted(cfg.get("game_whitelist", []) or []))
            if items == self._cfg_snapshot:
                return
            self._repoblar(items)
            self.cfg = cfg
            self._cfg_snapshot = items
            log.info("Lista blanca recargada desde disco (%d elementos).", len(items))
        except Exception as e:
            log.error("Error recargando lista blanca: %s", e, exc_info=True)
            messagebox.showwarning("Aviso", f"No se pudo refrescar la lista blanca:\n{e}")

    # ----------------------------- Tema -----------------------------
    def apply_theme(self, dark: bool):
        self.dark = dark
        log.debug("Tema aplicado en Whitelist (dark=%s)", dark)

    # ----------------------------- Internos -----------------------------
    def _repoblar(self, iterable):
        for iid in self.tv.get_children(""):
            self._img_refs.pop(iid, None)
            self.tv.delete(iid)
        for name in iterable or ():
            self._insert_item(name)
        log.debug("Repoblado tree con %d elementos.", len(iterable or []))
