# web.py — Pestaña Web/SafeSearch (tab-safe, sin bloqueos en UI)
import re
import sys
import ctypes
import webbrowser
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
from storage import load_state, save_state

from utils.tk_safe import after_safe
from webfilter import (
    ensure_hosts_rules,
    rollback_hosts,
    remove_parental_block,
    HOSTS,
    GOOGLE_TLDS,
    GOOGLE_SAFE_IP, BING_STRICT_IP, YANDEX_FAMILY_IP,
)

from logs import get_logger
log = get_logger("gui.web")

# Gate + pool global limitado (evita avalanchas si cambias rápido de pestañas)
try:
    from utils.async_tasks import TaskGate, submit_limited
except Exception:
    # Fallback mínimo por si el helper no está disponible
    from concurrent.futures import ThreadPoolExecutor
    _EXEC = ThreadPoolExecutor(max_workers=2)
    class TaskGate:
        def __init__(self): self._rev = 0
        def next_rev(self): 
            self._rev += 1
            return self._rev
        def is_current(self, rev): return rev == self._rev
    def submit_limited(fn, *a, **k): return _EXEC.submit(fn, *a, **k)

BLOCK_RE = re.compile(r"(?ms)^\s*# === PARENTAL_BEGIN ===\s*$.*?^\s*# === PARENTAL_END ===\s*$")

# ===== Helpers UAC =====
def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def relaunch_as_admin():
    params = " ".join(f'"{a}"' for a in sys.argv)
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)


class WebPage(ttk.Frame):
    def __init__(self, master, cfg: dict, on_save_cfg):
        super().__init__(master)
        # defaults nuevos:
        self.cfg = cfg
        self.cfg.setdefault("safesearch", False)
        self.cfg.setdefault("block_www", True)
        self.cfg.setdefault("google_tlds", GOOGLE_TLDS.copy())
        self.cfg.setdefault("domains_enabled", True) 


        self.on_save_cfg = on_save_cfg
        self._dirty = False
        self._nb = None
        self._nb_my_tab_id = None

        # Anti-avalanchas de cargas
        self._gate = TaskGate()

        self._build()
        self._auto_attach_notebook_guard()

        # Carga inicial en background como si se mostrara la pestaña
        self.on_show_async(None)

    # ---------------- Integración con app.py ----------------
    def on_show_async(self, rev=None):
        """Llamado al entrar en la pestaña. Refresca estado sin bloquear la UI."""
        rev = self._gate.next_rev() if rev is None else rev
        submit_limited(self._task_load_state, rev)

    def refresh_lite(self):
        """Gancho ligero por si el app llama antes de on_show_async()."""
        # Aquí no realizamos IO; mantenemos método por coherencia
        pass

    # ---------------- UI ----------------
    def _build(self):
        self.columnconfigure(0, weight=1)
        pad = {"padx": 10, "pady": 8}

        # Header
        header = ttk.Frame(self)
        header.grid(row=0, column=0, sticky="ew", **pad)
        header.columnconfigure(1, weight=1)

        self.lbl_title = ttk.Label(header, text="Web — SafeSearch y bloqueos", style="Headline.TLabel")
        self.lbl_title.grid(row=0, column=0, sticky="w")
        self.lbl_status = ttk.Label(header, text="Estado: …")
        self.lbl_status.grid(row=0, column=1, sticky="e")

        self.lbl_elev = ttk.Label(header, text="")
        self.lbl_elev.grid(row=1, column=0, sticky="w", pady=(4, 0))
        ttk.Button(header, text="Reiniciar como Administrador", command=relaunch_as_admin)\
            .grid(row=1, column=1, sticky="e", pady=(4, 0))

        ttk.Separator(self).grid(row=1, column=0, sticky="ew", padx=10)

        # --- (2) SafeSearch / Modo restringido ---
        lf_safe = ttk.LabelFrame(self, text="SafeSearch / Modo restringido")
        lf_safe.grid(row=2, column=0, sticky="ew", **pad)
        lf_safe.columnconfigure(0, weight=1)

        self.var_safe = tk.BooleanVar(value=bool(self.cfg.get("safesearch", False)))
        ttk.Checkbutton(
            lf_safe,
            text="Forzar Google SafeSearch + YouTube Restrict + Bing Strict + Yandex Family",
            variable=self.var_safe, command=self._mark_dirty
        ).grid(row=0, column=0, sticky="w", pady=(6, 2))

        ttk.Label(
            lf_safe,
            text="Requiere ejecutar como Administrador (para escribir en hosts).\nSi el navegador usa DNS seguro/DoH, puede ignorar el hosts local."
        ).grid(row=1, column=0, sticky="w", pady=(0, 6))

        # --- (3) TLDs de Google ---
        lf_tld = ttk.LabelFrame(self, text="TLDs de Google")
        lf_tld.grid(row=3, column=0, sticky="nsew", **pad)
        lf_tld.columnconfigure(0, weight=1)
        lf_tld.rowconfigure(0, weight=1)

        wrap_tld = ttk.Frame(lf_tld)
        wrap_tld.grid(row=0, column=0, sticky="nsew")
        wrap_tld.columnconfigure(0, weight=1)
        wrap_tld.rowconfigure(0, weight=1)

        self.lst_tlds = tk.Listbox(
            wrap_tld, height=6, activestyle="dotbox",
            selectmode="extended", exportselection=False
        )
        self.lst_tlds.grid(row=0, column=0, sticky="nsew")
        vs_tld = ttk.Scrollbar(wrap_tld, orient="vertical", command=self.lst_tlds.yview)
        vs_tld.grid(row=0, column=1, sticky="ns")
        self.lst_tlds.configure(yscrollcommand=vs_tld.set)

        for t in self.cfg.get("google_tlds", GOOGLE_TLDS):
            self.lst_tlds.insert("end", t)

        right_tld = ttk.Frame(lf_tld)
        right_tld.grid(row=0, column=1, sticky="n", padx=8)
        right_tld.columnconfigure(0, weight=1)

        self.ent_tld = ttk.Entry(right_tld, width=28)
        self.ent_tld.grid(row=0, column=0, sticky="ew")
        self.ent_tld.bind("<FocusOut>", lambda e: self._mark_dirty() if self.ent_tld.get().strip() else None)

        ttk.Button(right_tld, text="Añadir TLD", command=self._add_tld)\
            .grid(row=1, column=0, sticky="ew", pady=(6, 0))
        ttk.Button(right_tld, text="Eliminar TLD", command=self._del_tld)\
            .grid(row=2, column=0, sticky="ew", pady=(6, 0))

        self.lbl_tld_count = ttk.Label(right_tld, text="0 TLDs")
        self.lbl_tld_count.grid(row=3, column=0, sticky="w", pady=(8, 0))

        # --- (4) Opción www. ---
        self.var_www = tk.BooleanVar(value=bool(self.cfg.get("block_www", True)))
        ttk.Checkbutton(
            self, text="Duplicar ‘www.’ para dominios base",
            variable=self.var_www, command=self._mark_dirty
        ).grid(row=4, column=0, sticky="w", **pad)

        # --- (5) Dominios bloqueados ---
        lf_blk = ttk.LabelFrame(self, text="Dominios bloqueados (hosts → 0.0.0.0)")
        lf_blk.grid(row=5, column=0, sticky="nsew", **pad)
        self.rowconfigure(5, weight=1)
        lf_blk.columnconfigure(0, weight=1)
        lf_blk.rowconfigure(1, weight=1)

        # NUEVO: switch maestro
        self.var_domains_enabled = tk.BooleanVar(value=bool(self.cfg.get("domains_enabled", True)))
        ttk.Checkbutton(
            lf_blk,
            text="Activar bloqueo de dominios (hosts → 0.0.0.0)",
            variable=self.var_domains_enabled,
            command=self._mark_dirty
        ).grid(row=0, column=0, sticky="w", pady=(6, 6), columnspan=2)

        wrap = ttk.Frame(lf_blk)
        wrap.grid(row=1, column=0, sticky="nsew")
        wrap.columnconfigure(0, weight=1)
        wrap.rowconfigure(0, weight=1)

        self.lst_domains = tk.Listbox(wrap, height=10, activestyle="dotbox",
                                      selectmode="extended", exportselection=False)
        self.lst_domains.grid(row=0, column=0, sticky="nsew")
        vsb = ttk.Scrollbar(wrap, orient="vertical", command=self.lst_domains.yview)
        vsb.grid(row=0, column=1, sticky="ns")
        self.lst_domains.configure(yscrollcommand=vsb.set)

        for d in self.cfg.get("blocked_domains", []):
            self.lst_domains.insert("end", d)

        right = ttk.Frame(lf_blk)
        right.grid(row=1, column=1, sticky="n", padx=8)
        right.columnconfigure(0, weight=1)

        self.ent_d = ttk.Entry(right, width=28)
        self.ent_d.grid(row=0, column=0, sticky="ew")
        self.ent_d.bind("<Return>", lambda e: self._add_domain())

        ttk.Button(right, text="Añadir", command=self._add_domain).grid(row=1, column=0, sticky="ew", pady=(6, 0))
        ttk.Button(right, text="Editar seleccionado", command=self._edit_selected).grid(row=2, column=0, sticky="ew", pady=(6, 0))
        ttk.Button(right, text="Eliminar seleccionado(s)", command=self._del_selected).grid(row=3, column=0, sticky="ew", pady=(6, 0))
        ttk.Button(right, text="Importar (TXT)", command=self._import_domains).grid(row=4, column=0, sticky="ew", pady=(12, 0))
        ttk.Button(right, text="Exportar (TXT)", command=self._export_domains).grid(row=5, column=0, sticky="ew", pady=(6, 0))

        self.lbl_count = ttk.Label(right, text="0 dominios")
        self.lbl_count.grid(row=6, column=0, sticky="w", pady=(8, 0))

        self._mk_context_menu()
        self.lst_domains.bind("<<ListboxSelect>>", lambda e: self._preview_dirty())

        # --- (6) Botonera inferior ---
        btns = ttk.Frame(self)
        btns.grid(row=6, column=0, sticky="ew", **pad)
        btns.columnconfigure(5, weight=1)

        ttk.Button(btns, text="Aplicar cambios", command=self._save_async).grid(row=0, column=0, padx=(0, 6))
        ttk.Button(btns, text="Eliminar bloque parental", command=self._remove_block_async).grid(row=0, column=1, padx=(0, 6))
        ttk.Button(btns, text="Restaurar backup hosts", command=self._restore_backup_async).grid(row=0, column=3, padx=(0, 6))
        ttk.Button(btns, text="Recargar estado", command=self._reload_state_async).grid(row=0, column=4, padx=(0, 6))
        ttk.Button(btns, text="Vaciar caché DNS", command=self._flush_dns_async).grid(row=0, column=5, padx=(0, 6))
        ttk.Button(btns, text="¿DoH activado?", command=self._show_doh_help).grid(row=0, column=6, padx=(0, 6))

        ttk.Separator(self).grid(row=7, column=0, sticky="ew", padx=10)

        # --- (7) Pruebas rápidas ---
        test = ttk.Frame(self)
        test.grid(row=8, column=0, sticky="ew", **pad)
        ttk.Label(test, text="Pruebas rápidas:").grid(row=0, column=0, sticky="w")
        ttk.Button(test, text="Abrir Google",  command=lambda: webbrowser.open("https://www.google.com")).grid(row=0, column=1, padx=6)
        ttk.Button(test, text="Abrir YouTube", command=lambda: webbrowser.open("https://www.youtube.com")).grid(row=0, column=2, padx=6)
        ttk.Button(test, text="Abrir Bing",    command=lambda: webbrowser.open("https://www.bing.com")).grid(row=0, column=3, padx=6)


        self._refresh_count()
        self._refresh_tld_count()

        try:
            s = ttk.Style()
            s.configure("Headline.TLabel", font=("Segoe UI", 12, "bold"))
        except Exception:
            pass

    # -------- Context menu --------
    def _mk_context_menu(self):
        self.ctx = tk.Menu(self.lst_domains, tearoff=False)
        self.ctx.add_command(label="Añadir…", command=self._add_domain_from_menu)
        self.ctx.add_command(label="Editar…", command=self._edit_selected)
        self.ctx.add_command(label="Eliminar", command=self._del_selected)
        self.ctx.add_separator()
        self.ctx.add_command(label="Copiar", command=self._copy_selected)

        def show_ctx(event):
            try:
                self.lst_domains.selection_clear(0, "end")
                idx = self.lst_domains.nearest(event.y)
                if idx >= 0:
                    self.lst_domains.selection_set(idx)
            except Exception:
                pass
            self.ctx.tk_popup(event.x_root, event.y_root)

        self.lst_domains.bind("<Button-3>", show_ctx)

    # -------- Dirty / notebook guard --------
    def _preview_dirty(self):
        if not self._dirty:
            self._set_dirty_ui(True, preview=True)

    def _mark_dirty(self):
        if not self._dirty:
            self._dirty = True
            self._set_dirty_ui(True)

    def _clear_dirty(self):
        if self._dirty:
            self._dirty = False
            self._set_dirty_ui(False)

    def _set_dirty_ui(self, dirty: bool, preview: bool = False):
        base = "Web — SafeSearch y bloqueos"
        self.lbl_title.config(text=("• " + base) if dirty else base)
        try:
            nb = self._get_notebook()
            if nb is not None:
                tab_id = self._get_my_tab_id(nb)
                if tab_id is not None:
                    text = nb.tab(tab_id, "text") or "Web"
                    text_no_dot = text.replace("• ", "")
                    nb.tab(tab_id, text=("• " + text_no_dot) if dirty else text_no_dot)
        except Exception:
            pass
        if preview:
            return

    def _get_notebook(self):
        if self._nb:
            return self._nb
        p = self.nametowidget(self.winfo_parent())
        while p is not None:
            if isinstance(p, ttk.Notebook):
                self._nb = p
                break
            try:
                pn = p.winfo_parent()
                p = self.nametowidget(pn) if pn else None
            except Exception:
                p = None
        return self._nb

    def _get_my_tab_id(self, nb: ttk.Notebook):
        if self._nb_my_tab_id:
            return self._nb_my_tab_id
        for tab_id in nb.tabs():
            child = nb.nametowidget(tab_id)
            if child is self:
                self._nb_my_tab_id = tab_id
                break
        return self._nb_my_tab_id

    def _auto_attach_notebook_guard(self):
        nb = self._get_notebook()
        if nb is None:
            return
        if not hasattr(nb, "_xh_prev_tab"):
            nb._xh_prev_tab = nb.select()

        def on_tab_changed(event):
            try:
                was = getattr(nb, "_xh_prev_tab", None)
                now = nb.select()
                my_id = self._get_my_tab_id(nb)
                if my_id and was == my_id and my_id != now and self._dirty:
                    choice = messagebox.askyesnocancel(
                        "Cambios sin guardar",
                        "Hay cambios sin guardar en ‘Web’. ¿Quieres guardarlos ahora?",
                        icon=messagebox.WARNING,
                        default=messagebox.CANCEL
                    )
                    if choice is True:
                        if self._save_sync_ui():
                            nb._xh_prev_tab = now
                            return
                        else:
                            nb.select(my_id) 
                            nb._xh_prev_tab = my_id
                            return
                    elif choice is False:
                        self._clear_dirty()
                        nb._xh_prev_tab = now
                        return
                    else:
                        nb.select(my_id)
                        nb._xh_prev_tab = my_id
                        return
                nb._xh_prev_tab = now
            except Exception:
                pass

        nb.bind("<<NotebookTabChanged>>", on_tab_changed, add="+")
        if hasattr(self, "ent_d"):
            self.ent_d.bind("<FocusOut>", lambda e: self._mark_dirty() if self.ent_d.get().strip() else None)

    # -------- Lógica de lectura/estado (async-safe) --------
    def _read_hosts(self) -> str:
        try:
            with open(HOSTS, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except Exception:
            return ""

    def _parental_block_present(self, txt: str) -> bool:
        return bool(BLOCK_RE.search(txt))

    def _safesearch_effective(self, txt: str) -> bool:
        block = BLOCK_RE.search(txt)
        if not block:
            return False
        chunk = block.group(0)
        needles = [GOOGLE_SAFE_IP, BING_STRICT_IP, YANDEX_FAMILY_IP]
        return any(ip in chunk for ip in needles)

    # --- tareas en background ---
    def _task_load_state(self, rev=None):
        if not is_admin():
            log.warning("Aplicación ejecutándose sin privilegios de administrador. Algunas funciones fallarán.")

        txt = self._read_hosts()
        present = self._parental_block_present(txt)
        safeon = self._safesearch_effective(txt) if present else False
        elev = is_admin()
        log.debug("Lectura hosts: present=%s safeon=%s admin=%s", present, safeon, elev)

        if present and safeon:
            status = "Estado: ✅ Bloque parental presente · SafeSearch ACTIVO"
        elif present and not safeon:
            status = "Estado: ⚠️ Bloque parental presente · SafeSearch DESACTIVADO"
        else:
            status = "Estado: ℹ️ Sin bloque parental"

        def _apply():
            if rev is not None and not self._gate.is_current(rev):
                return
            if not self.winfo_exists():
                return
            self.lbl_status.config(text=status)
            self.lbl_elev.config(text=f"Permisos: {'✅ Elevado' if elev else '❌ No elevado (UAC)'}")
            self._clear_dirty()
            self._refresh_count()
            self._refresh_tld_count()
        after_safe(self, 0, _apply)

    # -------- Acciones (async) --------
    def _reload_state_async(self):
        rev = self._gate.next_rev()
        self.lbl_status.config(text="Estado: leyendo…")
        submit_limited(self._task_load_state, rev)

    def _save_async(self):
        """Aplica exactamente lo seleccionado (switches + listas).
        - Si ambos quedan desactivados ⇒ state.applied=False y se limpia el hosts (si hay admin).
        - Si alguno está activado ⇒ state.applied=True y se aplica.
        El servicio (SYSTEM) reafirma/limpia según el flag.
        """
        # 1) Volcar UI → cfg
        self.cfg["safesearch"]      = bool(self.var_safe.get())
        self.cfg["domains_enabled"] = bool(self.var_domains_enabled.get())
        self.cfg["blocked_domains"] = list(self.lst_domains.get(0, "end"))
        self.cfg["google_tlds"]     = list(self.lst_tlds.get(0, "end"))
        self.cfg["block_www"]       = bool(self.var_www.get())

        # 2) Guardar config.json
        self.on_save_cfg(self.cfg)

        # 3) Decidir si hay que aplicar algo
        will_apply = self.cfg["safesearch"] or (self.cfg["domains_enabled"] and len(self.cfg["blocked_domains"]) > 0)

        # 4) Actualizar state.applied (lo leerá el Guardian)
        try:
            st = load_state()
            st["applied"] = bool(will_apply)
            save_state(st)
            log.info("state.applied = %s (por switches UI)", will_apply)
        except Exception as e:
            log.error("No se pudo actualizar state.applied: %s", e)

        # 5) Lanzar Guardian (aplica o limpia como SYSTEM)
        try:
            cp = subprocess.run(["schtasks", "/Run", "/TN", r"XiaoHackParental\Guardian"],
                                capture_output=True, text=True)
            log.info("schtasks /Run Guardian rc=%s out=%s err=%s",
                    cp.returncode, (cp.stdout or "").strip(), (cp.stderr or "").strip())
        except Exception as e:
            log.warning("No se pudo lanzar la tarea Guardian: %s", e)

        # 6) Feedback local si hay admin (aplicar/limpiar ahora)
        rev = self._gate.next_rev()
        self.lbl_status.config(text="Estado: guardado. " + ("Aplicando…" if will_apply else "Desactivando…"))

        def _work():
            local_ok, local_err = True, None
            if is_admin():
                # IMPORTANTe: aplicar con cfg "efectiva" (si domains_enabled=False, vaciar lista)
                cfg_eff = dict(self.cfg)
                if not cfg_eff.get("domains_enabled", True):
                    cfg_eff["blocked_domains"] = []

                try:
                    if will_apply:
                        ensure_hosts_rules(cfg_eff)
                        log.info("Hosts actualizado localmente (aplicación inmediata, admin).")
                    else:
                        removed = remove_parental_block()
                        log.info("Bloque parental %s localmente.", "eliminado" if removed else "no presente")
                except PermissionError as e:
                    local_ok, local_err = False, ("PERM", e)
                except Exception as e:
                    local_ok, local_err = False, ("ERR", e)
                    log.error("Error local aplicar/limpiar hosts: %s", e, exc_info=True)

            def _post():
                if not self._gate.is_current(rev) or not self.winfo_exists(): 
                    return
                self._reload_state_async()
                if is_admin():
                    if local_ok:
                        messagebox.showinfo("OK",
                            ("Aplicado. El servicio lo mantendrá." if will_apply
                            else "Desactivado. Bloque eliminado; el servicio lo mantendrá limpio."))
                    else:
                        if local_err and local_err[0] == "PERM":
                            messagebox.showwarning("Permisos",
                                "Guardado. El servicio (SYSTEM) aplicará/limpiará en segundos.")
                        else:
                            messagebox.showerror("Error",
                                f"Guardado, pero fallo local: {type(local_err[1]).__name__}: {local_err[1]}")
                else:
                    messagebox.showinfo("OK",
                        "Guardado. El servicio aplicará/limpiará en unos segundos según lo seleccionado.")
            self.after(0, _post)
        submit_limited(_work)


    # (Sincronía para el guard del Notebook: se usa solo en confirmación)
    def _save_sync_ui(self) -> bool:
        """Versión síncrona SOLO para el guard del Notebook. No la uses en handlers comunes."""
        try:
            # Volcar UI → cfg
            self.cfg["safesearch"] = bool(self.var_safe.get())
            self.cfg["blocked_domains"] = list(self.lst_domains.get(0, "end"))
            self.cfg["google_tlds"] = list(self.lst_tlds.get(0, "end"))
            self.cfg["block_www"] = bool(self.var_www.get())
            self.on_save_cfg(self.cfg)

            ensure_hosts_rules(self.cfg)
            self._clear_dirty()
            self._load_state_sync()
            return True
        except PermissionError:
            messagebox.showwarning(
                "Permisos",
                "No se pudo escribir en hosts. Asegúrate de ejecutarla como Administrador o permitirla en tu antivirus."
            )
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo aplicar al hosts:\n{type(e).__name__}: {e}")
        return False

    def _load_state_sync(self):
        """Solo para camino síncrono del guard. Mantener ultra-ligera."""
        txt = self._read_hosts()
        present = self._parental_block_present(txt)
        safeon = self._safesearch_effective(txt) if present else False
        elev = is_admin()
        if present and safeon:
            status = "Estado: ✅ Bloque parental presente · SafeSearch ACTIVO"
        elif present and not safeon:
            status = "Estado: ⚠️ Bloque parental presente · SafeSearch DESACTIVADO"
        else:
            status = "Estado: ℹ️ Sin bloque parental"
        self.lbl_status.config(text=status)
        self.lbl_elev.config(text=f"Permisos: {'✅ Elevado' if elev else '❌ No elevado (UAC)'}")
        self._refresh_count()
        self._refresh_tld_count()

    def _remove_block_async(self):
        log.info("Eliminando bloque parental del hosts…")
        if not messagebox.askyesno("Confirmar", "¿Eliminar completamente el bloque parental del archivo hosts?"):
            return
        rev = self._gate.next_rev()
        self.lbl_status.config(text="Estado: eliminando bloque parental…")

        def _work():
            try:
                changed = remove_parental_block()
                ok, ch, err = True, changed, None
                # desactivar aplicación automática
                try:
                    st = load_state()
                    st["applied"] = False
                    save_state(st)
                except Exception as e:
                    log.error("No se pudo poner state.applied=False: %s", e)
                # avisar al servicio
                try:
                    subprocess.run(["schtasks", "/Run", "/TN", r"XiaoHackParental\Guardian"],
                                capture_output=True, text=True)
                except Exception:
                    pass
            except PermissionError as e:
                ok, ch, err = False, False, ("PERM", e)
            except Exception as e:
                ok, ch, err = False, False, ("ERR", e)
                log.error("Error eliminando bloque parental: %s", e, exc_info=True)

            def _post():
                if not self._gate.is_current(rev) or not self.winfo_exists():
                    return
                self._reload_state_async()
                if ok:
                    messagebox.showinfo("Listo",
                        "Bloque parental eliminado sin alterar el resto del archivo." if ch
                        else "No se encontró el bloque parental en el hosts.")
                else:
                    if err and err[0] == "PERM":
                        messagebox.showwarning("Permisos", "Ejecuta la aplicación como Administrador.")
                    else:
                        messagebox.showerror("Error",
                            f"No se pudo eliminar el bloque parental:\n{type(err[1]).__name__}: {err[1]}")
            self.after(0, _post)

        submit_limited(_work)



    def _restore_backup_async(self):
        log.info("Restaurando backup del archivo hosts…")
        if not messagebox.askyesno("Restaurar", "¿Restaurar el backup del archivo hosts? Se perderán cambios posteriores."):
            return
        rev = self._gate.next_rev()
        self.lbl_status.config(text="Estado: restaurando backup…")

        def _work():
            try:
                rollback_hosts()
                ok, err = True, None
                # desactivar aplicación automática
                try:
                    st = load_state()
                    st["applied"] = False
                    save_state(st)
                except Exception as e:
                    log.error("No se pudo poner state.applied=False: %s", e)
                # avisar al servicio
                try:
                    subprocess.run(["schtasks", "/Run", "/TN", r"XiaoHackParental\Guardian"],
                                capture_output=True, text=True)
                except Exception:
                    pass
            except PermissionError as e:
                ok, err = False, ("PERM", e)
            except Exception as e:
                ok, err = False, ("ERR", e)
                log.error("Error restaurando backup: %s", e, exc_info=True)

            def _post():
                if not self._gate.is_current(rev) or not self.winfo_exists():
                    return
                self._reload_state_async()
                if ok:
                    messagebox.showinfo("Restaurado", "Se restauró el archivo hosts desde el backup.")
                else:
                    if err and err[0] == "PERM":
                        messagebox.showwarning("Permisos", "Ejecuta la aplicación como Administrador.")
                    else:
                        messagebox.showerror("Error",
                            f"No se pudo restaurar el backup:\n{type(err[1]).__name__}: {err[1]}")
            self.after(0, _post)

        submit_limited(_work)


    def _set_applied(self, flag: bool):
        try:
            st = load_state()
            st["applied"] = bool(flag)
            save_state(st)
            log.info("state.applied = %s", flag)
        except Exception as e:
            log.error("No se pudo actualizar state.applied=%s: %s", flag, e)

    def _kick_guardian(self):
        try:
            cp = subprocess.run(
                ["schtasks", "/Run", "/TN", r"XiaoHackParental\Guardian"],
                capture_output=True, text=True
            )
            log.info("schtasks /Run Guardian rc=%s out=%s err=%s",
                    cp.returncode, (cp.stdout or "").strip(), (cp.stderr or "").strip())
        except Exception as e:
            log.warning("No se pudo lanzar la tarea Guardian: %s", e)


    def _flush_dns_async(self):
        log.info("Ejecutando ipconfig /flushdns…")
        rev = self._gate.next_rev()
        self.lbl_status.config(text="Estado: vaciando caché DNS…")

        def _work():
            try:
                cp = subprocess.run(["ipconfig", "/flushdns"], capture_output=True, text=True)
                out = (cp.stdout or "") + (cp.stderr or "")
                ok = (cp.returncode == 0)
                log.debug("Resultado flushdns rc=%s", ok)
            except Exception as e:
                ok = False
                out = f"{type(e).__name__}: {e}"

            def _post():
                if not self._gate.is_current(rev) or not self.winfo_exists():
                    return
                self._reload_state_async()
                messagebox.showinfo("DNS", out.strip() or ("Hecho." if ok else "Comando ejecutado."))
            self.after(0, _post)
            
        submit_limited(_work)
        

    def _show_doh_help(self):
        messagebox.showinfo(
            "DNS sobre HTTPS (DoH)",
            "Si SafeSearch no parece activarse, tu navegador podría usar DNS sobre HTTPS.\n\n"
            "Chrome/Edge:\n  - Configuración > Privacidad y seguridad > Seguridad\n"
            "  - Desactiva 'Usar DNS seguro' (o selecciona 'Con tu proveedor actual')\n\n"
            "Firefox:\n  - Opciones > General > Configuración de red > Configuración...\n"
            "  - Desmarca 'Habilitar DNS sobre HTTPS'\n"
        )

    # -------- Dominios --------
    def _refresh_count(self):
        n = self.lst_domains.size()
        self.lbl_count.config(text=f"{n} dominio{'s' if n != 1 else ''}")

    def _add_domain(self):
        v = self.ent_d.get().strip().strip('"').strip("'")
        if not v:
            return
        existing = {self.lst_domains.get(i).lower() for i in range(self.lst_domains.size())}
        if v.lower() not in existing:
            self.lst_domains.insert("end", v)
            self._mark_dirty()
            self._refresh_count()
            log.info("Dominio añadido manualmente: %s", v)
        self.ent_d.delete(0, "end")

    def _import_domains(self):
        fname = filedialog.askopenfilename(
            title="Importar dominios",
            filetypes=[("Texto", "*.txt"), ("Todos", "*.*")]
        )
        if not fname:
            return
        try:
            existing = {self.lst_domains.get(i).lower() for i in range(self.lst_domains.size())}
            added = 0
            with open(fname, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    parts = re.split(r"[,\s;]+", line.strip())
                    for d in parts:
                        d = d.strip().strip('"').strip("'")
                        if d and not d.startswith("#"):
                            if d.lower() not in existing:
                                self.lst_domains.insert("end", d)
                                existing.add(d.lower())
                                added += 1
            if added:
                self._mark_dirty()
                self._refresh_count()
            messagebox.showinfo("Importar", f"Importados {added} dominios nuevos.")
        except Exception as e:
            messagebox.showerror("Importar", f"No se pudo importar:\n{type(e).__name__}: {e}")

    def _add_domain_from_menu(self):
        v = simpledialog.askstring("Añadir dominio", "Dominio a bloquear (ej. example.com):", parent=self)
        if v:
            self.ent_d.delete(0, "end")
            self.ent_d.insert(0, v.strip())
            self._add_domain()

    def _edit_selected(self):
        sel = self.lst_domains.curselection()
        if not sel:
            return
        idx = sel[0]
        cur = self.lst_domains.get(idx)
        v = simpledialog.askstring("Editar dominio", "Nuevo valor:", initialvalue=cur, parent=self)
        if v is not None:
            v = v.strip()
            if v:
                self.lst_domains.delete(idx)
                self.lst_domains.insert(idx, v)
                self.lst_domains.selection_set(idx)
                self._refresh_count()
                self._mark_dirty()

    def _del_selected(self):
        sel = list(self.lst_domains.curselection())
        if not sel:
            return
        for i in reversed(sel):
            self.lst_domains.delete(i)
        self._refresh_count()
        self._mark_dirty()

    def _copy_selected(self):
        sel = self.lst_domains.curselection()
        if not sel:
            return
        vals = [self.lst_domains.get(i) for i in sel]
        self.clipboard_clear()
        self.clipboard_append("\n".join(vals))
        try:
            self.update()
        except Exception:
            pass

    def _export_domains(self):
        fname = filedialog.asksaveasfilename(
            title="Exportar dominios",
            defaultextension=".txt",
            filetypes=[("Texto", "*.txt"), ("Todos", "*.*")]
        )
        if not fname:
            return
        try:
            vals = [self.lst_domains.get(i) for i in range(self.lst_domains.size())]
            with open(fname, "w", encoding="utf-8", newline="\n") as f:
                f.write("\n".join(vals) + ("\n" if vals else ""))
            messagebox.showinfo("Exportar", "Lista exportada.")
        except Exception as e:
            messagebox.showerror("Exportar", f"No se pudo exportar:\n{type(e).__name__}: {e}")

    # -------- TLDs Google --------
    def _refresh_tld_count(self):
        n = self.lst_tlds.size()
        if hasattr(self, "lbl_tld_count"):
            self.lbl_tld_count.config(text=f"{n} TLD{'s' if n != 1 else ''}")

    def _add_tld(self):
        v = self.ent_tld.get().strip().strip(".")
        if not v:
            return
        existing = {self.lst_tlds.get(i).lower() for i in range(self.lst_tlds.size())}
        if v.lower() not in existing:
            self.lst_tlds.insert("end", v)
            self._mark_dirty()
            self._refresh_tld_count()
        self.ent_tld.delete(0, "end")

    def _del_tld(self):
        sel = list(self.lst_tlds.curselection())
        if not sel:
            return
        for i in reversed(sel):
            self.lst_tlds.delete(i)
        self._mark_dirty()
        self._refresh_tld_count()
