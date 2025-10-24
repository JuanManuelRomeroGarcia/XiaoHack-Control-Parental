# xiao_gui/pages/dnspage.py — Pestaña "DNS Protección" (lazy-import y no bloqueo UI)
import re
import ctypes
import importlib
import tkinter as tk
from tkinter import ttk, messagebox

from logs import get_logger
from utils.async_tasks import TaskGate, submit_limited

log = get_logger("gui.dns")

DOH_TEMPLATES = {
    "CleanBrowsing Family (DoH)": "https://doh.cleanbrowsing.org/doh/family-filter/",
    "Cloudflare Family (DoH)": "https://family.cloudflare-dns.com/dns-query",
    "AdGuard Family (DoH)": "https://dns-family.adguard.com/dns-query",
}

DNS_PROVIDERS = {
    "CleanBrowsing Family (recomendado)": ["185.228.168.168", "185.228.169.168"],
    "Cloudflare Family": ["1.1.1.3", "1.0.0.3"],
    "AdGuard Family": ["94.140.14.15", "94.140.15.16"],
}


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


class DNSPage(ttk.Frame):
    def __init__(self, master, cfg: dict, on_save_cfg):
        super().__init__(master)
        self.cfg = cfg
        self.on_save_cfg = on_save_cfg
        self.cfg.setdefault("dns_mode", "off")
        self.cfg.setdefault("dns_provider", "CleanBrowsing Family (recomendado)")
        self.cfg.setdefault("dns_custom", "")
        self.cfg.setdefault("dns_iface", "ALL")

        self._gate = TaskGate()
        self._dns_mod = None
        self._brave_mod = None

        self._build()
        # Lanza tareas asíncronas tras construir la UI
        #self.after(0, lambda: self.on_show_async(None))
        log.debug("DNSPage inicializada (modo=%s, iface=%s)", self.cfg["dns_mode"], self.cfg["dns_iface"])

    # ----------------- Lazy imports -----------------
    def _lazy_dns(self):
        """Importa dnsconfig cuando sea necesario (hilo worker)."""
        if self._dns_mod is None:
            try:
                self._dns_mod = importlib.import_module("dnsconfig")
                log.debug("dnsconfig importado en diferido")
            except Exception as e:
                log.error("No se pudo importar dnsconfig: %s", e, exc_info=True)
                raise
        return self._dns_mod

    def _lazy_brave(self):
        """Importa braveconfig cuando sea necesario (hilo worker)."""
        if self._brave_mod is None:
            try:
                self._brave_mod = importlib.import_module("braveconfig")
                log.debug("braveconfig importado en diferido")
            except Exception as e:
                log.error("No se pudo importar braveconfig: %s", e, exc_info=True)
                raise
        return self._brave_mod

    # ----------------- Hooks -----------------
    def on_show_async(self, rev=None):
        rev = self._gate.next_rev() if rev is None else rev
        self._update_status("Leyendo adaptadores y estado DNS…")

        def _pipeline():
            try:
                # Cada tarea ya hace su propio self.after(...) para tocar la UI
                self._task_reload_adapters(True, rev)
                self._task_refresh_dns_status(rev)
                self._task_refresh_brave_status(rev)
                self._task_sync_mode_from_system(rev)
            except Exception as e:
                log.error("Pipeline DNSPage falló: %s", e, exc_info=True)

        # Un único submit: no hay paralelismo, no hay deadlock.
        try:
            submit_limited(_pipeline)
        except Exception as e:
            log.error("Error lanzando pipeline async en dnspage: %s", e, exc_info=True)

        log.debug("on_show_async (pipeline) lanzado rev=%s", rev)


    # ----------------- UI -----------------
    def _build(self):
        self.columnconfigure(0, weight=1)
        pad = {"padx": 10, "pady": 8}
        
        # --- estilos para el estado ---
        style = ttk.Style(self)
        style.configure("StatusOk.TLabel",    foreground="#0a7a27", font=("Segoe UI", 9, "bold"))
        style.configure("StatusWarn.TLabel",  foreground="#8a6d3b", font=("Segoe UI", 9, "bold"))
        style.configure("StatusErr.TLabel",   foreground="#a61d24", font=("Segoe UI", 9, "bold"))
        style.configure("StatusMuted.TLabel", foreground="#666666", font=("Segoe UI", 9))


        header = ttk.Frame(self)
        header.grid(row=0, column=0, sticky="ew", **pad)
        header.columnconfigure(1, weight=1)
        ttk.Label(header, text="DNS — Protección familiar", style="Headline.TLabel").grid(row=0, column=0, sticky="w")

        self.lbl_status = ttk.Label(header, text="Leyendo estado del sistema…")
        self.lbl_status.grid(row=0, column=1, sticky="e")
        self.lbl_elev = ttk.Label(header, text=f"Permisos: {'✅ Elevado' if is_admin() else '❌ No elevado (UAC)'}")
        self.lbl_elev.grid(row=1, column=0, sticky="w", pady=(4, 0))
        ttk.Separator(self).grid(row=1, column=0, sticky="ew", padx=10)

        # --- modo DNS ---
        lf_mode = ttk.LabelFrame(self, text="Modo de DNS")
        lf_mode.grid(row=2, column=0, sticky="ew", **pad)
        self.var_mode = tk.StringVar(value=self.cfg.get("dns_mode", "off"))
        ttk.Radiobutton(lf_mode, text="Desactivado", value="off", variable=self.var_mode).grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(lf_mode, text="Proveedor familiar", value="provider", variable=self.var_mode).grid(row=1, column=0, sticky="w")
        ttk.Radiobutton(lf_mode, text="Personalizado", value="custom", variable=self.var_mode).grid(row=2, column=0, sticky="w")

        provf = ttk.Frame(lf_mode)
        provf.grid(row=1, column=1, sticky="ew", padx=(10, 0))
        ttk.Label(provf, text="Proveedor:").grid(row=0, column=0, sticky="w")
        self.cmb_provider = ttk.Combobox(provf, values=list(DNS_PROVIDERS.keys()), state="readonly", width=36)
        self.cmb_provider.set(self.cfg.get("dns_provider", "CleanBrowsing Family (recomendado)"))
        self.cmb_provider.grid(row=0, column=1, sticky="w")

        custf = ttk.Frame(lf_mode)
        custf.grid(row=2, column=1, sticky="ew", padx=(10, 0))
        ttk.Label(custf, text="DNS:").grid(row=0, column=0, sticky="w")
        self.ent_custom = ttk.Entry(custf, width=36)
        self.ent_custom.insert(0, self.cfg.get("dns_custom", ""))
        self.ent_custom.grid(row=0, column=1, sticky="ew")
        self.lbl_custom_hint = ttk.Label(
            custf,
            text="Ejemplo: 1.1.1.3, 1.0.0.3  (separados por coma o espacio)",
            foreground="#666"
        )
        self.lbl_custom_hint.grid(row=1, column=1, sticky="w", pady=(2, 0))

        # reaccionar cuando cambie el modo
        self.var_mode.trace_add("write", self._refresh_custom_hint)

        # pintar estado inicial según el modo guardado
        self._refresh_custom_hint()

        # --- interfaces ---
        lf_if = ttk.LabelFrame(self, text="Adaptador de red")
        lf_if.grid(row=3, column=0, sticky="ew", **pad)
        ttk.Label(lf_if, text="Aplicar a:").grid(row=0, column=0, sticky="w")
        self.cmb_iface = ttk.Combobox(lf_if, values=["ALL"], state="readonly", width=40)
        self.cmb_iface.grid(row=0, column=1, sticky="w", padx=(6, 0))
        ttk.Button(lf_if, text="Actualizar lista", command=self._reload_adapters_async).grid(row=0, column=2, sticky="w", padx=(6, 0))

        # --- botones DNS ---
        btns = ttk.Frame(self)
        btns.grid(row=4, column=0, sticky="ew", **pad)
        ttk.Button(btns, text="Aplicar DNS", command=self._apply).grid(row=0, column=0, padx=(0, 6))
        ttk.Button(btns, text="Volver a automático", command=self._auto).grid(row=0, column=1, padx=(0, 6))

        # --- Brave ---
        lf_brave = ttk.LabelFrame(self, text="Brave (DNS seguro / DoH)")
        lf_brave.grid(row=5, column=0, sticky="ew", **pad)
        lf_brave.columnconfigure(1, weight=1)
        self.var_brave_mode = tk.StringVar(value="off")
        ttk.Radiobutton(lf_brave, text="Desactivar DoH", value="off", variable=self.var_brave_mode).grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(lf_brave, text="Usar DoH familiar", value="provider", variable=self.var_brave_mode).grid(row=1, column=0, sticky="w")
        self.cmb_doh = ttk.Combobox(lf_brave, values=list(DOH_TEMPLATES.keys()), state="readonly", width=40)
        self.cmb_doh.set("CleanBrowsing Family (DoH)")
        self.cmb_doh.grid(row=1, column=1, sticky="w", padx=(8, 0))

        scf = ttk.Frame(lf_brave)
        scf.grid(row=2, column=0, columnspan=2, sticky="w", pady=(6, 0))
        ttk.Label(scf, text="Ámbito:").grid(row=0, column=0, sticky="w")
        self.cmb_scope = ttk.Combobox(scf, values=["Usuario (HKCU)", "Equipo (HKLM)", "Ambos"], state="readonly", width=18)
        self.cmb_scope.set("Ambos")
        self.cmb_scope.grid(row=0, column=1, sticky="w", padx=(6, 0))

        btn_brave = ttk.Frame(lf_brave)
        btn_brave.grid(row=3, column=0, columnspan=2, sticky="w", pady=(6, 0))
        ttk.Button(btn_brave, text="Aplicar en Brave", command=self._apply_brave).grid(row=0, column=0, padx=(0, 6))
        ttk.Button(btn_brave, text="Quitar política", command=self._clear_brave).grid(row=0, column=1, padx=(0, 6))

        self.lbl_brave_status = ttk.Label(lf_brave, text="Estado DoH Brave: leyendo…", style="StatusMuted.TLabel")
        self.lbl_brave_status.grid(row=4, column=0, columnspan=2, sticky="w", pady=(4, 0))


    # --------------- Acciones DNS -----------------
    def _get_target_iface(self):
        val = (self.cmb_iface.get() or "").strip()
        return None if not val or val == "ALL" else val

    def _get_dns_list(self):
        mode = self.var_mode.get()
        if mode == "provider":
            return DNS_PROVIDERS.get(self.cmb_provider.get(), [])
        if mode == "custom":
            raw = self.ent_custom.get().strip()
            if not raw:
                return []
            return [p.strip() for p in re.split(r"[,\s;]+", raw) if p.strip()]
        return []
    
    def _refresh_custom_hint(self, *_):
        # Mostrar solo cuando el modo seleccionado es "custom"
        if self.var_mode.get() == "custom":
            self.lbl_custom_hint.grid()          # vuelve a mostrarla si estaba oculta
        else:
            self.lbl_custom_hint.grid_remove()   # oculta cuando no toca
            
    def _apply_brave_status_to_label(self, st: dict):
        """Pinta el estado en la etiqueta con texto claro y estilo (color)."""
        try:
            from braveconfig import summarize_brave_status_plain
            text, kind = summarize_brave_status_plain(st)  # ('Protección familiar activa (CleanBrowsing Family)', 'ok')
        except Exception:
            text, kind = "No configurado (sin política)", "unset"

        style_map = {
            "ok": "StatusOk.TLabel",
            "off": "StatusErr.TLabel",
            "auto": "StatusWarn.TLabel",
            "unset": "StatusMuted.TLabel",
            "unknown": "StatusWarn.TLabel",
        }
        self.lbl_brave_status.configure(
            text=f"Estado DoH Brave: {text}",
            style=style_map.get(kind, "StatusMuted.TLabel"),
        )

    def _apply(self):
        mode = self.var_mode.get()
        servers = self._get_dns_list()
        if mode == "off":
            messagebox.showinfo("DNS", "Modo desactivado: no se aplican cambios.")
            return
        if not servers:
            messagebox.showwarning("DNS", "No hay servidores DNS definidos.")
            return

        iface = self._get_target_iface()
        log.info("Aplicando DNS (%s) → %s [%s]", mode, servers, iface or "ALL")

        def _work():
            try:
                dns = self._lazy_dns()
                ok, out = dns.set_dns_servers(servers, interface_alias=iface)
            except Exception as e:
                ok, out = False, f"Excepción al aplicar DNS: {e}"

            def _post():
                if not self.winfo_exists():
                    return

                if ok:
                    # Persistimos configuración elegida
                    self.cfg.update({
                        "dns_mode": mode,
                        "dns_provider": self.cmb_provider.get(),
                        "dns_custom": self.ent_custom.get().strip(),
                        "dns_iface": self.cmb_iface.get() or "ALL"
                    })
                    self.on_save_cfg(self.cfg)
                    log.info("DNS aplicados correctamente: %s", servers)
                    messagebox.showinfo("DNS", f"Aplicados: {', '.join(servers)}\n{out}")
                else:
                    log.error("Error al aplicar DNS: %s", out)
                    messagebox.showerror("DNS", f"No se pudieron aplicar los DNS.\n{out}")

                # 🔄 Refresco inmediato de estado/adaptadores/modo
                self._update_status("Leyendo estado…")
                try:
                    rev2 = self._gate.next_rev()
                except Exception:
                    rev2 = 0
                submit_limited(self._task_reload_adapters, True, rev2)
                submit_limited(self._task_refresh_dns_status, rev2)
                submit_limited(self._task_sync_mode_from_system, rev2)

            self.after(0, _post)

        submit_limited(_work)


    def _auto(self):
        iface = self._get_target_iface()
        log.info("Restaurando DNS automático [%s]", iface or "ALL")

        def _work():
            try:
                dns = self._lazy_dns()
                ok, out = dns.set_dns_auto(interface_alias=iface)
            except Exception as e:
                ok, out = False, f"Excepción al restaurar automático: {e}"

            def _post():
                if not self.winfo_exists():
                    return

                if ok:
                    log.info("Modo automático restaurado: %s", (out or "").strip())
                    messagebox.showinfo("DNS", "Modo automático restaurado correctamente.")
                else:
                    log.error("Fallo al restaurar automático: %s", (out or "").strip())
                    messagebox.showerror("DNS", "Error al restaurar el DNS automático.")

                # 🔄 Refresco inmediato de estado/adaptadores/modo
                self._update_status("Leyendo estado…")
                try:
                    rev2 = self._gate.next_rev()
                except Exception:
                    rev2 = 0
                submit_limited(self._task_reload_adapters, True, rev2)
                submit_limited(self._task_refresh_dns_status, rev2)
                submit_limited(self._task_sync_mode_from_system, rev2)

            self.after(0, _post)

        submit_limited(_work)


    # --------------- Acciones Brave -----------------
    def _apply_brave(self):
        mode = self.var_brave_mode.get()
        scope_txt = self.cmb_scope.get()
        scope = "BOTH" if "Ambos" in scope_txt else ("HKLM" if "Equipo" in scope_txt else "HKCU")
        tmpl_key = self.cmb_doh.get()
        log.info("Aplicando política Brave (mode=%s, scope=%s, template=%s)", mode, scope, tmpl_key)

        def _work():
            try:
                brave = self._lazy_brave()
                ok, _ = (brave.set_brave_doh_off(scope) if mode == "off"
                         else brave.set_brave_doh_provider(DOH_TEMPLATES.get(tmpl_key), scope))
            except Exception as e:
                ok = False
                log.error("Error aplicando política Brave: %s", e, exc_info=True)
            def _post():
                if not self.winfo_exists():
                    return
                if ok:
                    log.info("Política Brave aplicada correctamente.")
                    messagebox.showinfo("Brave", "Política aplicada. Reinicia Brave.")
                else:
                    log.warning("No se pudo aplicar la política Brave.")
                    messagebox.showerror("Brave", "Error al aplicar la política.")
                    
                # 🔄 Actualiza estado DoH inmediatamente
                try:
                    from braveconfig import get_brave_doh_status
                    st = get_brave_doh_status(force=True)
                    self._apply_brave_status_to_label(st)
                except Exception as e:
                    log.error("Error actualizando estado Brave tras aplicar/limpiar: %s", e)
                # Refresco async habitual (por si cambian cosas tras reiniciar Brave)
                self._refresh_brave_status_async()

            self.after(0, _post)
        submit_limited(_work)

    def _clear_brave(self):
        scope_txt = self.cmb_scope.get()
        scope = "BOTH" if "Ambos" in scope_txt else ("HKLM" if "Equipo" in scope_txt else "HKCU")
        log.info("Eliminando política Brave (%s)", scope)

        def _work():
            try:
                brave = self._lazy_brave()
                ok, _ = brave.clear_brave_policy(scope)
            except Exception as e:
                ok = False
                log.error("Error eliminando política Brave: %s", e, exc_info=True)
            def _post():
                if not self.winfo_exists():
                    return
                if ok:
                    log.info("Política Brave eliminada correctamente.")
                    messagebox.showinfo("Brave", "Política eliminada. Reinicia Brave.")
                else:
                    log.warning("No se pudo eliminar la política Brave.")
                    messagebox.showerror("Brave", "Error al eliminar la política.")
                
                # 🔄 Actualiza estado DoH inmediatamente
                try:
                    from braveconfig import get_brave_doh_status
                    st = get_brave_doh_status(force=True)
                    self._apply_brave_status_to_label(st)
                except Exception as e:
                    log.error("Error actualizando estado Brave tras aplicar/limpiar: %s", e)
                # Refresco async habitual (por si cambian cosas tras reiniciar Brave)
                self._refresh_brave_status_async()

            self.after(0, _post)
        submit_limited(_work)

    # --------------- Tareas async (helpers) -----------------
    def _task_reload_adapters(self, include_all: bool, rev: int):
        """Lee adaptadores y actualiza combo en hilo UI."""
        try:
            dns = self._lazy_dns()
            data = dns.list_adapters() or []
            aliases = []
            for a in (data if isinstance(data, list) else [data]):
                al = (a.get("InterfaceAlias") or "").strip()
                if al and al not in aliases:
                    aliases.append(al)
            if include_all:
                aliases = ["ALL"] + aliases
            def _post():
                if not self.winfo_exists() or not self._gate.is_current(rev):
                    return
                self.cmb_iface.configure(values=aliases)
                desired = self.cfg.get("dns_iface", "ALL")
                self.cmb_iface.set(desired if desired in aliases else "ALL")
                log.debug("Adaptadores DNS cargados: %d", len(aliases) - (1 if include_all else 0))
            self.after(0, _post)
        except Exception as e:
            log.error("Error listando adaptadores: %s", e, exc_info=True)

    def _task_refresh_dns_status(self, rev: int):
        """Obtiene estado real de DNS y actualiza label."""
        try:
            dns = self._lazy_dns()
            status = dns.get_dns_status()
            summary = dns.summarize_dns_status(status)
            def _post():
                if not self.winfo_exists() or not self._gate.is_current(rev):
                    return
                self._update_status(summary)
            self.after(0, _post)
        except Exception as e:
            log.error("Error leyendo estado DNS: %s", e, exc_info=True)
            def _post():
                if self.winfo_exists():
                    self._update_status("Estado DNS: error al leer.")
            self.after(0, _post)

    def _task_refresh_brave_status(self, rev: int):
        """Lee el estado de política DoH en Brave y sincroniza UI (texto normalizado)."""
        try:
            brave = self._lazy_brave()
            st = brave.get_brave_doh_status() or {}
            txt = f"Estado DoH Brave: {brave.summarize_brave_status(st)}"

            def _post():
                if not self.winfo_exists() or not self._gate.is_current(rev):
                    return
                self._apply_brave_status_to_label(st)

                # Sincronizar controles según el estado real
                mode = (st.get("mode") or "unset").lower()
                tmpl = (st.get("templates") or "")
                if mode == "secure":
                    self.var_brave_mode.set("provider")
                    for k, v in DOH_TEMPLATES.items():
                        if v.lower() in tmpl.lower():
                            try:
                                self.cmb_doh.set(k)
                            except Exception:
                                pass
                            break
                elif mode == "off":
                    self.var_brave_mode.set("off")
                else:
                    self.var_brave_mode.set("off")

                log.debug("Brave status (UI): %s", txt)

            self.after(0, _post)

        except Exception as e:
            log.error("Error leyendo estado Brave: %s", e, exc_info=True)
            def _post():
                if self.winfo_exists():
                    self.lbl_brave_status.config(text="Estado DoH Brave: error al leer.")
            self.after(0, _post)

    def _task_sync_mode_from_system(self, rev: int):
        """
        Heurística: si el DNS real está en automático → UI 'off';
        si es estático y coincide con un proveedor → 'provider' (elige);
        si es estático pero distinto → 'custom' y rellena.
        No guarda en cfg; solo sincroniza controles.
        """
        try:
            dns = self._lazy_dns()
            status = dns.get_dns_status()
            inter = status.get("interfaces") or []
            all_servers = []
            mode_seen = set()
            for it in inter:
                mode_seen.add(it.get("mode"))
                all_servers.extend(it.get("servers") or [])
            mode_only = list(mode_seen)[0] if len(mode_seen) == 1 else None

            def _post():
                if not self.winfo_exists() or not self._gate.is_current(rev):
                    return
                if mode_only == "dhcp":
                    self.var_mode.set("off")
                elif mode_only == "static" and all_servers:
                    servers_norm = [s.strip() for s in all_servers]
                    matched = None
                    for name, lst in DNS_PROVIDERS.items():
                        if set(servers_norm) == set(lst):
                            matched = name
                            break
                    if matched:
                        self.var_mode.set("provider")
                        try:
                            self.cmb_provider.set(matched)
                        except Exception:
                            pass
                    else:
                        self.var_mode.set("custom")
                        try:
                            self.ent_custom.delete(0, "end")
                            self.ent_custom.insert(0, ", ".join(servers_norm))
                        except Exception:
                            pass
                log.debug("Sync desde sistema: mode=%s servers=%s", mode_only, all_servers)
            self.after(0, _post)
        except Exception as e:
            log.error("Error sincronizando modo desde sistema: %s", e, exc_info=True)

    # --------------- Helpers UI -----------------
    def _update_status(self, text: str):
        try:
            self.lbl_status.config(text=text)
        except Exception:
            pass

    def _reload_adapters_async(self):
        rev = self._gate.next_rev()
        self._update_status("Actualizando adaptadores…")
        submit_limited(self._task_reload_adapters, True, rev)
        submit_limited(self._task_refresh_dns_status, rev)

    def _refresh_brave_status_async(self):
        rev = self._gate.next_rev()
        submit_limited(self._task_refresh_brave_status, rev)
