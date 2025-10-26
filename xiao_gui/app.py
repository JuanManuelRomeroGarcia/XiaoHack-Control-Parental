# app.py — XiaoHack Control Parental — GUI Tutor (revisado)
from __future__ import annotations
import contextlib
import json
from pathlib import Path
import subprocess
import threading
import traceback
import sys
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
import ctypes  # AppUserModelID
from . import prof

from storage import load_state, save_state, now_epoch, load_config, save_config

# Tema / diálogos
from .theme import apply_theme
from .dialogs import ask_pin, check_pin, set_new_pin_hash

# Logs
from logs import (
    configure, install_exception_hooks, get_logger, get_log_file,
)

log = get_logger("app")

# ------------------- ICONOS / ASSETS con fallback robusto -------------------
try:
    # Preferencia: utilidades de tests si existen
    from test_app.utils import ICON_APP, ASSETS  # type: ignore
except Exception:
    RUNTIME_ROOT = Path(__file__).resolve().parents[1]
    ASSETS = RUNTIME_ROOT / "assets"
    ICO = ASSETS / "app_icon.ico"
    ICON_APP = ICO if ICO.exists() else Path()  # Path() => no existe

# ---------------- Integración con scheduler / notifier ----------------------
try:
    from scheduler import is_play_allowed, check_playtime_alerts
except Exception:
    is_play_allowed = None
    check_playtime_alerts = None

try:
    import notifier as notifier_mod  # overlay + toasts
except Exception:
    notifier_mod = None

# ---------------- AppUserModelID (icono correcto en la barra) ---------------
try:
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("XiaoHack.Parental.Panel")
except Exception:
    pass

# ---------------- Versión del runtime ---------------------------------------
def _read_version():
    try:
        root = Path(__file__).resolve().parents[1]
        return (root / "VERSION").read_text(encoding="utf-8").strip()
    except Exception:
        return "0.0.0"

APP_VERSION = _read_version()

# ---------------- Auto-check de updates (no bloqueante) ---------------------
def _find_install_root_from(here: Path) -> Path | None:
    """
    Sube hasta 5 niveles buscando una carpeta que contenga updater.py o VERSION.
    Devuelve la ruta o None si no se encuentra.
    """
    p = here
    for _ in range(6):
        if (p / "updater.py").exists() or (p / "VERSION").exists():
            return p
        if p.parent == p:
            break
        p = p.parent
    return None

def _auto_check_updates_once(root):
    """
    Comprueba si hay una versión nueva usando updater.py y ofrece aplicar la actualización.
    No bloquea la UI (usa un thread).
    """
    def _find_install_and_updater():
        from pathlib import Path
        import os
        import sys  # noqa: F401
        # 1) Preferir lo que nos diga el instalador
        inst = os.environ.get("XH_INSTALL_DIR", "").strip()
        if inst:
            base = Path(inst)
            up = base / "updater.py"
            pyw = base / "venv" / "Scripts" / "pythonw.exe"
            if up.exists():
                return base, up, (pyw if pyw.exists() else None)

        # 2) Relativo al paquete (xiao_gui/app.py -> …/updater.py)
        try:
            base = Path(__file__).resolve().parents[1]
            up = base / "updater.py"
            pyw = base / "venv" / "Scripts" / "pythonw.exe"
            if up.exists():
                return base, up, (pyw if pyw.exists() else None)
        except Exception:
            pass

        # 3) Último intento: cwd
        base = Path.cwd()
        up = base / "updater.py"
        pyw = base / "venv" / "Scripts" / "pythonw.exe"
        return base, up, (pyw if pyw.exists() else None)

    def _run():
        try:
            base, up, pyw = _find_install_and_updater()
            if not up.exists():
                log.warning("Updater no encontrado en: %s", up)
                return

            # Elegir intérprete: el actual o el del venv si detectamos que no estamos en él
            exe = sys.executable
            try:
                # Si el actual no es nuestro venv y tenemos pythonw del venv, úsalo
                if ("\\XiaoHackParental\\venv\\Scripts\\" not in exe.replace("/", "\\")
                    and pyw and pyw.exists()):
                    exe = str(pyw)
            except Exception:
                pass

            log.info("Lanzando updater: exe=%s, script=%s", exe, up)
            out = subprocess.check_output([exe, str(up), "--check"],
                                          stderr=subprocess.STDOUT, timeout=300)
            res = json.loads(out.decode("utf-8", "ignore"))
            if res.get("update_available"):
                latest = res.get("latest") or "desconocida"
                def _apply():
                    try:
                        subprocess.check_call([exe, str(up), "--apply"])
                        messagebox.showinfo(
                            "Actualización",
                            "Actualización instalada correctamente.\nReinicia el Panel para ver los cambios."
                        )
                    except Exception as e:
                        messagebox.showerror("Actualización", f"No se pudo actualizar:\n{e}")
                root.after(0, lambda: (
                    messagebox.askyesno(
                        "Actualización disponible",
                        f"Hay una nueva versión {latest}.\n¿Quieres instalarla ahora?"
                    ) and _apply()
                ))
        except subprocess.CalledProcessError as e:
            msg = (e.output or b"").decode("utf-8", "ignore")
            log.error("Updater fallo: rc=%s out=%s", e.returncode, msg)
            try:
                messagebox.showerror("Actualizaciones",
                    f"Error: Updater falló (rc={e.returncode}).\n{msg}")
            except Exception:
                pass
        except Exception as e:
            log.error("Updater sin salida: %s", e, exc_info=True)
            try:
                messagebox.showerror("Actualizaciones",
                    f"Error: Updater sin salida ({type(e).__name__}: {e}).")
            except Exception:
                pass

    threading.Thread(target=_run, daemon=True).start()



# ---------------- Enforcement helper ----------------------------------------
def _compute_enforcement(cfg, st, *, allowed: bool):
    prev = st.get("enforcement", {})
    wl = list(cfg.get("game_whitelist") or [])
    bl = list(cfg.get("blocked_apps") or [])

    if allowed and wl:
        wl_set = {x.lower() for x in wl}
        block_effective = [exe for exe in bl if exe.lower() not in wl_set]
        rules = {"mode": "allowlist", "allow": wl, "block": block_effective}
    else:
        rules = {"mode": "blocklist", "allow": [], "block": bl}
        if allowed and not wl:
            rules["note"] = "schedule_without_whitelist"

    changed = (prev != rules)
    st["enforcement"] = rules
    return rules, changed

# ----------------------------------------------------------------------------

class TutorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("XiaoHack Control Parental — Tutor")
        self.geometry("1024x900")
        self.minsize(1024, 720)
        self.resizable(True, True)

        # Icono
        try:
            if ICON_APP and ICON_APP.exists():
                self.iconbitmap(str(ICON_APP))  # .ico
            else:
                _png = ASSETS / "app_icon.png"
                if _png.exists():
                    self._icon_png_ref = tk.PhotoImage(file=str(_png))
                    self.iconphoto(True, self._icon_png_ref)
        except Exception:
            pass

        # Cargar config/tema
        self.cfg = load_config()
        self.ui_dark = tk.BooleanVar(value=self.cfg.get("ui_theme", "light") == "dark")
        try:
            apply_theme(self, self.ui_dark.get())
        except Exception:
            pass

        # Login PIN
        if not self._login():
            self.destroy()
            return

        # Header
        try:
            self._build_header()
        except Exception:
            pass

        # ===== Contenedor central (Notebook + Footer fijo) =====
        body = ttk.Frame(self)
        body.pack(fill="both", expand=True)
        body.grid_rowconfigure(0, weight=1)
        body.grid_columnconfigure(0, weight=1)

        self.nb = ttk.Notebook(body)
        self.nb.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)

        self._tab_titles: dict[tk.Widget, str] = {}
        self._switch_guard = False
        self._switch_seq = 0
        self._pending_onshow = None

        # Tabs
        _PAGES_ERR = []
        try:
            from .pages.apps import AppsPage
        except Exception as e:
            _PAGES_ERR.append(("Aplicaciones/Juegos", e, traceback.format_exc()))
            AppsPage = None
        try:
            from .pages.whitelist import GameWhitelistPage
        except Exception as e:
            _PAGES_ERR.append(("Lista blanca", e, traceback.format_exc()))
            GameWhitelistPage = None
        try:
            from .pages.web import WebPage
        except Exception as e:
            _PAGES_ERR.append(("Web/SafeSearch", e, traceback.format_exc()))
            WebPage = None
        try:
            from .pages.dnspage import DNSPage
        except Exception as e:
            _PAGES_ERR.append(("DNS Protección", e, traceback.format_exc()))
            DNSPage = None
        try:
            from .pages.time_page import TimePage
        except Exception as e:
            _PAGES_ERR.append(("Tiempo de juego", e, traceback.format_exc()))
            TimePage = None
        try:
            from .pages.options import OptionsPage
        except Exception as e:
            _PAGES_ERR.append(("Opciones", e, traceback.format_exc()))
            OptionsPage = None

        # Apps
        if AppsPage:
            try:
                self.page_apps = AppsPage(self.nb, self.cfg, self.ui_dark.get())
                self.nb.add(self.page_apps, text="Aplicaciones/Juegos")
                self._tab_titles[self.page_apps] = "Aplicaciones/Juegos"
            except Exception as e:
                self._add_error_tab(self.nb, "Aplicaciones/Juegos", e)
                self.page_apps = None
        else:
            self._add_missing_tab(self.nb, "Aplicaciones/Juegos")

        # Whitelist
        if GameWhitelistPage:
            try:
                self.page_wl = GameWhitelistPage(self.nb, self.cfg, self.ui_dark.get())
                self.nb.add(self.page_wl, text="Lista blanca")
                self._tab_titles[self.page_wl] = "Lista blanca"
            except Exception as e:
                self._add_error_tab(self.nb, "Lista blanca", e)
                self.page_wl = None
        else:
            self._add_missing_tab(self.nb, "Lista blanca")

        # Web
        if WebPage:
            try:
                # Nota: WebPage debe llamar a webfilter.ensure_hosts_rules_or_elevate() cuando aplique
                self.page_web = WebPage(self.nb, self.cfg, self._save_cfg)
                self.nb.add(self.page_web, text="Web/SafeSearch")
            except Exception as e:
                self._add_error_tab(self.nb, "Web/SafeSearch", e)
                self.page_web = None
        else:
            self._add_missing_tab(self.nb, "Web/SafeSearch")

        # DNS
        if DNSPage:
            try:
                self.page_dns = DNSPage(self.nb, self.cfg, self._save_cfg)
                self.nb.add(self.page_dns, text="DNS Protección")
                self._tab_titles[self.page_dns] = "DNS Protección"
            except Exception as e:
                self._add_error_tab(self.nb, "DNS Protección", e)
                self.page_dns = None
        else:
            self._add_missing_tab(self.nb, "DNS Protección")

        # Tiempo
        if TimePage:
            try:
                self.page_time = TimePage(self.nb, self.cfg)
                self.nb.add(self.page_time, text="Tiempo de juego")
            except Exception as e:
                self._add_error_tab(self.nb, "Tiempo de juego", e)
                self.page_time = None
        else:
            self._add_missing_tab(self.nb, "Tiempo de juego")

        # Opciones
        if OptionsPage:
            try:
                self.page_opts = OptionsPage(self.nb, self.cfg, self.ui_dark,
                                             self._on_toggle_theme, self._save_cfg)
                self.nb.add(self.page_opts, text="Opciones")
            except Exception as e:
                self._add_error_tab(self.nb, "Opciones", e)
                self.page_opts = None
        else:
            self._add_missing_tab(self.nb, "Opciones")

        # ===== Footer fijo =====
        self.style = ttk.Style(self)
        footer = ttk.Frame(body)
        footer.grid(row=1, column=0, sticky="ew")
        footer.grid_columnconfigure(0, weight=1)

        left = ttk.Frame(footer)
        left.grid(row=0, column=0, sticky="w", padx=(8, 0), pady=(0, 8))
        self._dirty_label = ttk.Label(left, text="", foreground="#cc0000")
        self._dirty_label.pack(side="left", padx=(0, 10))
        ttk.Label(left, text=f"Control Parental © XiaoHack — ver. {APP_VERSION}").pack(side="left")

        right = ttk.Frame(footer)
        right.grid(row=0, column=1, sticky="e", padx=(0, 8), pady=(0, 8))

        self._btn_save_wl = ttk.Button(right, text="Guardar lista blanca",
                                       command=self._save_whitelist_rules, width=24)
        self._btn_save_apps = ttk.Button(right, text="Guardar reglas de Apps/Juegos",
                                         command=self._save_apps_rules, width=28)
        self._btn_save_apps_base_text = "Guardar reglas de Apps/Juegos"

        # Eventos notebook y cierre
        self._active_tab_index = self.nb.index("current")
        self.nb.bind("<<NotebookTabChanged>>", self._on_nb_tab_changed)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # Atajo Ctrl+S → guardar lo de la pestaña activa
        self.bind_all("<Control-s>", lambda e: self._save_current_tab())

        # Ventanas auxiliares
        self._countdown_win = None
        self._hint_windows = {}
        self._countdown_last = -1

        # Vigilancia de cambios en UI
        self._tick_dirty_watch()

        # Profiler de latencia UI (opcional)
        self._probe = prof.start(
            self,
            getattr(self, "lbl_status", None),
            interval_ms=500,
            warn_ms=800,
            on_warn=lambda lag: log.warning("[UI] lag %d ms — pestaña: %s",
                                            int(lag),
                                            self.nb.tab(self.nb.select(), "text") if self.nb.tabs() else "?")
        )

        # on_show inicial
        try:
            first = self.nb.nametowidget(self.nb.tabs()[self.nb.index("current")])
            self.after_idle(lambda: self._call_page_on_show(first))
        except Exception:
            pass

        if _PAGES_ERR:
            msg = "\n\n".join([f"[{name}] {err}" for name, err, _ in _PAGES_ERR])
            messagebox.showwarning("Aviso",
                                   "Algunas pestañas no pudieron cargarse. Revisa el log.\n\n" + msg)

        # Tick de tiempo de juego
        self.after(1000, self._tick_playtime)

    # ---------- Header ----------
    def _build_header(self):
        header = ttk.Frame(self)
        header.pack(fill="x", padx=8, pady=(8, 0))
        self._logo_img_ref = None
        try:
            logo_path = ASSETS / "logo.png"
            logo_lbl = ttk.Label(header)
            if logo_path.exists():
                raw = tk.PhotoImage(file=str(logo_path))
                max_h = 30
                if raw.height() > max_h:
                    import math
                    factor = max(1, math.ceil(raw.height() / max_h))
                    raw = raw.subsample(factor, factor)
                self._logo_img_ref = raw
                logo_lbl.configure(image=self._logo_img_ref)
            logo_lbl.pack(side="left", padx=(0, 10))
        except Exception:
            pass
        title = ttk.Label(header, text="Panel del tutor", font=("", 12, "bold"))
        self._subtitle = ttk.Label(header, text="", font=("", 10))
        title.pack(side="left", anchor="w")
        self._subtitle.pack(side="left", anchor="s", padx=(8, 0))

    # ---------- Login ----------
    def _login(self) -> bool:
        stored = self.cfg.get("parent_password_hash", "")
        try:
            self.deiconify()
            self.state("normal")
            self.lift()
            self.attributes("-topmost", True)
            self.after(50, lambda: self.attributes("-topmost", False))
            self.update_idletasks()
        except Exception:
            pass
        if not stored:
            while True:
                messagebox.showinfo("PIN", "Primera vez: establece un PIN de tutor.", parent=self)
                newh = set_new_pin_hash(self)
                if newh:
                    self.cfg["parent_password_hash"] = newh
                    self._save_cfg(self.cfg)
                    break
                resp = messagebox.askyesno("Cancelar","No se estableció ningún PIN.\n\n¿Quieres salir del panel?",parent=self)
                if resp:
                    return False
            try:
                self.lift()
                self.focus_force()
            except Exception:
                pass
            return True

        MAX_TRIES = 3
        tries = 0
        while tries < MAX_TRIES:
            try:
                self.lift()
                self.attributes("-topmost", True)
                self.after(50, lambda: self.attributes("-topmost", False))
            except Exception:
                pass
            pin = ask_pin(self)
            if pin is None:
                return False
            if check_pin(stored, pin):
                try:
                    self.lift()
                    self.focus_force()
                except Exception:
                    pass
                return True
            tries += 1
            messagebox.showerror("Error", f"PIN incorrecto. Intento {tries} de {MAX_TRIES}.", parent=self)
        messagebox.showwarning("Bloqueo", "Demasiados intentos. Cerrando el panel.", parent=self)
        return False

    # ---------- Guardado/tema ----------
    def _save_cfg(self, cfg: dict):
        try:
            save_config(cfg)
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo guardar la configuración:\n{e}")

    def _save_apps_rules(self):
        if getattr(self, "page_apps", None) is None:
            messagebox.showwarning("Aviso", "La pestaña de Apps no está disponible.")
            return
        try:
            data = self.page_apps.collect()
            for k in ("blocked_apps", "blocked_executables", "blocked_paths"):
                self.cfg[k] = data.get(k, [])
            self._save_cfg(self.cfg)
            messagebox.showinfo("OK", "Reglas guardadas.")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudieron guardar las reglas:\n{e}")

    def _save_current_tab(self):
        active_widget = self.nb.nametowidget(self.nb.select())
        if active_widget is getattr(self, "page_apps", None):
            self._save_apps_rules()
        elif active_widget is getattr(self, "page_wl", None):
            self._save_whitelist_rules()

    def _save_whitelist_rules(self):
        if getattr(self, "page_wl", None) is None:
            return
        try:
            if hasattr(self.page_wl, "get_whitelist"):
                items = list(self.page_wl.get_whitelist())
            elif hasattr(self.page_wl, "lst"):
                items = list(self.page_wl.lst.get(0, "end"))
            else:
                items = self.cfg.get("game_whitelist", [])
            self.cfg["game_whitelist"] = items
            self._save_cfg(self.cfg)
            messagebox.showinfo("OK", "Lista blanca guardada.")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo guardar la lista blanca:\n{e}")

    def _on_toggle_theme(self):
        dark = bool(self.ui_dark.get())
        self.cfg["ui_theme"] = "dark" if dark else "light"
        self._save_cfg(self.cfg)
        try:
            apply_theme(self, dark)
            if getattr(self, "page_apps", None):
                self.page_apps.apply_theme(dark)
            if getattr(self, "page_wl", None) and hasattr(self.page_wl, "apply_theme"):
                self.page_wl.apply_theme(dark)
        except Exception:
            pass

    # ---------- Dirty-check helpers ----------
    def _apps_state_from_ui(self):
        if not getattr(self, "page_apps", None):
            return None
        data = self.page_apps.collect()
        return {
            "blocked_apps": sorted(data.get("blocked_apps", [])),
            "blocked_executables": sorted(data.get("blocked_executables", [])),
            "blocked_paths": sorted(data.get("blocked_paths", [])),
        }

    def _apps_state_from_cfg(self):
        return {
            "blocked_apps": sorted(self.cfg.get("blocked_apps", [])),
            "blocked_executables": sorted(self.cfg.get("blocked_executables", [])),
            "blocked_paths": sorted(self.cfg.get("blocked_paths", [])),
        }

    def _is_apps_dirty(self) -> bool:
        if not getattr(self, "page_apps", None):
            return False
        return self._apps_state_from_ui() != self._apps_state_from_cfg()

    def _wl_from_ui(self):
        if not getattr(self, "page_wl", None):
            return None
        if hasattr(self.page_wl, "get_whitelist"):
            items = list(self.page_wl.get_whitelist())
        elif hasattr(self.page_wl, "lst"):
            items = list(self.page_wl.lst.get(0, "end"))
        else:
            items = list(self.cfg.get("game_whitelist", []))
        return sorted(items)

    def _wl_from_cfg(self):
        return sorted(self.cfg.get("game_whitelist", []))

    def _is_wl_dirty(self) -> bool:
        if not getattr(self, "page_wl", None):
            return False
        return self._wl_from_ui() != self._wl_from_cfg()

    def _set_tab_dirty(self, page_widget, dirty: bool):
        if page_widget not in self._tab_titles:
            return
        base = self._tab_titles[page_widget]
        current = self.nb.tab(page_widget, option="text")
        want = f"• {base}" if dirty else base
        if current != want:
            self.nb.tab(page_widget, text=want)

    def _ensure_packed_right(self, widget):
        try:
            if not widget.winfo_ismapped():
                widget.pack(side="right", padx=(6, 0))
        except Exception:
            pass

    def _update_dirty_bar(self, apps_dirty: bool, wl_dirty: bool):
        parts = []
        if apps_dirty: 
            parts.append("Aplicaciones/Juegos")
        if wl_dirty: 
            parts.append("Lista blanca")
        self._dirty_label.configure(text=("• Cambios sin guardar: " + ", ".join(parts)) if parts else "")
        active_widget = self.nb.nametowidget(self.nb.select()) if self.nb.tabs() else None
        try:
            if active_widget is getattr(self, "page_apps", None) and apps_dirty:
                self._btn_save_apps.configure(text=self._btn_save_apps_base_text + " •")
                self._ensure_packed_right(self._btn_save_apps)
            else:
                if self._btn_save_apps.winfo_ismapped():
                    self._btn_save_apps.pack_forget()
        except Exception:
            pass
        try:
            if active_widget is getattr(self, "page_wl", None) and wl_dirty:
                self._ensure_packed_right(self._btn_save_wl)
            else:
                if self._btn_save_wl.winfo_ismapped():
                    self._btn_save_wl.pack_forget()
        except Exception:
            pass

    def _tick_dirty_watch(self):
        try:
            apps_dirty = self._is_apps_dirty() if getattr(self, "page_apps", None) else False
            wl_dirty = self._is_wl_dirty() if getattr(self, "page_wl", None) else False
            if getattr(self, "page_apps", None):
                self._set_tab_dirty(self.page_apps, apps_dirty)
            if getattr(self, "page_wl", None):
                self._set_tab_dirty(self.page_wl, wl_dirty)
            self._update_dirty_bar(apps_dirty, wl_dirty)
        except Exception:
            pass
        finally:
            self.after(500, self._tick_dirty_watch)

    def _ask_save_discard_cancel(self, what: str):
        try:
            resp = messagebox.askyesnocancel(
                "Cambios sin guardar",
                f"Hay cambios sin guardar en {what}.\n\n¿Quieres guardarlos antes de continuar?",
                icon="warning"
            )
            return resp
        except Exception:
            ok = messagebox.askokcancel(
                "Cambios sin guardar",
                f"Hay cambios sin guardar en {what}.\n\nPulsa Aceptar para guardar o Cancelar para descartar.",
                icon="warning"
            )
            return True if ok else False

    def _handle_dirty_for_page(self, page_widget) -> bool:
        if page_widget is getattr(self, "page_apps", None) and self._is_apps_dirty():
            resp = self._ask_save_discard_cancel("Aplicaciones/Juegos")
            if resp is None: 
                return False
            if resp is True:
                self._save_apps_rules()
        elif page_widget is getattr(self, "page_wl", None) and self._is_wl_dirty():
            resp = self._ask_save_discard_cancel("Lista blanca")
            if resp is None:
                return False
            if resp is True:
                self._save_whitelist_rules()
        return True

    def _refresh_if_needed_on_enter(self, new_widget):
        try:
            if new_widget is getattr(self, "page_wl", None) and hasattr(self.page_wl, "reload_from_storage"):
                self.page_wl.reload_from_storage()
                self.cfg = load_config()
        except Exception:
            pass

    def _on_nb_tab_changed(self, event):
        if self._switch_guard: 
            return
        self._switch_guard = True
        self._switch_seq += 1
        seq = self._switch_seq

        try:
            new_index = self.nb.index("current")
            old_index = getattr(self, "_active_tab_index", new_index)
            if old_index == new_index:
                return

            tabs = self.nb.tabs()
            old_widget = self.nb.nametowidget(tabs[old_index]) if old_index < len(tabs) else None
            if not self._handle_dirty_for_page(old_widget):
                self.nb.select(old_index)
                return

            new_widget = self.nb.nametowidget(tabs[new_index])

            if self._pending_onshow:
                with contextlib.suppress(Exception):
                    self.after_cancel(self._pending_onshow)
                self._pending_onshow = None

            self._refresh_if_needed_on_enter(new_widget)
            with contextlib.suppress(Exception):
                self.update_idletasks()

            def _kick():
                if seq != self._switch_seq:
                    return
                self._call_page_on_show(new_widget)
            self._pending_onshow = self.after(50, _kick)

            self._active_tab_index = new_index
        finally:
            def _release():
                if seq == self._switch_seq:
                    self._switch_guard = False
            self.after(120, _release)

    def _call_page_on_show(self, page_widget):
        if page_widget is None or not hasattr(page_widget, 'winfo_exists') or not page_widget.winfo_exists():
            return
        def _safe_call():
            try:
                if hasattr(page_widget, "on_show_async"):
                    gate = getattr(page_widget, "_gate", None)
                    if gate and hasattr(gate, "next_rev"):
                        rev = gate.next_rev()
                        page_widget.on_show_async(rev)
                    else:
                        page_widget.on_show_async(None)
                    return
            except Exception:
                traceback.print_exc()
            try:
                if hasattr(page_widget, "on_show"):
                    page_widget.on_show()
            except Exception:
                traceback.print_exc()
        try:
            self.after_idle(_safe_call)
        except Exception:
            self.after(0, _safe_call)

    def _on_close(self):
        for page in (getattr(self, "page_apps", None), getattr(self, "page_wl", None)):
            if page is None:
                continue
            if page is getattr(self, "page_apps", None) and self._is_apps_dirty():
                resp = self._ask_save_discard_cancel("Aplicaciones/Juegos")
                if resp is None: 
                    return
                if resp is True:
                    self._save_apps_rules()
            elif page is getattr(self, "page_wl", None) and self._is_wl_dirty():
                resp = self._ask_save_discard_cancel("Lista blanca")
                if resp is None:
                    return
                if resp is True:
                    self._save_whitelist_rules()

        probe = getattr(self, "_probe", None)
        if probe:
            with contextlib.suppress(Exception):
                probe.stop()

        self.destroy()

    def _add_error_tab(self, nb: ttk.Notebook, name: str, exc: Exception):
        frame = ttk.Frame(nb)
        nb.add(frame, text=f"{name} (error)")
        tk.Label(frame, text=f"Error cargando {name}:\n{exc}", fg="red", justify="left").pack(anchor="w", padx=10, pady=10)

    def _add_missing_tab(self, nb: ttk.Notebook, name: str):
        frame = ttk.Frame(nb)
        nb.add(frame, text=f"{name} (no encontrada)")
        tk.Label(frame, text=f"La página '{name}' no está disponible (archivo faltante).",
                 justify="left").pack(anchor="w", padx=10, pady=10)

    # -------- Ventana persistente de cuenta atrás (overlay local) --------
    # Nota: el overlay real sobre juegos en pantalla completa lo gestiona notifier (Win32 layered).
    def _show_countdown_window(self, seconds: int):
        try:
            if self._countdown_win is None or not self._countdown_win.winfo_exists():
                w = tk.Toplevel(self)
                w.withdraw()
                w.overrideredirect(1)
                w.attributes("-topmost", True)
                w.attributes("-toolwindow", True)
                w.geometry("300x120+{}+{}".format(
                    max(0, (self.winfo_screenwidth()  - 300) // 2),
                    max(0, (self.winfo_screenheight() - 120) // 4)
                ))
                frm = ttk.Frame(w, padding=12)
                frm.pack(fill="both", expand=True)
                self._cd_title = ttk.Label(frm, text="⏱ Cuenta atrás", font=("", 12, "bold"))
                self._cd_value = ttk.Label(frm, text="60 s", font=("", 26))
                self._cd_sub   = ttk.Label(frm, text="Se cerrará el juego", font=("", 10))
                self._cd_title.pack(pady=(0, 6))
                self._cd_value.pack()
                self._cd_sub.pack(pady=(4, 0))
                w.protocol("WM_DELETE_WINDOW", lambda: None)
                w.deiconify()
                self._countdown_win = w

            if seconds != self._countdown_last:
                self._cd_value.configure(text=f"{seconds:02d} s")
                self._countdown_last = seconds
        except Exception:
            pass

    def _hide_countdown_window(self):
        try:
            if self._countdown_win and self._countdown_win.winfo_exists():
                self._countdown_win.destroy()
        except Exception:
            pass
        finally:
            self._countdown_win = None
            self._countdown_last = -1

    # ---------- Tick control de tiempo ----------
    def _tick_playtime(self):
        log.debug("tick-start")
        try:
            cfg = load_config()
            st = load_state()
            now = datetime.now()
            now_ts = now_epoch()
            enabled = bool(cfg.get("playtime_enabled", True))
            log.debug("tick enabled=%s", enabled)

            if not enabled:
                self._hide_countdown_window()
                st.setdefault("play_alerts", {})
                st["play_alerts"]["countdown_started"] = False
                st["play_countdown"] = 0
                st["play_end_notified"] = False
                _, enf_changed = _compute_enforcement(cfg, st, allowed=False)
                wl_changed = bool(st.get("play_whitelist"))
                if wl_changed:
                    st["play_whitelist"] = []
                if enf_changed or wl_changed or st.get("play_countdown", 0):
                    save_state(st)
                try:
                    if getattr(self, "page_time", None) and hasattr(self.page_time, "_refresh_status_label"):
                        self.page_time._refresh_status_label()
                except Exception:
                    pass
                self.after(1000, self._tick_playtime)
                log.debug("disabled-branch → blocklist-only")
                return

            msgs, countdown = (check_playtime_alerts(st, now, cfg) if check_playtime_alerts else ([], 0))
            log.debug("alerts msgs=%d countdown=%d", len(msgs), countdown)

            if countdown > 0:
                self._show_countdown_window(countdown)
                self._subtitle.configure(text="")
            else:
                self._hide_countdown_window()

            if msgs:
                for m in msgs:
                    title = "Tiempo de juego"
                    key = "play:generic"
                    if "10 minutos" in m:
                        key = "play:m10"
                    elif "5 minutos" in m:
                        key = "play:m5"
                    elif "Último minuto" in m or "cuenta atrás" in m:
                        key = "play:m1"

                    sent = False
                    if notifier_mod:
                        if hasattr(notifier_mod, "notify_once"):
                            try:
                                notifier_mod.notify_once(key, title, m, min_interval=2.0)
                                sent = True
                            except Exception:
                                sent = False
                        if not sent and hasattr(notifier_mod, "notify"):
                            try:
                                notifier_mod.notify(title, m)
                                sent = True
                            except Exception:
                                sent = False
                    if not sent:
                        with contextlib.suppress(Exception):
                            print("[ALERTA]", m)
                    self._show_hint_window(key, m, ttl_sec=10)

            play_until = int(st.get("play_until") or 0)
            ended_flag = bool(st.get("play_end_notified", False))
            state_changed = False

            if play_until > 0 and now_ts >= play_until:
                st.setdefault("play_alerts", {})
                st["play_alerts"]["countdown_started"] = False
                st["play_countdown"] = 0
                self._hide_countdown_window()
                if not ended_flag:
                    msg_end = "⛔ Se acabó el tiempo de juego."
                    if notifier_mod and hasattr(notifier_mod, "notify_once"):
                        with contextlib.suppress(Exception):
                            notifier_mod.notify_once("play:end", "Tiempo de juego", msg_end, min_interval=2.0)
                    else:
                        with contextlib.suppress(Exception):
                            print("[ALERTA]", msg_end)
                    log.info("session-end")
                    st["play_end_notified"] = True
                    state_changed = True
            elif play_until > now_ts:
                if ended_flag:
                    st["play_end_notified"] = False
                    state_changed = True

            allowed = is_play_allowed(cfg, st, now) if is_play_allowed else True

            desired_wl = cfg.get("game_whitelist", []) or []
            current_wl = st.get("play_whitelist", []) or []
            if allowed:
                if current_wl != desired_wl:
                    st["play_whitelist"] = desired_wl
                    state_changed = True
            else:
                if current_wl:
                    st["play_whitelist"] = []
                    state_changed = True

            _, enf_changed = _compute_enforcement(cfg, st, allowed=allowed)
            log.debug("policy allowed=%s wl=%s mode=%s block=%s",
                      allowed, len(desired_wl), st["enforcement"].get("mode"),
                      len(st["enforcement"].get("block", [])))
            if enf_changed:
                state_changed = True

            if st.get("play_countdown", 0) or msgs:
                state_changed = True

            if state_changed:
                save_state(st)

            try:
                if getattr(self, "page_time", None) and hasattr(self.page_time, "_refresh_status_label"):
                    self.page_time._refresh_status_label()
            except Exception:
                pass

        except Exception as e:
            log.exception("tick-playtime error: %s", e)
        finally:
            with contextlib.suppress(Exception):
                self.after(1000, self._tick_playtime)

    def _show_hint_window(self, key: str, text: str, ttl_sec: int = 10):
        import time
        now_ts = time.time()

        if key in self._hint_windows:
            win, _ = self._hint_windows[key]
            try:
                if win and win.winfo_exists():
                    for child in win.winfo_children():
                        if isinstance(child, ttk.Label) and child.cget("name") == "msg":
                            child.configure(text=text)
                    self._hint_windows[key] = (win, now_ts)
                    return
            except Exception:
                pass

        w = tk.Toplevel(self)
        w.withdraw()
        w.overrideredirect(1)
        w.attributes("-topmost", True)
        w.attributes("-toolwindow", True)

        width, height, margin = 360, 90, 16
        x = max(0, self.winfo_screenwidth() - width - margin)
        y = max(0, self.winfo_screenheight() - height - margin*2)
        w.geometry(f"{width}x{height}+{x}+{y}")

        frm = ttk.Frame(w, padding=12)
        frm.pack(fill="both", expand=True)
        title = ttk.Label(frm, text="Tiempo de juego", font=("", 11, "bold"))
        msg = ttk.Label(frm, name="msg", text=text, font=("", 10))
        title.pack(anchor="w")
        msg.pack(anchor="w", pady=(6, 0))

        w.deiconify()
        self._hint_windows[key] = (w, now_ts)

        def _autoclose():
            try:
                if key not in self._hint_windows:
                    return
                win, created = self._hint_windows[key]
                if not win or not win.winfo_exists():
                    self._hint_windows.pop(key, None)
                    return
                import time as _t
                alive = (_t.time() - created) < ttl_sec
                if alive:
                    self.after(500, _autoclose)
                else:
                    try:
                        win.destroy()
                    except Exception:
                        pass
                    self._hint_windows.pop(key, None)
            except Exception:
                self._hint_windows.pop(key, None)
        self.after(500, _autoclose)

    def _hide_all_hints(self):
        try:
            for key, (win, _) in list(self._hint_windows.items()):
                try:
                    if win and win.winfo_exists():
                        win.destroy()
                except Exception:
                    pass
            self._hint_windows.clear()
        except Exception:
            pass


def run():
    # Configurar logging y hooks al arrancar GUI
    configure(level="INFO")  # cambia a "DEBUG" para depurar
    install_exception_hooks("gui-crash")
    log.info("Iniciando GUI XiaoHack… (log en %s)", get_log_file())

    # Alta-DPI (Windows)
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass

    try:
        app = TutorApp()
        app.after(3000, lambda: _auto_check_updates_once(app))
        app.mainloop()
    except Exception as e:
        err = traceback.format_exc()
        try:
            with open("gui_error.log", "a", encoding="utf-8") as f:
                f.write(err + "\n")
        except Exception:
            pass
        messagebox.showerror("Error crítico", f"No se pudo iniciar la GUI:\n{e}\n\nRevisa gui_error.log")
        print(err, file=sys.stderr)
