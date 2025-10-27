# app.py — XiaoHack Control Parental — GUI Tutor (revisado)
from __future__ import annotations
from pathlib import Path
import traceback
import sys
import tkinter as tk
from tkinter import ttk, messagebox
import ctypes  # AppUserModelID
from utils.runtime import set_appusermodelid, set_process_title, parse_role

from app.storage import load_state, save_state, now_epoch, load_config, save_config  # noqa: F401


# Tema / diálogos
try:
    from xiao_gui.theme import apply_theme
except Exception:  # pragma: no cover
    def apply_theme(root):
        pass

try:
    from xiao_gui.dialogs import (
        show_confirm_restricted_window,
        show_dns_dialog,
        show_doh_dialog,
        show_blocklist_editor,
        show_about_dialog,
    )
except Exception:  # pragma: no cover
    def show_confirm_restricted_window(*a, **k):
        return False
    def show_dns_dialog(*a, **k):
        pass
    def show_doh_dialog(*a, **k):
        pass
    def show_blocklist_editor(*a, **k):
        pass
    def show_about_dialog(*a, **k):
        pass

# Logs
from app.logs import (
    configure, install_exception_hooks, get_logger, get_log_file,
)

log = get_logger("app")

# Identidad de proceso (AppUserModelID + título)
try:
    set_appusermodelid("XiaoHack.Parental.Panel")
    set_process_title(parse_role(sys.argv) or "panel")
except Exception:
    pass

# ------------------- ICONOS / ASSETS con fallback robusto -------------------
try:
    # Preferencia: utilidades de tests si existen
    from test_app.utils import ICON_APP, ASSETS  # type: ignore
except Exception:
    RUNTIME_ROOT = Path(__file__).resolve().parents[1]
    ASSETS = RUNTIME_ROOT / "assets"
    ICON_APP = ASSETS / "app_icon.ico"

# --------------------- Estado global del GUI (perfil tutor) -----------------
class TutorState:
    def __init__(self):
        self.last_refresh = now_epoch()
        self.status_text = ""
        self.enforcement = None

TS = TutorState()

# ----------------------- Widgets auxiliares comunes -------------------------
class StatusBar(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.var = tk.StringVar(value="Listo")
        self.label = ttk.Label(self, textvariable=self.var, anchor="w")
        self.label.pack(fill="x", padx=8, pady=2)

    def set(self, text: str):
        self.var.set(text)


# ---------------- Enforcement helper ----------------------------------------
def _compute_enforcement(cfg, st, *, allowed: bool):
    """
    Construye el conjunto efectivo de reglas para Notifier/Guardian según
    configuración + whitelist, respetando horarios.
    Devuelve (rules, changed)
    """
    prev = st.get("enforcement") or {}
    wl = cfg.get("game_whitelist") or []
    bl = cfg.get("blocked_executables") or []

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


# ======================== Main App ==========================================
class TutorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("XiaoHack — Control Parental")
        try:
            if ICON_APP.exists():
                self.iconbitmap(default=str(ICON_APP))
        except Exception:
            pass

        apply_theme(self, mode="auto")

        # Layout básico
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        self.main = ttk.Frame(self)
        self.main.grid(row=0, column=0, sticky="nsew")
        self.main.columnconfigure(0, weight=1)

        # Encabezado
        title = ttk.Label(self.main, text="Panel del Tutor", font=("Segoe UI", 14, "bold"))
        title.grid(row=0, column=0, sticky="w", padx=10, pady=(10,4))

        # Botonera principal (ejemplo; conserva tus comandos originales)
        btns = ttk.Frame(self.main)
        btns.grid(row=1, column=0, sticky="w", padx=10, pady=6)

        ttk.Button(btns, text="Filtrado web", command=self.on_webfilter).grid(row=0, column=0, padx=4, pady=2)
        ttk.Button(btns, text="DNS", command=self.on_dns).grid(row=0, column=1, padx=4, pady=2)
        ttk.Button(btns, text="DoH", command=self.on_doh).grid(row=0, column=2, padx=4, pady=2)
        ttk.Button(btns, text="Lista de apps", command=self.on_blocklist).grid(row=0, column=3, padx=4, pady=2)
        ttk.Button(btns, text="Acerca de", command=self.on_about).grid(row=0, column=4, padx=4, pady=2)

        # Status bar
        self.status = StatusBar(self)
        self.status.grid(row=2, column=0, sticky="ew")

        self.refresh_status()

    def refresh_status(self):
        try:
            cfg = load_config()
            st = load_state()
        except Exception as e:
            log.error("No se pudo cargar config/estado: %s", e, exc_info=True)
            return

        # Ejemplo: calcular enforcement actual por horario (si lo usas)
        allowed_now = True  # sustituir por scheduler si corresponde
        rules, changed = _compute_enforcement(cfg, st, allowed=allowed_now)
        if changed:
            save_state(st)
        txt = f"Reglas: {rules['mode']} — bloqueos: {len(rules['block'])}"
        self.status.set(txt)

    # --- Acciones de UI (conserva tus handlers reales) ------------------
    def on_webfilter(self):
        show_blocklist_editor(self)

    def on_dns(self):
        show_dns_dialog(self)

    def on_doh(self):
        show_doh_dialog(self)

    def on_blocklist(self):
        show_blocklist_editor(self)

    def on_about(self):
        show_about_dialog(self)


# ======================== Lanzador ==========================================
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
        from .services import check_update_and_maybe_apply_async
        app.after(3000, lambda: check_update_and_maybe_apply_async(app))
        app.mainloop()
    except Exception as e:
        err = traceback.format_exc()
        try:
            with open("gui_error.log", "a", encoding="utf-8") as f:
                f.write(err)
        except Exception:
            pass
        messagebox.showerror("Error crítico", str(e))

if __name__ == "__main__":
    run()
