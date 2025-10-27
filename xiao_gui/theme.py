# xiao_gui/theme.py — tema claro/oscuro normalizado (auto / light / dark)
from __future__ import annotations
import os
import tkinter as tk
from tkinter import ttk
from app.logs import get_logger

log = get_logger("gui.theme")

# ---------------- Paletas normalizadas ----------------
_DARK = dict(
    bg="#1f1f1f", sub="#262626", sub2="#2d2d2d",
    fg="#f0f0f0", fg_muted="#cfcfcf",
    border="#343434", sel="#4f8cff", sel_fg="#ffffff", accent="#4f8cff"
)
_LIGHT = dict(
    bg=None, sub="#ffffff", sub2="#f6f6f6",
    fg="#000000", fg_muted="#222222",
    border="#d9d9d9", sel="#d9e8ff", sel_fg="#000000", accent="#0b69ff"
)

# ======================================================================
# Detección de tema del sistema (Windows)
#   Windows guarda en:
#   HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize
#     - AppsUseLightTheme = 1 (claro) / 0 (oscuro)
# ======================================================================
def _system_prefers_dark() -> bool:
    if os.name != "nt":
        return False
    try:
        import winreg  # type: ignore
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
            0,
            winreg.KEY_READ,
        ) as k:
            v, _ = winreg.QueryValueEx(k, "AppsUseLightTheme")
            return int(v) == 0
    except Exception:
        return False


# ======================================================================
# ThemeManager: aplica estilos idempotentes y escucha cambios del sistema
# ======================================================================
class ThemeManager:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.mode = "auto"   # 'auto' | 'light' | 'dark'
        self._bound = False  # WM_SETTINGCHANGE hook
        self._last_dark = None

    def apply(self, mode: str = "auto"):
        """
        Aplica tema:
          - mode = 'auto'  → sigue el sistema (Windows)
          - mode = 'light' → claro
          - mode = 'dark'  → oscuro
        """
        mode = (mode or "auto").lower()
        if mode not in ("auto", "light", "dark"):
            mode = "auto"
        self.mode = mode

        dark = _system_prefers_dark() if mode == "auto" else (mode == "dark")
        _apply_theme_normalized(self.root, dark)
        self._last_dark = dark

        # Hook para cambiar al vuelo si estamos en 'auto'
        if os.name == "nt":
            if mode == "auto" and not self._bound:
                try:
                    # tk no expone WM_SETTINGCHANGE, pero sí nos da el mensaje cuando cambia
                    # el registro (señal general de settings) → aprovechamos y re-aplicamos.
                    self.root.bind("<<ThemeAutoRefresh>>", lambda e: self._on_auto_refresh(), add="+")
                    # Pequeño temporizador para 'sondear' cambios cada X ms (fiable en tk)
                    self._bound = True
                    self._schedule_probe()
                except Exception:
                    pass
            elif mode != "auto" and self._bound:
                self._bound = False  # el probe se auto-cancela

        log.info("Tema aplicado: %s (modo=%s)", ("oscuro" if dark else "claro"), self.mode)

    # ---------- mecanismo simple de 'probe' para detectar cambios del sistema ----------
    def _schedule_probe(self):
        if not self._bound:
            return
        self.root.after(2500, self._probe_and_refresh)

    def _probe_and_refresh(self):
        if not self._bound or self.mode != "auto":
            return
        try:
            new_dark = _system_prefers_dark()
            if new_dark != self._last_dark:
                _apply_theme_normalized(self.root, new_dark)
                self._last_dark = new_dark
                self.root.event_generate("<<ThemeAutoRefresh>>", when="tail")
        except Exception:
            pass
        finally:
            self._schedule_probe()

    def _on_auto_refresh(self):
        # Gancho disponible si la UI quiere reaccionar de forma adicional
        pass


# ======================================================================
# Implementación: escribir estilos siempre igual (idempotente)
# ======================================================================
def _apply_theme_normalized(root: tk.Tk, dark: bool):
    s = ttk.Style()
    pal = _DARK if dark else _LIGHT

    # 1) Tema base coherente (usar 'clam' si no hay 'vista')
    try:
        if dark:
            s.theme_use("clam")
        else:
            try:
                s.theme_use("vista")
            except Exception:
                s.theme_use("clam")
    except Exception as e:
        log.warning("Falló theme_use: %s", e)

    # 2) Fondo raíz
    try:
        root.configure(bg=(pal["bg"] if dark else s.lookup("TFrame", "background") or "#f0f0f0"))
    except Exception:
        pass

    base_bg = pal["bg"] if dark else (s.lookup("TFrame", "background") or "#f0f0f0")

    # 3) Reconfiguración *completa* de estilos (idempotente)
    s.configure("TFrame", background=base_bg)
    s.configure("Header.TFrame", background=base_bg)

    s.configure("TLabel", background=base_bg, foreground=pal["fg"])
    s.configure("Header.TLabel", background=base_bg, foreground=(pal["fg"] if dark else "black"))

    # Botones
    s.configure(
        "TButton",
        background=(pal["sub"] if dark else None),
        foreground=pal["fg"],
        padding=6,
        bordercolor=pal["border"],
        focusthickness=1,
        focuscolor=pal["accent"],
    )
    s.map(
        "TButton",
        background=[("active", pal["sub2"] if dark else None)],
        relief=[("pressed", "sunken")],
    )

    # Check / Radio
    for w in ("TCheckbutton", "TRadiobutton"):
        s.configure(w, background=base_bg, foreground=pal["fg"])

    # Entry / Combobox
    s.configure(
        "TEntry",
        fieldbackground=(pal["sub"] if dark else "white"),
        background=(pal["sub"] if dark else "white"),
        foreground=pal["fg"],
        bordercolor=pal["border"],
    )
    s.map("TEntry", fieldbackground=[("readonly", pal["sub2"] if dark else "#f7f7f7")])

    s.configure(
        "TCombobox",
        fieldbackground=(pal["sub"] if dark else "white"),
        background=(pal["sub"] if dark else "white"),
        foreground=pal["fg"],
        arrowcolor=(pal["fg"] if dark else "#333333"),
    )
    s.map("TCombobox", fieldbackground=[("readonly", pal["sub2"] if dark else "#f7f7f7")])

    # Notebook / Tabs
    s.configure("TNotebook", background=base_bg, bordercolor=pal["border"])
    s.configure("TNotebook.Tab", padding=(12, 6), background=base_bg, foreground=pal["fg"])
    s.map(
        "TNotebook.Tab",
        background=[("selected", pal["sub"] if dark else base_bg)],
        foreground=[("selected", pal["fg"])],
    )

    # Treeview
    s.configure(
        "Treeview",
        background=(pal["sub"] if dark else "white"),
        fieldbackground=(pal["sub"] if dark else "white"),
        foreground=pal["fg"],
        bordercolor=pal["border"],
        rowheight=28,
    )
    s.configure("Treeview.Heading", background=base_bg, foreground=pal["fg"], font=("", 9, "bold"))
    s.map(
        "Treeview",
        background=[("selected", pal["sel"])],
        foreground=[("selected", pal["sel_fg"])],
    )

    # Scrollbars
    s.configure("Vertical.TScrollbar", background=(pal["sub2"] if dark else None), troughcolor=(pal["sub"] if dark else None))
    s.configure("Horizontal.TScrollbar", background=(pal["sub2"] if dark else None), troughcolor=(pal["sub"] if dark else None))


# ======================================================================
# API pública cómoda (retrocompatible con tu código)
# ======================================================================
def apply_theme(root: tk.Tk, mode: str = "auto"):
    """
    Aplica tema. 'mode' ∈ {'auto','light','dark'}.
    Devuelve la paleta usada.
    """
    tm = getattr(root, "_xh_theme_manager", None)
    if tm is None:
        tm = ThemeManager(root)
        root._xh_theme_manager = tm
    tm.apply(mode)
    # devolvemos la paleta efectiva por comodidad en llamadas existentes
    return (_DARK if (_system_prefers_dark() if mode == "auto" else mode == "dark") else _LIGHT)


def style_listbox(lb: tk.Listbox, dark: bool):
    """Aplica colores coherentes al Listbox según el tema."""
    if dark:
        lb.configure(
            bg="#262626",
            fg="#f0f0f0",
            selectbackground="#4f8cff",
            selectforeground="#ffffff",
            highlightthickness=0,
            borderwidth=1,
            relief="solid",
        )
    else:
        lb.configure(
            bg="white",
            fg="black",
            selectbackground="#d9e8ff",
            selectforeground="black",
            highlightthickness=0,
            borderwidth=1,
            relief="solid",
        )


def apply_treeview_stripes(tv: ttk.Treeview, dark: bool):
    """
    Aplica 'zebra stripes' a las filas ya existentes.
    Llamar después de poblar el Treeview.
    """
    odd = "#262626" if dark else "#f9f9f9"
    even = "#2d2d2d" if dark else "white"

    tv.tag_configure("oddrow", background=odd)
    tv.tag_configure("evenrow", background=even)

    for i, iid in enumerate(tv.get_children("")):
        tv.item(iid, tags=("oddrow" if i % 2 else "evenrow",))
