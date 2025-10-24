# xiao_gui/theme.py — tema claro/oscuro para XiaoHack
import tkinter as tk
from tkinter import ttk
from logs import get_logger

log = get_logger("gui.theme")

# Paletas
_DARK = dict(
    bg="#1f1f1f", sub="#2a2a2a", sub2="#252525",
    fg="#f0f0f0", fg_muted="#cfcfcf",
    border="#343434", sel="#4f8cff", sel_fg="#ffffff", accent="#4f8cff"
)
_LIGHT = dict(
    bg=None, sub="#ffffff", sub2="#f6f6f6",
    fg="#000000", fg_muted="#222222",
    border="#d9d9d9", sel="#d9e8ff", sel_fg="#000000", accent="#0b69ff"
)

def apply_theme(root: tk.Tk, dark: bool):
    """Aplica el tema global a la ventana raíz y devuelve la paleta usada."""
    s = ttk.Style()
    pal = _DARK if dark else _LIGHT

    try:
        if dark:
            s.theme_use("clam")
        else:
            try:
                s.theme_use("vista")
            except Exception:
                s.theme_use("clam")
                log.debug("Tema 'vista' no disponible, usando 'clam'.")
    except Exception as e:
        log.warning("Error al aplicar tema base: %s", e)

    # Fondo raíz
    try:
        root.configure(bg=(pal["bg"] if dark else s.lookup("TFrame", "background") or "#f0f0f0"))
    except Exception:
        pass

    base_bg = pal["bg"] if dark else (s.lookup("TFrame", "background") or "#f0f0f0")

    # ---------- Widgets comunes ----------
    s.configure("TFrame", background=base_bg)
    s.configure("TLabel", background=base_bg, foreground=pal["fg"])
    s.configure("Header.TFrame", background=base_bg)
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
    s.configure(
        "TNotebook.Tab",
        padding=(12, 6),
        background=base_bg,
        foreground=pal["fg"],
    )
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
    s.configure(
        "Treeview.Heading",
        background=base_bg,
        foreground=pal["fg"],
        font=("", 9, "bold"),
    )
    s.map(
        "Treeview",
        background=[("selected", pal["sel"])],
        foreground=[("selected", pal["sel_fg"])],
    )

    # Scrollbars
    s.configure(
        "Vertical.TScrollbar",
        background=(pal["sub2"] if dark else None),
        troughcolor=(pal["sub"] if dark else None),
    )
    s.configure(
        "Horizontal.TScrollbar",
        background=(pal["sub2"] if dark else None),
        troughcolor=(pal["sub"] if dark else None),
    )

    log.info("Tema aplicado: %s", "oscuro" if dark else "claro")
    return pal


def style_listbox(lb: tk.Listbox, dark: bool):
    """Aplica colores coherentes al Listbox según el tema."""
    if dark:
        lb.configure(
            bg="#2a2a2a",
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

    log.debug("Zebra stripes aplicadas (%d filas, tema %s)", len(tv.get_children("")), "oscuro" if dark else "claro")
