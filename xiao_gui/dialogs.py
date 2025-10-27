# xiao_gui/dialogs.py — diálogos de PIN del tutor
from __future__ import annotations
import tkinter as tk
from tkinter import ttk, simpledialog, messagebox

from app.logs import get_logger
from utils.security import hash_pin, check_pin, validate_pin

log = get_logger("gui.dialogs")


# ---------- Diálogo de entrada ----------
class _PinDialog(simpledialog.Dialog):
    """Ventana de entrada de PIN con opción de mostrar/ocultar."""

    def __init__(self, parent, title="PIN del tutor"):
        self._pin = None
        super().__init__(parent, title)

    def body(self, master):
        ttk.Label(master, text="Introduce el PIN del tutor:").grid(
            row=0, column=0, sticky="w", padx=8, pady=(8, 2)
        )
        self.var = tk.StringVar()
        self.ent = ttk.Entry(master, textvariable=self.var, show="•", width=26)
        self.ent.grid(row=1, column=0, sticky="we", padx=8)
        self.ent.focus()

        self._show = tk.BooleanVar(value=False)
        chk = ttk.Checkbutton(master, text="Mostrar", variable=self._show, command=self._toggle)
        chk.grid(row=2, column=0, sticky="w", padx=8, pady=(2, 8))
        master.grid_columnconfigure(0, weight=1)
        return self.ent

    def _toggle(self):
        self.ent.configure(show="" if self._show.get() else "•")

    def apply(self):
        self._pin = (self.var.get() or "").strip()
        # limpia por seguridad
        self.var.set("")


def ask_pin(parent) -> str | None:
    """Pide al usuario el PIN y lo devuelve como texto o None si canceló."""
    dlg = _PinDialog(parent)
    pin = dlg._pin
    if pin:
        log.debug("PIN introducido (long=%d)", len(pin))
    else:
        log.debug("Entrada de PIN cancelada.")
    return pin


# ---------- Alta/cambio de PIN ----------
def set_new_pin_hash(parent, *, min_len=4, max_len=10, digits_only=True) -> str | None:
    """
    Pide dos veces el PIN, valida y devuelve su hash (o None si se cancela/valida mal).
    """
    p1 = simpledialog.askstring("Nuevo PIN", "Introduce un nuevo PIN:", parent=parent, show="•")
    if p1 is None or p1.strip() == "":
        log.debug("Creación de nuevo PIN cancelada (vacío o None).")
        return None

    ok, err = validate_pin(p1, min_len=min_len, max_len=max_len, digits_only=digits_only)
    if not ok:
        messagebox.showerror("PIN inválido", err, parent=parent)
        return None

    p2 = simpledialog.askstring("Confirmación", "Repite el PIN:", parent=parent, show="•")
    if p2 is None:
        return None
    if p1 != p2:
        messagebox.showerror("Error", "Los PIN no coinciden.", parent=parent)
        log.warning("Intento de nuevo PIN: los valores no coincidieron.")
        return None

    h = hash_pin(p1)
    log.info("PIN establecido (hash generado correctamente).")
    # limpia variables locales
    p1 = p2 = None
    return h


# ---------- Verificación ----------
def verify_pin_dialog(parent, stored_hash: str) -> bool:
    """
    Abre un diálogo pidiendo el PIN y lo verifica.
    Devuelve True si coincide, False si no o si se cancela.
    """
    pin = ask_pin(parent)
    if pin is None:
        return False
    if check_pin(stored_hash, pin):
        log.debug("PIN verificado correctamente.")
        return True
    else:
        messagebox.showerror("Error", "PIN incorrecto.", parent=parent)
        log.warning("PIN incorrecto introducido.")
        return False
