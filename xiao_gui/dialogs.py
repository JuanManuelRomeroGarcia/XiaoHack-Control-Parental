# xiao_gui/dialogs.py — diálogos de PIN del tutor
from __future__ import annotations
import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
from logs import get_logger

log = get_logger("gui.dialogs")

# ---------- Dependencia opcional ----------
try:
    import bcrypt
except Exception:
    bcrypt = None
    log.warning("bcrypt no disponible: el PIN se comparará en texto plano (modo desarrollo).")
    _warned_once = False
else:
    _warned_once = True


# ---------- Utilidades de hash ----------
def hash_pin(pin: str) -> str:
    """Genera un hash seguro del PIN (usa bcrypt si está disponible)."""
    if not bcrypt:
        log.warning("Usando hash PIN inseguro (bcrypt no instalado).")
        return pin
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(pin.encode("utf-8"), salt).decode("utf-8")


def check_pin(stored_hash: str, pin: str) -> bool:
    """Verifica el PIN contra el hash almacenado."""
    if not stored_hash:
        return False
    if not bcrypt:
        log.warning("Comparando PIN en texto plano (bcrypt no disponible).")
        return stored_hash == pin
    try:
        return bcrypt.checkpw(pin.encode("utf-8"), stored_hash.encode("utf-8"))
    except Exception as e:
        log.error("Error comprobando PIN: %s", e, exc_info=True)
        return False


# ---------- Diálogos ----------
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


def set_new_pin_hash(parent) -> str | None:
    """Pide dos veces el PIN, comprueba coincidencia y devuelve su hash."""
    p1 = simpledialog.askstring("Nuevo PIN", "Introduce un nuevo PIN:", parent=parent, show="•")
    if p1 is None or p1.strip() == "":
        log.debug("Creación de nuevo PIN cancelada (vacío o None).")
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
