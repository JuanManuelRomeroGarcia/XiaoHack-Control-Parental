# utils/tk_safe.py — helpers seguros para Tkinter desde hilos
from app.logs import get_logger
log = get_logger("async")

def after_safe(widget, ms, fn):
    """
    Ejecuta widget.after(ms, fn) de forma segura.
    - Comprueba que el widget sigue existiendo.
    - Ignora RuntimeError/TclError si el mainloop ya no está activo.
    """
    try:
        if widget and getattr(widget, "winfo_exists", None) and widget.winfo_exists():
            widget.after(ms, fn)
    except Exception as e:
        # Evita ruidos si el mainloop ya terminó o el widget fue destruido
        if "main thread is not in main loop" in str(e):
            log.debug("after_safe descartado (mainloop cerrado): %s", e)
        else:
            log.debug("after_safe ignorado: %s", e)
