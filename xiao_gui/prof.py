# xiao_gui/prof.py — monitor de latencia del loop Tkinter
from __future__ import annotations
import time
import weakref
from typing import Optional, Callable
from app.logs import get_logger

log = get_logger("gui.prof")

# Estado global para compatibilidad con el helper tick()
_last_tick = [time.perf_counter()]


class UILagProbe:
    """
    Pequeño monitor del loop Tkinter:
      - Usa after() periódico.
      - Mide dt entre ticks (ms).
      - Calcula media móvil exponencial (EMA) y pico.
      - Dispara callback si dt > warn_ms.
      - Puede pintar en un label opcional.
    """

    def __init__(
        self,
        root,
        label_widget=None,
        interval_ms: int = 500,
        warn_ms: int = 800,
        on_warn: Optional[Callable[[float], None]] = None,
    ):
        self._root_ref = weakref.ref(root)
        self._label_ref = weakref.ref(label_widget) if label_widget else None
        self.interval_ms = int(max(50, interval_ms))
        self.warn_ms = int(max(100, warn_ms))
        self.on_warn = on_warn

        self._after_id: Optional[str] = None
        self._last = time.perf_counter()
        self._ema = None
        self._max = 0.0
        self._running = False
        
                # Auto-stop si destruyen la raíz (evita after() sobre widget muerto)
        try:
            r = self._root_ref()
            if r is not None:
                # add='+' para no pisar otros handlers del caller
                r.bind("<Destroy>", lambda e: self.stop(), add="+")
        except Exception:
            pass


    # --------------------------
    # API pública
    # --------------------------
    def start(self):
        """Inicia el monitor."""
        if self._running:
            return
        self._running = True
        log.debug("UILagProbe iniciado (interval=%d ms, warn=%d ms)", self.interval_ms, self.warn_ms)
        self._schedule_next()

    def stop(self):
        """Detiene el monitor."""
        if not self._running:
            return
        self._running = False
        root = self._root_ref()
        if root and self._after_id:
            try:
                root.after_cancel(self._after_id)
            except Exception:
                pass
        self._after_id = None
        log.debug("UILagProbe detenido")

    # --------------------------
    # Internos
    # --------------------------
    def _schedule_next(self):
        root = self._root_ref()
        if not root or not self._running:
            self.stop()
            return
        try:
            self._after_id = root.after(self.interval_ms, self._tick_once)
        except Exception as e:
            log.warning("Error al programar after(): %s", e)
            self.stop()

    def _tick_once(self):
        now = time.perf_counter()
        dt_ms = (now - self._last) * 1000.0
        self._last = now

        # EMA (media móvil exponencial)
        if self._ema is None:
            self._ema = dt_ms
        else:
            self._ema = 0.1 * dt_ms + 0.9 * self._ema

        # Pico
        if dt_ms > self._max:
            self._max = dt_ms

        # Aviso
        if dt_ms > self.warn_ms:
            log.warning("UI lag alto: %.0f ms (EMA=%.0f, pico=%.0f)", dt_ms, self._ema, self._max)
            if self.on_warn:
                try:
                    self.on_warn(dt_ms)
                except Exception as e:
                    log.error("Error en callback on_warn: %s", e)

        # Label opcional
        lbl = self._label_ref() if self._label_ref else None
        if lbl:
            try:
                lbl.config(
                    text=f"UI lag: {int(dt_ms)} ms (EMA {int(self._ema)} / pico {int(self._max)})"
                )
            except Exception:
                self._label_ref = None

        # Reprogramar siguiente tick
        self._schedule_next()
        
    def get_metrics(self) -> tuple[float, float, float]:
        """Devuelve (dt_ms_último, ema_ms, pico_ms)."""
        last = (time.perf_counter() - self._last) * 1000.0  # aproximado al instante
        ema = float(self._ema if self._ema is not None else 0.0)
        return (max(0.0, last), ema, float(self._max))

    def reset_metrics(self) -> None:
        """Resetea EMA y pico (útil tras un spike inicial)."""
        self._ema = None
        self._max = 0.0
  


# ---------------------- Compat API (drop-in) ----------------------
def start(
    root,
    label_widget=None,
    interval_ms: int = 500,
    warn_ms: int = 800,
    on_warn: Optional[Callable[[float], None]] = None,
) -> UILagProbe:
    """
    Arranca un monitor persistente y devuelve el objeto.
    Ejemplo:
        probe = prof.start(root, lbl_status)
        ...
        probe.stop()
    """
    probe = UILagProbe(
        root,
        label_widget=label_widget,
        interval_ms=interval_ms,
        warn_ms=warn_ms,
        on_warn=on_warn,
    )
    probe.start()
    return probe


def stop(probe: UILagProbe):
    """Detiene un monitor iniciado con start()."""
    if isinstance(probe, UILagProbe):
        probe.stop()


# ---------------------- Helper legado (compatibilidad) ----------------------
def tick(root, label_widget=None, warn_ms=800):
    """
    Compat: llama a esto cada ~500 ms con root.after.
    Si el loop 'se para', opcionalmente pinta en label_widget.
    """
    now = time.perf_counter()
    dt = (now - _last_tick[0]) * 1000.0
    _last_tick[0] = now

    if dt > warn_ms and label_widget:
        try:
            label_widget.config(text=f"⚠ lag UI {int(dt)} ms")
        except Exception:
            pass

    try:
        root.after(500, tick, root, label_widget, warn_ms)
    except Exception:
        pass
