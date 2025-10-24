# utils/async_tasks.py — XiaoHack Parental
# Pool de tareas asincrónicas con control de concurrencia y logs centralizados.
from concurrent.futures import ThreadPoolExecutor
import threading
import contextlib
import traceback
from logs import get_logger

log = get_logger("async")

# Pool pequeño y estable
_EXECUTOR = ThreadPoolExecutor(max_workers=3)

# Limita tareas simultáneas "en vuelo" (evita avalanchas si cambias de tab)
_MAX_INFLIGHT = 3
_SEM = threading.Semaphore(_MAX_INFLIGHT)


class CancelToken:
    __slots__ = ("_rev",)

    def __init__(self, rev: int):
        self._rev = rev

    def is_current(self, rev: int) -> bool:
        return self._rev == rev


class TaskGate:
    """
    Una 'versión' por página o contexto. Cuando cambias de tab o pantalla,
    aumenta la rev y todas las tareas anteriores quedan obsoletas.
    """

    def __init__(self):
        self._rev = 0
        self._lock = threading.Lock()

    def next_rev(self) -> int:
        with self._lock:
            self._rev += 1
            log.debug("Nueva revisión TaskGate → %d", self._rev)
            return self._rev

    def is_current(self, rev: int) -> bool:
        with self._lock:
            return rev == self._rev

    def token(self) -> CancelToken:
        return CancelToken(self._rev)
    

def submit_limited(fn, *args, **kwargs):
    """
    Encola la función `fn` en el pool con control de 'in-flight'.
    Si el límite está lleno, espera un hueco antes de ejecutar.
    Envuelve la tarea con logs y manejo de excepciones seguro.
    """
    _SEM.acquire()

    def _wrapped():
        try:
            name = getattr(fn, "__name__", str(fn))
            log.debug("Tarea iniciada: %s", name)
            result = fn(*args, **kwargs)
            log.debug("Tarea completada: %s", name)
            return result

        except RuntimeError as e:
            # Caso típico al postear a Tk tras cerrar/cambiar de pestaña
            if "main thread is not in main loop" in str(e):
                log.debug("Tarea descartada (mainloop cerrado): %s", e)
                return None
            # Cualquier otro RuntimeError sí lo registramos como error
            log.error("Error en tarea (RuntimeError): %s\n%s", e, traceback.format_exc())

        except Exception:
            log.error("Error en tarea %s:\n%s",
                      getattr(fn, "__name__", str(fn)),
                      traceback.format_exc())

        finally:
            with contextlib.suppress(Exception):
                _SEM.release()

    return _EXECUTOR.submit(_wrapped)
