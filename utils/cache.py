# utils/cache.py — XiaoHack Parental
# Caché simple con TTL (Time-To-Live) y logs opcionales para depuración.
import time
import threading
from typing import Any, Callable, Dict, Tuple
from app.logs import get_logger

log = get_logger("cache")

_cache: Dict[str, Tuple[Any, float]] = {}
_LOCK = threading.Lock()


def memo_ttl(key: str, ttl_seconds: float, getter: Callable[[], Any]) -> Any:
    """
    Devuelve el valor cacheado si no ha expirado; si no, ejecuta getter(),
    guarda y devuelve el nuevo valor.

    Args:
        key: clave única (string).
        ttl_seconds: segundos de validez.
        getter: función que genera el valor si expiró.
    """
    now = time.time()

    with _LOCK:
        item = _cache.get(key)
        if item:
            value, ts = item
            if (now - ts) < ttl_seconds:
                log.debug("Cache hit: %s (age=%.1fs < %.1fs)", key, now - ts, ttl_seconds)
                return value

    # Si llegamos aquí → expirado o inexistente
    log.debug("Cache miss: %s (ttl=%ss)", key, ttl_seconds)
    try:
        value = getter()
    except Exception as e:
        log.error("Error ejecutando getter() de cache '%s': %s", key, e, exc_info=True)
        raise

    with _LOCK:
        _cache[key] = (value, now)
    return value


def clear(key: str | None = None) -> None:
    """
    Borra una clave concreta o todo el caché.
    """
    with _LOCK:
        if key is None:
            _cache.clear()
            log.debug("Cache global vaciado")
        else:
            existed = key in _cache
            _cache.pop(key, None)
            if existed:
                log.debug("Cache entry eliminada: %s", key)
