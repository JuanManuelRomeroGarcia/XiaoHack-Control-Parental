# utils/security.py — hashing/validación de PIN (reutilizable)
from __future__ import annotations
import hmac
from typing import Tuple

try:
    import bcrypt  # type: ignore
except Exception:  # pragma: no cover
    bcrypt = None

_PLAIN_PREFIX = "plain:"

def hash_pin(pin: str) -> str:
    """Devuelve un hash seguro del PIN (bcrypt si está disponible; si no, prefijo plain:)."""
    pin = (pin or "").strip()
    if bcrypt:
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(pin.encode("utf-8"), salt).decode("utf-8")
    # Fallback (desarrollo). Marcamos con prefijo para distinguir de hashes reales.
    return _PLAIN_PREFIX + pin

def check_pin(stored_hash: str, pin: str) -> bool:
    """Verifica un PIN contra el hash almacenado, con comparación constante en los fallbacks."""
    if not stored_hash:
        return False
    pin = (pin or "").strip()
    if bcrypt and not stored_hash.startswith(_PLAIN_PREFIX):
        try:
            return bcrypt.checkpw(pin.encode("utf-8"), stored_hash.encode("utf-8"))
        except Exception:
            return False
    # Fallbacks: prefijo plain: o legado en claro sin prefijo
    if stored_hash.startswith(_PLAIN_PREFIX):
        return hmac.compare_digest(stored_hash[len(_PLAIN_PREFIX):], pin)
    return hmac.compare_digest(stored_hash, pin)

def validate_pin(pin: str, min_len: int = 4, max_len: int = 10, digits_only: bool = True) -> Tuple[bool, str]:
    """Valida formato del PIN: longitud y (opcional) solo dígitos. Devuelve (ok, mensaje_error)."""
    if pin is None:
        return False, "PIN vacío."
    p = pin.strip()
    if len(p) < min_len:
        return False, f"PIN demasiado corto (mínimo {min_len})."
    if len(p) > max_len:
        return False, f"PIN demasiado largo (máximo {max_len})."
    if digits_only and not p.isdigit():
        return False, "El PIN solo puede tener dígitos."
    return True, ""
