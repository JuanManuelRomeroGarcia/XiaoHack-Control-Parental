# scheduler.py — Horarios y avisos (manual + tramos) con LOG centralizado
# al inicio del archivo:
#import os
#from app import helperdb


from datetime import datetime, time as dtime, timedelta
from typing import Dict, List, Tuple, Optional

from app.logs import get_logger
log = get_logger("scheduler")

# =========================
# Utilidades de horarios
# =========================

_DAY_ALIASES = {
    "mon": "mon", "tue": "tue", "wed": "wed", "thu": "thu", "fri": "fri",
    "sat": "sat", "sun": "sun",
    # Español corto admitido:
    "lun": "mon", "mar": "tue", "mie": "wed", "mié": "wed",
    "jue": "thu", "vie": "fri", "sab": "sat", "sáb": "sat", "dom": "sun",
}

# Umbrales (segundos)
M10 = 10 * 60
M5  = 5 * 60
M1  = 60

def _parse_time(s: str) -> dtime:
    try:
        h, m = map(int, s.split(":"))
        return dtime(hour=h, minute=m)
    except Exception:
        log.warning("Hora inválida en _parse_time(%r)", s)
        raise

def _norm_days(days: List[str]) -> List[str]:
    return [_DAY_ALIASES.get((d or "").lower()[:3], (d or "").lower()[:3]) for d in days]

def is_within_allowed_hours(cfg: dict, now: datetime) -> bool:
    """
    True si 'now' cae dentro de algún tramo permitido.
    Soporta tramos normales (from <= to) y tramos que cruzan medianoche (from > to).
    """
    day = now.strftime("%a").lower()[:3]
    tnow = now.time()
    for sch in cfg.get("schedules", []):
        if not sch or "from" not in sch or "to" not in sch:
            continue
        days = _norm_days(sch.get("days", []))
        if day not in days:
            continue
        t_from = _parse_time(sch["from"])
        t_to   = _parse_time(sch["to"])
        if t_from <= t_to:
            # Tramo normal: dentro si t_from <= now <= t_to
            if t_from <= tnow <= t_to:
                return True
        else:
            # Tramo overnight: permitido si now >= from (hoy) o now <= to (mañana)
            if tnow >= t_from or tnow <= t_to:
                return True
    return False


def current_allowed_window(cfg: dict, now: datetime) -> Optional[Tuple[datetime, datetime]]:
    """
    Si 'now' está dentro de un tramo permitido devuelve (inicio, fin) del tramo (datetimes).
    Soporta tramos normales y que cruzan medianoche.
    """
    day_code = now.strftime("%a").lower()[:3]
    tnow = now.time()

    for sch in cfg.get("schedules", []):
        if not sch or "from" not in sch or "to" not in sch:
            continue
        days = _norm_days(sch.get("days", []))
        if day_code not in days:
            continue

        t_from = _parse_time(sch["from"])
        t_to   = _parse_time(sch["to"])

        if t_from <= t_to:
            # Tramo normal
            if t_from <= tnow <= t_to:
                start = now.replace(hour=t_from.hour, minute=t_from.minute, second=0, microsecond=0)
                end   = now.replace(hour=t_to.hour,   minute=t_to.minute,   second=0, microsecond=0)
                return (start, end)
        else:
            # Tramo overnight: ejemplo 21:30 → 01:00
            if tnow >= t_from:
                # Estamos en la parte "hoy" (desde from hasta 23:59:59...)
                start = now.replace(hour=t_from.hour, minute=t_from.minute, second=0, microsecond=0)
                end   = (now + timedelta(days=1)).replace(hour=t_to.hour, minute=t_to.minute, second=0, microsecond=0)
                return (start, end)
            elif tnow <= t_to:
                # Estamos en la parte "madrugada" (00:00 → to); el tramo empezó AYER
                start = (now - timedelta(days=1)).replace(hour=t_from.hour, minute=t_from.minute, second=0, microsecond=0)
                end   = now.replace(hour=t_to.hour,   minute=t_to.minute,   second=0, microsecond=0)
                return (start, end)

    return None


def is_play_allowed(cfg: dict, state: dict, now: datetime) -> bool:
    """
    Permitido si:
      - hay sesión manual activa (state['play_until'] > now), o
      - estamos dentro de un tramo horario permitido.
    """
    play_until = int(state.get("play_until") or 0)
    if play_until > int(now.timestamp()):
        return True
    return is_within_allowed_hours(cfg, now)

def build_example_schedules() -> List[Dict]:
    """L–V 18–19, S/D 10–13 y 17–20."""
    return [
        {"days": ["mon", "tue", "wed", "thu", "fri"], "from": "18:00", "to": "19:00"},
        {"days": ["sat", "sun"], "from": "10:00", "to": "13:00"},
        {"days": ["sat", "sun"], "from": "17:00", "to": "20:00"},
    ]

# =========================
# Avisos / Cuenta atrás
# =========================

def _ensure_alert_struct(state: dict) -> Dict:
    pa = state.get("play_alerts")
    if not isinstance(pa, dict):
        pa = {}
    pa.setdefault("enabled", True)
    pa.setdefault("m10", False)
    pa.setdefault("m5", False)
    pa.setdefault("m1", False)
    pa.setdefault("countdown_started", False)
    state["play_alerts"] = pa
    state.setdefault("play_countdown", 0)
    return pa

def _sec_remaining_manual(state: dict, now: datetime) -> int:
    play_until = int(state.get("play_until") or 0)
    return play_until - int(now.timestamp())

def _sec_remaining_schedule(cfg: dict, now: datetime) -> int:
    win = current_allowed_window(cfg, now)
    if not win:
        return -1
    _start, end = win
    return int(end.timestamp()) - int(now.timestamp())

def remaining_play_seconds(state: dict, now: datetime, cfg: Optional[dict] = None) -> Tuple[int, Optional[str]]:
    """
    Devuelve (remaining_seconds, mode):
      - Si hay sesión manual activa → (segundos_restantes, "manual")
      - Si no y cfg indica tramo activo → (segundos_restantes, "schedule")
      - Si nada → (<=0, None)
    """
    rem = _sec_remaining_manual(state, now)
    if rem > 0:
        return rem, "manual"
    if cfg is not None:
        rem = _sec_remaining_schedule(cfg, now)
        if rem > 0:
            return rem, "schedule"
    return rem, None

def check_playtime_alerts(state: dict, now: datetime, cfg: Optional[dict] = None) -> Tuple[List[str], int]:
    """
    Lanza avisos a 10/5/1 min y activa cuenta atrás (60→0) en el último minuto.
    Prioridad:
      1) Sesión manual (state['play_until'])
      2) Tramo horario actual (si se provee cfg)
    Devuelve (mensajes, countdown_segundos). No guarda a disco.
    """
    log.debug("check_playtime_alerts: play_until=%s now=%s", state.get("play_until"), int(now.timestamp()))

    pa = _ensure_alert_struct(state)
    messages: List[str] = []

    remaining, mode = remaining_play_seconds(state, now, cfg)

    # Sin tiempo restante → reset
    if remaining <= 0:
        state["play_countdown"] = 0
        if state.get("play_alert_mode") in ("manual", "schedule"):
            pa["m10"] = pa["m5"] = pa["m1"] = False
            pa["countdown_started"] = False
            state["play_alert_mode"] = None
        log.debug("No hay tiempo restante → reset countdown")
        return messages, 0

    if not pa.get("enabled", True):
        log.debug("Alertas desactivadas por configuración")
        return messages, 0

    # Cambio de modo o reinicio de sesión
    last_mode = state.get("play_alert_mode")
    last_until = state.get("_alerts_last_until", 0)
    current_until = int(state.get("play_until") or 0)
    if last_mode != mode or last_until != current_until:
        pa["m10"] = pa["m5"] = pa["m1"] = False
        pa["countdown_started"] = False
        state["play_alert_mode"] = mode
        state["_alerts_last_until"] = current_until
        log.debug("Reset de flags: last_mode=%s new_mode=%s", last_mode, mode)

    log.debug("Tiempo restante=%s mode=%s flags=%s", remaining, mode, pa)

    # Umbrales
    if remaining <= M10 and not pa["m10"]:
        pa["m10"] = True
        messages.append("⏳ Quedan 10 minutos de juego.")
        log.info("Emitido aviso de 10 minutos")
        
        #if (os.getenv("XH_ROLE") or "").lower() != "guardian":
        #   helperdb.log_event("notify", "Tiempo de juego", "⏳ Quedan 10 minutos de juego.")

    if remaining <= M5 and not pa["m5"]:
        pa["m5"] = True
        messages.append("⏳ Quedan 5 minutos de juego.")
        log.info("Emitido aviso de 5 minutos")
        
        #if (os.getenv("XH_ROLE") or "").lower() != "guardian":
        #   helperdb.log_event("notify", "Tiempo de juego", "⏳ Quedan 5 minutos de juego.")

    if remaining <= M1 and not pa["m1"]:
        pa["m1"] = True
        pa["countdown_started"] = True
        messages.append("⚠️ ¡Último minuto! Comienza la cuenta atrás.")
        log.warning("Último minuto: inicia cuenta atrás")

    # Cuenta atrás visible (0..60)
    if pa.get("countdown_started", False):
        countdown = max(0, min(60, remaining))
        state["play_countdown"] = countdown
        log.debug("Cuenta atrás activa: %s s", countdown)
        return messages, countdown

    state["play_countdown"] = 0
    return messages, 0

# =========================
# Helpers para OVERLAY
# =========================

def get_overlay_countdown(state: dict) -> int:
    """
    Segundos (0..60) que debe mostrar el overlay gigante. 0 = no mostrar.
    El guardian actualiza 'play_countdown' cada segundo cuando restan <= 60s.
    """
    try:
        n = int(state.get("play_countdown", 0) or 0)
    except Exception:
        n = 0
    return max(0, min(60, n))

def should_show_overlay(state: dict) -> bool:
    """
    True si hay que mostrar overlay (esto no abre panel; lo usará notifier).
    Estrategia: mostrar overlay solo durante la cuenta atrás del último minuto.
    """
    return get_overlay_countdown(state) > 0

def alerts_snapshot(state: dict, now: datetime, cfg: Optional[dict] = None) -> Dict:
    """
    Snapshot útil para el notifier/overlay (no guarda nada).
    Incluye flags de m10/m5/m1, segundos restantes y modo.
    """
    pa = state.get("play_alerts") or {}
    rem, mode = remaining_play_seconds(state, now, cfg)
    return {
        "remaining": max(0, rem),
        "mode": mode,  # "manual" | "schedule" | None
        "m10": bool(pa.get("m10")),
        "m5": bool(pa.get("m5")),
        "m1": bool(pa.get("m1")),
        "countdown": get_overlay_countdown(state),
    }


if __name__ == "__main__":
    import time
    cfg = {"schedules": build_example_schedules()}
    st = {"play_until": 0}
    log.info("Scheduler test iniciado")
    while True:
        now = datetime.now()
        allowed = is_within_allowed_hours(cfg, now)
        rem, mode = remaining_play_seconds(st, now, cfg)
        log.debug("loop allowed=%s rem=%ss mode=%s", allowed, rem, mode)
        time.sleep(10)
