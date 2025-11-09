# scheduler.py — Horarios y avisos (manual + tramos) con LOG centralizado
# al inicio del archivo:
#import os
#from app import helperdb


from datetime import datetime, time as dtime, timedelta
import os
from typing import Dict, List, Tuple, Optional
from app.storage import get_alerts_cfg


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


def _parse_time(s: str) -> Optional[dtime]:
    try:
        s = (s or "").strip()
        h, m = map(int, s.split(":"))
        if not (0 <= h <= 23 and 0 <= m <= 59):
            raise ValueError("out of range")
        return dtime(hour=h, minute=m)
    except Exception as e:
        log.warning("Hora inválida en _parse_time(%r): %s (ignoro tramo)", s, e)
        return None
    
def _norm_days(days) -> List[str]:
    # Acepta lista o cadena; filtra solo días válidos ['mon'..'sun']
    if isinstance(days, str):
        days = [d.strip() for d in days.replace(",", " ").split()]
    if not isinstance(days, list):
        return []
    out = []
    for d in days:
        key3 = (d or "").strip().lower()[:3]
        norm = _DAY_ALIASES.get(key3)
        if norm in ("mon","tue","wed","thu","fri","sat","sun"):
            out.append(norm)
    return out


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
        if not t_from or not t_to:
            continue
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
        
        if not t_from or not t_to:
            continue

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

def _fmt_span(seconds: int) -> str:
    """Devuelve 'X minutos' si es múltiplo de 60, si no 'Y segundos'."""
    seconds = int(max(0, seconds))
    if seconds % 60 == 0:
        m = seconds // 60
        return f"{m} minuto{'s' if m != 1 else ''}"
    return f"{seconds} segundos"


def check_playtime_alerts(state: dict, now: datetime, cfg: Optional[dict] = None) -> Tuple[List[str], int]:
    origin = (os.getenv("XH_ROLE") or "").lower()
    alerts = get_alerts_cfg(cfg)
    A1 = int(alerts.get("aviso1_sec", 600))
    A2 = int(alerts.get("aviso2_sec", 300))
    A3 = int(alerts.get("aviso3_sec", 60))
    MARGIN = 3
    GRACE_START = 5

    log.debug("check_playtime_alerts: play_until=%s now=%s", state.get("play_until"), int(now.timestamp()))

    pa = _ensure_alert_struct(state)
    messages: List[str] = []

    remaining, mode = remaining_play_seconds(state, now, cfg)

    # Sin tiempo → reset duro
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

    # --- Detectar cambio de UMBRALES (para reseed robusto) ---
    prev_rev = state.get("_alerts_rev")
    alerts_rev = f"{A1}:{A2}:{A3}"
    config_changed = (prev_rev != alerts_rev)
    if config_changed:
        state["_alerts_rev"] = alerts_rev

    # --- Detectar transición de HORARIO permitido (NO→SÍ / SÍ→NO) ---
    try:
        allowed_now = is_play_allowed(cfg, state, now)
    except Exception:
        allowed_now = (remaining > 0)  # fallback razonable

    allowed_prev = state.get("_alerts_allowed_prev")
    state["_alerts_allowed_prev"] = allowed_now  # persistimos el último visto

    # --- Cambio de 'sesión' (manual/schedule) según estado previo ---
    last_mode     = state.get("play_alert_mode")
    last_until    = state.get("_alerts_last_until", 0)
    current_until = int(state.get("play_until") or 0)

    changed_session = (last_mode != mode) or (last_until != current_until)

    # Si el horario pasa de NO permitido → SÍ permitido, tratar como inicio de sesión
    if (allowed_prev is not None) and allowed_now and (not allowed_prev):
        changed_session = True
        # Token de semilla para este “arranque por horario”
        state["_alerts_seeded_for_until"] = int(now.timestamp())

    # Si el horario pasa de SÍ → NO, hacemos un reset (por si no entró por remaining<=0)
    if (allowed_prev is not None) and (not allowed_now) and allowed_prev:
        pa["m10"] = pa["m5"] = pa["m1"] = False
        pa["countdown_started"] = False
        state["play_countdown"] = 0
        state["play_alert_mode"] = None
        log.debug("Horario desactivado → reset flags")
        return messages, 0

    SEED_KEY = "_alerts_seeded_for_until"
    seeded_for = state.get(SEED_KEY)
    # Nota: para horario usamos el timestamp del “arranque por horario” como token,
    # para manual seguimos usando play_until.
    seed_token = current_until if mode == "manual" else state.get(SEED_KEY, 0)

    need_seed = changed_session or (seeded_for != seed_token) or config_changed

    if changed_session:
        pa["m10"] = pa["m5"] = pa["m1"] = False
        pa["countdown_started"] = False
        state["play_alert_mode"] = mode
        state["_alerts_last_until"] = current_until
        log.debug("Reset de flags: last_mode=%s new_mode=%s", last_mode, mode)

    if need_seed:
        # Sembrar segun dónde arrancamos respecto a los umbrales actuales
        if remaining < (A1 - MARGIN):
            pa["m10"] = True
        else:
            if config_changed:
                pa["m10"] = False
        if remaining < (A2 - MARGIN):
            pa["m5"] = True
        else:
            if config_changed:
                pa["m5"] = False
        if remaining < A3:
            pa["m1"] = True
            pa["countdown_started"] = True

        # Guardar token de seed:
        state[SEED_KEY] = seed_token if mode == "manual" else int(now.timestamp())

        log.debug("Seed aplicado (cfg_changed=%s, mode=%s, remaining=%s)", config_changed, mode, remaining)

        # Ventana de gracia en el arranque (manual o por horario) y también al cambiar umbrales
        if abs(remaining - A1) <= GRACE_START and not pa["m10"]:
            pa["m10"] = True
            messages.append(f"⏳ Quedan {_fmt_span(A1)} de juego.")
            if origin == "guardian":
                log.info("Aviso1 (ventana %ss) por %s", GRACE_START, "inicio" if changed_session else "cambio umbrales")
            else:
                log.debug("Aviso1 (ventana %ss) por %s", GRACE_START, "inicio" if changed_session else "cambio umbrales")
                
        if abs(remaining - A2) <= GRACE_START and not pa["m5"]:
            pa["m5"] = True
            messages.append(f"⏳ Quedan {_fmt_span(A2)} de juego.")
            if origin == "guardian":
                log.info("Aviso2 (ventana %ss) por %s", GRACE_START, "inicio" if changed_session else "cambio umbrales")
            else:  
                log.debug("Aviso2 (ventana %ss) por %s", GRACE_START, "inicio" if changed_session else "cambio umbrales")

    log.debug("Tiempo restante=%s mode=%s flags=%s", remaining, mode, pa)

    # --- Disparos normales por cruce de umbral ---
    if remaining <= A1 and not pa["m10"]:
        pa["m10"] = True
        messages.append(f"⏳ Quedan {_fmt_span(A1)} de juego.")
        (log.info if origin == "guardian" else log.debug)("Emitido aviso1")

    if remaining <= A2 and not pa["m5"]:
        pa["m5"] = True
        messages.append(f"⏳ Quedan {_fmt_span(A2)} de juego.")
        (log.info if origin == "guardian" else log.debug)("Emitido aviso2")

    if remaining <= A3 and not pa["m1"]:
        pa["m1"] = True
        pa["countdown_started"] = True
        messages.append("⚠️ ¡Último minuto! Comienza la cuenta atrás.")
        (log.debug if origin == "guardian" else log.debug)("Último minuto: inicia cuenta atrás")

    # Cuenta atrás visible (0..60)
    if pa.get("countdown_started", False):
        countdown = int(max(0, min(60, remaining)))
        state["play_countdown"] = countdown
        log.debug("Cuenta atrás activa: %s s", countdown)
        return messages, countdown

    state["play_countdown"] = 0
    return messages, 0



# snapshot de solo lectura para la GUI
def alerts_snapshot(state: dict, now: datetime, cfg: Optional[dict] = None) -> dict:
    alerts = get_alerts_cfg(cfg)
    A1 = int(alerts.get("aviso1_sec", 600))
    A2 = int(alerts.get("aviso2_sec", 300))
    A3 = int(alerts.get("aviso3_sec", 60))

    rem, mode = remaining_play_seconds(state, now, cfg)
    snap = {
        "remaining": int(rem),
        "mode": mode,
        "m10": rem <= A1,
        "m5":  rem <= A2,
        "m1":  rem <= A3,
        "countdown": int(max(0, min(60, rem))) if rem <= A3 else 0,
    }
    return snap


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
