# storage.py — XiaoHack Parental
# Persistencia compartida (GUI/servicio/notifier) con IO atómica, fallback seguro
# y LOG/rutas centralizados (ProgramFiles + ProgramData/LocalAppData compliant)

from __future__ import annotations
import json
import os
import copy
import tempfile
import time
import threading
from pathlib import Path
from typing import Dict, Union

# Importamos utilidades del logger central para unificar el "data dir"
from app.logs import (
    get_logger,
    get_data_dir as _logs_get_data_dir,
    set_data_dir as _logs_set_data_dir,  # noqa: F401
)

# ========= APLICAR OVERRIDE TEMPRANO (si viene de los .bat) ====================
# Esto asegura que el logger ya se inicialice apuntando al DATA_DIR correcto.
try:
    _XH_ENV = os.getenv("XH_DATA_DIR")
    if _XH_ENV:
        _logs_set_data_dir(_XH_ENV)
except Exception:
    # No impedimos el arranque si falla el override del entorno
    pass

log = get_logger("storage")

# ==============================================================================
# Selección de directorio de datos (fuente única: logs.get_data_dir)
# ==============================================================================
def _get_data_dir() -> Path:
    """
    Devuelve la carpeta de datos activa de la app.
    Corrige el caso en que por error llegue ...\XiaoHackParental\logs.
    """
    base = Path(_logs_get_data_dir())
    # ⚠️ Autocorrección si alguien pasó el directorio de LOGS por error
    if base.name.lower() == "logs":
        base = base.parent
    try:
        base.mkdir(parents=True, exist_ok=True)
        test = base / ".write_test"
        test.write_text("ok", encoding="utf-8")
        test.unlink(missing_ok=True)
        log.debug("Usando directorio de datos: %s", base)
        return base
    except Exception as e:
        log.warning("No se pudo asegurar escritura en %s (%s). Usando cwd/.xh_data", base, e)
        alt = Path.cwd() / ".xh_data"
        alt.mkdir(parents=True, exist_ok=True)
        return alt



DATA_DIR = _get_data_dir()
CONFIG_PATH = DATA_DIR / "config.json"
STATE_PATH  = DATA_DIR / "state.json"
DB_PATH     = DATA_DIR / "guardian.db"
LOGS_DIR    = DATA_DIR / "logs"
try:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    pass

# Posibles rutas legacy (versiones antiguas que guardaban junto al código)
LEGACY_DIRS = [
    # Junto al archivo actual (instalaciones antiguas en la carpeta del programa)
    Path(__file__).resolve().parent,
    (Path(_logs_get_data_dir()) / "..").resolve(), # Por si el data dir estaba mal apuntando a logs
    # AppData clásico (por si existiera de builds previas)
    Path(os.environ.get("APPDATA", str(Path.home()))) / "XiaoHackParental",
]

# ==============================================================================
# Defaults
# ==============================================================================
_DEFAULT_STATE: Dict = {
    "play_until": 0,
    "play_whitelist": [],
    # Flag para indicar si el usuario ya aprobó aplicar reglas a nivel sistema
    "applied": False,
}

# --- Defaults de alertas (configurables) ---
_DEFAULT_ALERTS_CFG = {
    "aviso1_sec": 600,        # antes "10 min"
    "aviso2_sec": 300,        # antes "5 min"
    "aviso3_sec": 60,         # último minuto (fijo por diseño)
    "flash_ttl": 7,           # duración de banner de aviso (segundos)
    "close_banner_ttl": 10,   # duración de "Cerrando juegos y aplicaciones"
}


_DEFAULT_CFG: Dict = {
    "parent_password_hash": "",
    # Por defecto NO aplicar nada:
    "safesearch": False,
    "blocked_apps": [],
    "blocked_paths": [],
    "blocked_executables": [],
    "blocked_domains": [],              # vacío -> no tocar hosts/dns hasta que el usuario lo habilite
    "game_whitelist": [],
    "schedules": [
        {"days": ["mon","tue","wed","thu","fri"], "from": "12:00", "to": "13:00"},
        {"days": ["mon","tue","wed","thu","fri"], "from": "18:00", "to": "19:00"},
        {"days": ["sat","sun"], "from": "12:00", "to": "13:00"},
        {"days": ["sat","sun"], "from": "18:00", "to": "19:00"}
    ],
    "strict_mode_after": "22:00",
    "log_process_activity": False,
    # Flag opcional por si la app quiere control explícito:
    "apply_on_start": False,
    "overlay": { "mode": "banner|fullscreen", "position": "top|bottom",
                   "height": 160, "opacity": 0.92 },
    "alerts": _DEFAULT_ALERTS_CFG.copy(),
}


def now_epoch() -> int:
    return int(time.time())

# ==============================================================================
# IO atómica y thread-safe
# ==============================================================================
_LOCK = threading.Lock()

def _atomic_write(path: Path, data: dict):
    """Escritura atómica con lock, flush y replace seguro (NTFS)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_name = tempfile.mkstemp(prefix=path.name, dir=str(path.parent))
    tmp_path = Path(tmp_name)
    with _LOCK:
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, path)  # atómico en NTFS
            log.debug("Archivo guardado correctamente: %s", path)
        except Exception as e:
            log.error("Error al escribir %s: %s", path, e, exc_info=True)
            try:
                tmp_path.unlink(missing_ok=True)
            except Exception:
                pass
            raise
        finally:
            try:
                tmp_path.unlink(missing_ok=True)
            except Exception:
                pass

def _read_json(path: Path, default: Dict | list | None = None):
    """
    Lee JSON con tolerancia a bloqueos (PermissionError) y escrituras en curso.
    - 8 reintentos con backoff.
    - Si falla, intenta .bak y devuelve default.
    """
    default = {} if default is None else default
    for i in range(8):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except PermissionError:
            # Archivo momentáneamente bloqueado por otro proceso: reintenta
            time.sleep(0.04 * (i + 1))
            continue
        except json.JSONDecodeError:
            # Posible escritura a medio volcar: reintenta
            time.sleep(0.04 * (i + 1))
            continue
        except FileNotFoundError:
            break
        except Exception as e:
            log.warning("Error al leer %s: %s", path, e)
            break

    # Fallback a copia si la usas al guardar (opcional)
    bak = path.with_suffix(path.suffix + ".bak")
    if bak.exists():
        try:
            with open(bak, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass

    # Último recurso
    log.warning("Devolviendo default para %s (no se pudo leer de forma segura).", path)
    return copy.deepcopy(default)


# ==============================================================================
# Migración inicial (una sola vez)
# ==============================================================================
def _migrate_if_needed():
    """
    Si no existen config/state en DATA_DIR, intenta migrar desde ubicaciones legacy:
      - Directorio del código (instalaciones antiguas).
      - %AppData%\XiaoHackParental (builds previas).
    """
    try:
        migrated = False
        for legacy in LEGACY_DIRS:
            legacy_cfg = legacy / "config.json"
            legacy_st  = legacy / "state.json"

            if legacy_cfg.exists() and not CONFIG_PATH.exists():
                CONFIG_PATH.write_text(legacy_cfg.read_text(encoding="utf-8"), encoding="utf-8")
                log.info("Migrado config.json desde: %s", legacy_cfg)
                migrated = True

            if legacy_st.exists() and not STATE_PATH.exists():
                STATE_PATH.write_text(legacy_st.read_text(encoding="utf-8"), encoding="utf-8")
                log.info("Migrado state.json desde: %s", legacy_st)
                migrated = True

            if migrated:
                break
    except Exception as e:
        log.error("Error en migración inicial: %s", e, exc_info=True)

def _ensure_present():
    """
    Crea config/state con defaults NO-OP si faltan (evita aplicar nada al instalar).
    """
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        if not CONFIG_PATH.exists():
            _atomic_write(CONFIG_PATH, _DEFAULT_CFG)
            log.info("Creado config.json con defaults NO-OP (safesearch=False, blocked_domains=[])")
        if not STATE_PATH.exists():
            _atomic_write(STATE_PATH, _DEFAULT_STATE)
            log.info("Creado state.json con defaults (applied=False)")
    except Exception as e:
        log.error("Error creando ficheros iniciales: %s", e, exc_info=True)

_migrate_if_needed()
_ensure_present()

# ==============================================================================
# API pública
# ==============================================================================
def load_config() -> dict:
    cfg = _read_json(CONFIG_PATH, _DEFAULT_CFG)

    # Normalización de listas
    for k in ("blocked_apps","blocked_executables","blocked_paths","game_whitelist","blocked_domains"):
        xs = cfg.get(k, [])
        if not isinstance(xs, list):
            xs = []
        cfg[k] = [x for x in xs if isinstance(x, str) and x.strip()]

    # Booleanos
    cfg["safesearch"] = bool(cfg.get("safesearch", False))
    cfg["apply_on_start"] = bool(cfg.get("apply_on_start", False))
    cfg["log_process_activity"] = bool(cfg.get("log_process_activity", False))

    # Schedules: lista segura
    sch = cfg.get("schedules", [])
    if not isinstance(sch, list):
        sch = []
    cfg["schedules"] = sch

    # Normalización de dominios (limpia http(s):// y slashes)
    cfg["blocked_domains"] = _norm_domain_list(cfg.get("blocked_domains", []))
    
    # Alerts (umbrales y TTLs)
    cfg["alerts"] = _norm_alerts_cfg(cfg.get("alerts", {}))
    
    return cfg


def save_config(cfg: dict):
    log.debug("Guardando configuración (%s entradas)", len(cfg))
    _atomic_write(CONFIG_PATH, cfg)

def load_state() -> dict:
    log.debug("Cargando estado desde %s", STATE_PATH)
    st = _read_json(STATE_PATH, _DEFAULT_STATE)
    st.setdefault("applied", False)
    st.setdefault("play_until", st.get("play_until", 0))
    st.setdefault("play_whitelist", st.get("play_whitelist", []))
    pa = st.get("play_alerts")
    if not isinstance(pa, dict):
        pa = {}
    pa.setdefault("enabled", True)
    pa.setdefault("m10", False)
    pa.setdefault("m5", False)
    pa.setdefault("m1", False)
    pa.setdefault("countdown_started", False)
    st["play_alerts"] = pa
    
    return st

def save_state(st: dict):
    log.debug("Guardando estado (%s claves)", len(st))
    _atomic_write(STATE_PATH, st)
    
def get_alerts_cfg(cfg: dict | None = None) -> dict:
    """
    Devuelve los valores efectivos de alertas desde config.json,
    con defaults y normalización aplicados.
    """
    if cfg is None:
        cfg = load_config()
    return _norm_alerts_cfg(cfg.get("alerts", {}))

def update_alerts_cfg(mutator_or_dict) -> dict:
    """
    Actualiza solo la sección 'alerts' en config.json.
    - Si pasas un dict, se fusiona y normaliza.
    - Si pasas un callable, recibe el dict actual de alerts y debe mutarlo
      o devolver uno nuevo. Luego se guarda.
    Devuelve el alerts final persistido.
    """
    def _mut(cfg: dict):
        curr = _norm_alerts_cfg(cfg.get("alerts", {}))
        if callable(mutator_or_dict):
            ret = mutator_or_dict(curr) or curr
            cfg["alerts"] = _norm_alerts_cfg(ret)
        else:
            # fusión superficial
            merged = dict(curr)
            merged.update(mutator_or_dict or {})
            cfg["alerts"] = _norm_alerts_cfg(merged)
        return cfg

    cfg = update_config(_mut)
    return _norm_alerts_cfg(cfg.get("alerts", {}))


# --- Normalizadores (para uso común en GUI/servicios) ---
def _norm_list(xs):
    return [x for x in (xs or []) if isinstance(x, str) and x.strip()]

def _norm_domain_list(xs):
    out = []
    for x in _norm_list(xs):
        x = x.strip().lower()
        # quitar http(s):// y trailing slashes si vinieran del UI
        if x.startswith("http://"):
            x = x[7:]
        if x.startswith("https://"):
            x = x[8:]
        x = x.strip("/ ")
        if x:
            out.append(x)
    return out

def _parse_time_value(v, default: int) -> int:
    """
    Acepta int/float directamente (segundos) o str tipo "10m", "300s", "10".
    Devuelve un entero >= 0; si no es válido, retorna default.
    """
    try:
        if isinstance(v, (int, float)):
            n = int(v)
            return max(0, n)
        if isinstance(v, str):
            s = v.strip().lower()
            if s.endswith("m"):
                return max(0, int(float(s[:-1]) * 60))
            if s.endswith("s"):
                return max(0, int(float(s[:-1])))
            return max(0, int(float(s)))
    except Exception:
        pass
    return int(default)

def _norm_alerts_cfg(alerts: dict | None) -> dict:
    """
    Devuelve un dict completo y consistente con claves:
      aviso1_sec, aviso2_sec, aviso3_sec, flash_ttl, close_banner_ttl
    - Forzamos aviso3 a 60 s (último minuto) por diseño.
    - Garantizamos orden lógico: aviso1_sec >= aviso2_sec >= 60.
    - Clampeamos a rangos razonables.
    """
    a = dict(_DEFAULT_ALERTS_CFG)
    if isinstance(alerts, dict):
        a["aviso1_sec"]       = _parse_time_value(alerts.get("aviso1_sec", a["aviso1_sec"]), a["aviso1_sec"])
        a["aviso2_sec"]       = _parse_time_value(alerts.get("aviso2_sec", a["aviso2_sec"]), a["aviso2_sec"])
        a["flash_ttl"]        = _parse_time_value(alerts.get("flash_ttl", a["flash_ttl"]), a["flash_ttl"])
        a["close_banner_ttl"] = _parse_time_value(alerts.get("close_banner_ttl", a["close_banner_ttl"]), a["close_banner_ttl"])
        # Si alguien configuró aviso3, lo ignoramos: es fijo (último minuto).
        # Aun así, parseamos por cortesía y luego forzamos:
        _ = _parse_time_value(alerts.get("aviso3_sec", a["aviso3_sec"]), a["aviso3_sec"])

    # Forzar último minuto fijo
    a["aviso3_sec"] = 60

    # Clampeos razonables
    # - avisos entre 60 s y 24 h (por si alguien quiere avisos raros),
    # - ttl entre 1 y 60 s
    a["aviso1_sec"] = min(max(a["aviso1_sec"], 60), 24*3600)
    a["aviso2_sec"] = min(max(a["aviso2_sec"], 60), 24*3600)
    a["flash_ttl"]  = min(max(a["flash_ttl"], 1), 60)
    a["close_banner_ttl"] = min(max(a["close_banner_ttl"], 1), 60)

    # Orden lógico: aviso1 ≥ aviso2 ≥ 60
    if a["aviso2_sec"] > a["aviso1_sec"]:
        a["aviso2_sec"] = a["aviso1_sec"]
    if a["aviso2_sec"] < 60:
        a["aviso2_sec"] = 60

    return a


# --- Updates transaccionales (evitan carreras entre hilos) ---
def update_config(mutator):
    """
    Carga cfg -> mutator(cfg) -> guarda.
    'mutator' puede modificar in-place o devolver un dict nuevo.
    """
    cfg = load_config()
    ret = mutator(cfg)
    if isinstance(ret, dict):
        cfg = ret
    # normalización mínima estándar
    for k in ("blocked_apps","blocked_executables","blocked_paths","game_whitelist"):
        cfg[k] = _norm_list(cfg.get(k, []))
    cfg["blocked_domains"] = _norm_domain_list(cfg.get("blocked_domains", []))
    save_config(cfg)
    return cfg

def update_state(mutator):
    st = load_state()
    ret = mutator(st)
    if isinstance(ret, dict):
        st = ret
    save_state(st)
    return st

# Utilidades opcionales (para tests o herramientas)
def data_dir() -> str:
    """Ruta del directorio de datos activo."""
    return str(DATA_DIR)

def set_data_dir_forced(path: Union[str, os.PathLike[str], Path]) -> None:
    """
    Fuerza el data_dir para esta sesión (tests/arranques controlados).
    También ajusta el de logs para mantener coherencia.
    """
    global DATA_DIR, CONFIG_PATH, STATE_PATH, DB_PATH, LOGS_DIR
    p_str = str(path)
    _logs_set_data_dir(p_str)
    DATA_DIR = _get_data_dir()
    CONFIG_PATH = DATA_DIR / "config.json"
    STATE_PATH  = DATA_DIR / "state.json"
    DB_PATH     = DATA_DIR / "guardian.db"
    LOGS_DIR    = DATA_DIR / "logs"
    try:
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    log.info("Data dir forzado a: %s", DATA_DIR)

# --- Path getters (reutilizables) ---
def get_config_path() -> Path:
    return CONFIG_PATH

def get_state_path() -> Path:
    return STATE_PATH

def get_db_path() -> Path:
    return DB_PATH

def get_logs_dir_path() -> Path:
    return LOGS_DIR

def get_config_mtime() -> float:
    try:
        return CONFIG_PATH.stat().st_mtime
    except FileNotFoundError:
        return 0.0

def get_state_mtime() -> float:
    try:
        return STATE_PATH.stat().st_mtime
    except FileNotFoundError:
        return 0.0

# ==============================================================================
# Log resumen de entorno
# ==============================================================================
log.info("Directorio de datos: %s", DATA_DIR)
log.info("Archivos: config=%s, state=%s, db=%s", CONFIG_PATH, STATE_PATH, DB_PATH)
