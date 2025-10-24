# storage.py — XiaoHack Parental
# Persistencia compartida (GUI/servicio/notifier) con IO atómica, fallback seguro y LOG centralizado.

from __future__ import annotations
import json
import os
import tempfile
import time
import threading
from pathlib import Path
from logs import get_logger

log = get_logger("storage")

# -----------------------------------------------------------------------------
# Selección de directorio de datos
# -----------------------------------------------------------------------------
def _get_data_dir() -> Path:
    """Devuelve la carpeta de datos preferida (ProgramData o AppData fallback)."""
    base = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "XiaoHackParental"
    try:
        base.mkdir(parents=True, exist_ok=True)
        test = base / ".write_test"
        test.write_text("ok", encoding="utf-8")
        test.unlink(missing_ok=True)
        log.debug("Usando directorio de datos principal: %s", base)
        return base
    except Exception as e:
        log.warning("Fallo en ProgramData (%s), usando AppData fallback", e)
        alt = Path(os.environ.get("APPDATA", str(Path.home()))) / "XiaoHackParental"
        alt.mkdir(parents=True, exist_ok=True)
        log.debug("Usando fallback de datos: %s", alt)
        return alt

DATA_DIR = _get_data_dir()
CONFIG_PATH = DATA_DIR / "config.json"
STATE_PATH  = DATA_DIR / "state.json"
DB_PATH     = DATA_DIR / "guardian.db"
LOGS_DIR    = DATA_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)

# Para migrar los ficheros antiguos (junto al código)
LEGACY_DIR = Path(__file__).resolve().parent

# -----------------------------------------------------------------------------
# Defaults
# -----------------------------------------------------------------------------
_DEFAULT_CFG = {
    "parent_password_hash": "",
    # No aplicar nada por defecto:
    "safesearch": False,
    "blocked_apps": [],
    "blocked_paths": [],
    "blocked_executables": [],
    "blocked_domains": [],              # <- vacío: no toca hosts/dns si se aplicara
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
    "apply_on_start": False
}

_DEFAULT_STATE = {
    "play_until": 0,
    "play_whitelist": [],
    # Flag para indicar si el usuario ya aprobó aplicar reglas a nivel sistema
    "applied": False
}

def now_epoch() -> int:
    return int(time.time())

# -----------------------------------------------------------------------------
# IO atómica y thread-safe
# -----------------------------------------------------------------------------
_LOCK = threading.Lock()

def _atomic_write(path: Path, data: dict):
    """Escritura atómica con lock, flush y replace seguro."""
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
            tmp_path.unlink(missing_ok=True)
            raise
        finally:
            tmp_path.unlink(missing_ok=True)

def _read_json(path: Path, defaults: dict) -> dict:
    """Lee JSON; si no existe o hay error, lo crea con defaults y devuelve una copia."""
    try:
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                log.debug("Leído correctamente %s", path)
                return data
        else:
            log.info("Archivo no encontrado (%s). Creando con defaults (NO-OP).", path)
            _atomic_write(path, defaults)
            return defaults.copy()
    except Exception as e:
        log.warning("Error al leer %s: %s (recreando con defaults)", path, e, exc_info=True)
        _atomic_write(path, defaults)
        return defaults.copy()

# -----------------------------------------------------------------------------
# Migración inicial (una sola vez)
# -----------------------------------------------------------------------------
def _migrate_if_needed():
    legacy_cfg = LEGACY_DIR / "config.json"
    legacy_st  = LEGACY_DIR / "state.json"
    try:
        if legacy_cfg.exists() and not CONFIG_PATH.exists():
            CONFIG_PATH.write_text(legacy_cfg.read_text(encoding="utf-8"), encoding="utf-8")
            log.info("Migrado config.json desde directorio legacy")
        if legacy_st.exists() and not STATE_PATH.exists():
            STATE_PATH.write_text(legacy_st.read_text(encoding="utf-8"), encoding="utf-8")
            log.info("Migrado state.json desde directorio legacy")
    except Exception as e:
        log.error("Error en migración inicial: %s", e, exc_info=True)

def _ensure_present():
    """Crea config/state con defaults NO-OP si faltan (evita aplicar nada al instalar)."""
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

# -----------------------------------------------------------------------------
# API pública
# -----------------------------------------------------------------------------
def load_config() -> dict:
    cfg = _read_json(CONFIG_PATH, _DEFAULT_CFG)
    # Normalización básica
    for k in ("blocked_apps","blocked_executables","blocked_paths","game_whitelist","blocked_domains"):
        cfg[k] = [x for x in cfg.get(k, []) if x]
    # Asegurar flags presentes
    cfg.setdefault("safesearch", False)
    cfg.setdefault("apply_on_start", False)
    return cfg

def save_config(cfg: dict):
    log.debug("Guardando configuración (%s entradas)", len(cfg))
    _atomic_write(CONFIG_PATH, cfg)

def load_state() -> dict:
    log.debug("Cargando estado desde %s", STATE_PATH)
    st = _read_json(STATE_PATH, _DEFAULT_STATE)
    st.setdefault("applied", False)
    return st

def save_state(st: dict):
    log.debug("Guardando estado (%s claves)", len(st))
    _atomic_write(STATE_PATH, st)

# -----------------------------------------------------------------------------
# Log resumen de entorno
# -----------------------------------------------------------------------------
log.info("Directorio de datos: %s", DATA_DIR)
log.info("Archivos: config=%s, state=%s, db=%s", CONFIG_PATH, STATE_PATH, DB_PATH)
