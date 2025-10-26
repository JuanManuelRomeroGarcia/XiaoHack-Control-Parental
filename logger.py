# logger.py — XiaoHack Parental (Audit Logger con integración de logs + DB en ProgramData)
from __future__ import annotations
import sqlite3
import time
import threading
from pathlib import Path

from logs import get_logger
from storage import DB_PATH  # <- guardian.db ubicado en ProgramData/LocalAppData según rol

log = get_logger("audit")

# DB en ProgramData (o LocalAppData si no es SYSTEM/guardian)
DB_FILE = Path(DB_PATH)

# Lock a nivel de hilo (SQLite coordina entre procesos)
_LOCK = threading.Lock()

# -----------------------------------------------------------------------------
# Utilidades de conexión
# -----------------------------------------------------------------------------
def _connect(db_path: Path) -> sqlite3.Connection:
    """
    Conexión con pragmas para concurrencia y durabilidad razonable:
      - WAL: mejores lecturas concurrentes (notifier + guardian)
      - synchronous=NORMAL: buen equilibrio I/O/seguridad
      - temp_store=MEMORY: menos disco para tmp
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(
        str(db_path),
        timeout=10.0,               # espera razonable si otro proceso escribe
        check_same_thread=False,    # por si usamos desde varios hilos
        isolation_level=None,       # modo autocommit; commits explícitos cuando interesa
    )
    try:
        cur = con.cursor()
        cur.execute("PRAGMA journal_mode=WAL;")
        cur.execute("PRAGMA synchronous=NORMAL;")
        cur.execute("PRAGMA temp_store=MEMORY;")
        cur.execute("PRAGMA foreign_keys=ON;")
        con.commit()
    except Exception:
        # No pasa nada si algún PRAGMA falla por versión
        pass
    return con

def _ensure_db_schema():
    try:
        with _LOCK:
            con = _connect(DB_FILE)
            cur = con.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS events(
                    id    INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts    INTEGER NOT NULL,
                    type  TEXT    NOT NULL,
                    value TEXT,
                    meta  TEXT
                );
            """)
            # Índices útiles para consultas por tiempo y tipo
            cur.execute("CREATE INDEX IF NOT EXISTS ix_events_ts   ON events(ts);")
            cur.execute("CREATE INDEX IF NOT EXISTS ix_events_type ON events(type);")
            con.commit()
            con.close()
            log.debug("Audit DB lista: %s", DB_FILE)
    except Exception as e:
        log.error("Error inicializando guardian.db: %s", e, exc_info=True)

_ensure_db_schema()

# -----------------------------------------------------------------------------
# AuditLogger
# -----------------------------------------------------------------------------
class AuditLogger:
    """
    AuditLogger — registra eventos en guardian.db (tabla 'events')
    Compatible con log_block / log_seen antiguos.
    """

    def __init__(self, db_path: str | Path = DB_FILE):
        self.db_path = Path(db_path)
        _ensure_db_schema()

    # ------------------------------
    # Inserción de eventos
    # ------------------------------
    def _insert(self, event_type: str, value: str = "", meta: str = ""):
        ts = int(time.time())
        try:
            with _LOCK:
                con = _connect(self.db_path)
                cur = con.cursor()
                cur.execute(
                    "INSERT INTO events(ts,type,value,meta) VALUES(?,?,?,?)",
                    (ts, event_type, value, meta),
                )
                con.commit()
                con.close()
                log.debug("Evento registrado: %s | %s | %s", event_type, value, meta)
        except sqlite3.OperationalError as e:
            # Picos de lock: registramos warning, pero no reventamos el flujo del guardian
            log.warning("SQLite ocupado al registrar '%s': %s", event_type, e)
        except Exception as e:
            log.error("Error al registrar evento '%s': %s", event_type, e, exc_info=True)

    # ------------------------------
    # Métodos públicos
    # ------------------------------
    def log_block(self, name: str, reason: str = ""):
        """Registrar un bloqueo (app, carpeta, dominio, etc.)"""
        self._insert("block", name, reason)

    def log_seen(self, name: str):
        """Registrar un elemento 'visto' (ejecución, ventana, etc.)"""
        self._insert("seen", name, "")

    def log_info(self, message: str, meta: str = ""):
        """Registrar información genérica."""
        self._insert("info", message, meta)

    def log_error(self, message: str, meta: str = ""):
        """Registrar un error o advertencia."""
        self._insert("error", message, meta)

    def purge_old(self, max_age_days: int = 30):
        """Eliminar eventos más antiguos que max_age_days (mantenimiento)."""
        cutoff = int(time.time()) - (max_age_days * 86400)
        try:
            with _LOCK:
                con = _connect(self.db_path)
                cur = con.cursor()
                cur.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
                con.commit()
                # SQLite no actualiza tamaño del archivo hasta VACUUM;
                # no lo hacemos automáticamente para evitar bloquear procesos.
                con.close()
                log.info("Purgados eventos anteriores a %d días", max_age_days)
        except sqlite3.OperationalError as e:
            log.warning("SQLite ocupado durante purge_old: %s", e)
        except Exception as e:
            log.error("Error purgando eventos antiguos: %s", e, exc_info=True)
