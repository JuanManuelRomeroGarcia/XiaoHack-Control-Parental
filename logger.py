# logger.py — XiaoHack Parental (Audit Logger con integración de logs)
import sqlite3
import os
import time
import threading
from logs import get_logger

log = get_logger("audit")

DB = os.path.join(os.path.dirname(__file__), "guardian.db")
_LOCK = threading.Lock()

class AuditLogger:
    """
    AuditLogger — registra eventos en guardian.db (tabla 'events')
    Compatible con log_block / log_seen antiguos.
    """

    def __init__(self, db_path: str = DB):
        self.db_path = db_path
        self._ensure_db()

    # ------------------------------
    # Inicialización
    # ------------------------------
    def _ensure_db(self):
        """Crea la tabla events si no existe."""
        try:
            with _LOCK:
                con = sqlite3.connect(self.db_path)
                cur = con.cursor()
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS events(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts INTEGER NOT NULL,
                        type TEXT NOT NULL,
                        value TEXT,
                        meta TEXT
                    )
                """)
                con.commit()
                con.close()
                log.debug("Audit DB lista: %s", self.db_path)
        except Exception as e:
            log.error("Error inicializando guardian.db: %s", e, exc_info=True)

    # ------------------------------
    # Inserción de eventos
    # ------------------------------
    def _insert(self, event_type: str, value: str = "", meta: str = ""):
        """Inserta un evento en la base de datos."""
        ts = int(time.time())
        try:
            with _LOCK:
                con = sqlite3.connect(self.db_path, timeout=5)
                con.execute(
                    "INSERT INTO events(ts,type,value,meta) VALUES(?,?,?,?)",
                    (ts, event_type, value, meta),
                )
                con.commit()
                con.close()
                log.debug("Evento registrado: %s | %s | %s", event_type, value, meta)
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
                con = sqlite3.connect(self.db_path)
                cur = con.cursor()
                cur.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
                count = cur.rowcount
                con.commit()
                con.close()
                if count > 0:
                    log.info("Purgados %d eventos antiguos (> %d días)", count, max_age_days)
        except Exception as e:
            log.error("Error purgando eventos antiguos: %s", e, exc_info=True)
