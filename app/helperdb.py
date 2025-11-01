# app/helperdb.py
from __future__ import annotations
import contextlib
import sqlite3
import threading
from pathlib import Path
from datetime import datetime, time

# Usamos la misma ruta que storage
from .storage import DB_PATH

# Un solo lock de proceso para serializar escrituras (SQLite maneja multi-proceso con BEGIN IMMEDIATE)
_WRITE_LOCK = threading.Lock()


def _now_local_str() -> str:
    # Ej: "2025-10-30 14:39:00"
    return datetime.now().strftime("%d-%m-%Y %H:%M:%S")

def _db_path_str() -> str:
    return str(Path(DB_PATH))

def _open_rw():
    """
    Conexión lectura/escritura con WAL y cache compartida.
    check_same_thread=False para poder usar desde hilos.
    """
    uri = f"file:{_db_path_str()}?cache=shared"
    con = sqlite3.connect(uri, timeout=15, check_same_thread=False, uri=True)
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA synchronous=NORMAL;")
    con.execute("PRAGMA temp_store=MEMORY;")
    con.execute("PRAGMA busy_timeout=10000;")
    return con

def _open_ro():
    """
    Conexión solo-lectura, sin bloquear escritor.
    """
    uri = f"file:{_db_path_str()}?mode=ro&cache=shared"
    con = sqlite3.connect(uri, timeout=5, check_same_thread=False, uri=True)
    con.execute("PRAGMA query_only=ON;")
    con.execute("PRAGMA temp_store=MEMORY;")
    con.execute("PRAGMA busy_timeout=5000;")
    return con

def _ensure_schema(con: sqlite3.Connection):
    """
    Crea/actualiza el esquema:
    - events.ts pasa a TEXT (hora local 'YYYY-MM-DD HH:MM:SS')
    - migra datos antiguos (INTEGER epoch -> localtime string)
    - índice por (type,id)
    - vista 'events_human' simple (muestra ts tal cual)
    """
    # ¿Existe la tabla?
    cur = con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='events'")
    has_events = cur.fetchone() is not None

    if not has_events:
        # Crear directamente con ts TEXT (local)
        con.execute("""
            CREATE TABLE events(
                id INTEGER PRIMARY KEY,
                ts TEXT,
                type TEXT,
                value TEXT,
                meta TEXT
            )
        """)
    else:
        # Detectar tipo de columna ts
        cols = con.execute("PRAGMA table_info('events')").fetchall()
        colmap = {c[1]: c for c in cols}  # name -> row
        ts_decl = (colmap.get("ts", [None, None, ""])[2] or "").upper()

        # Si la tabla antigua tenía ts INTEGER (epoch), migrar a TEXT local
        if "INT" in ts_decl:
            con.execute("BEGIN IMMEDIATE")
            try:
                con.execute("""
                    CREATE TABLE events_new(
                        id INTEGER PRIMARY KEY,
                        ts TEXT,
                        type TEXT,
                        value TEXT,
                        meta TEXT
                    )
                """)
                # Convertimos epoch -> localtime string en la INSERT
                con.execute("""
                    INSERT INTO events_new(id, ts, type, value, meta)
                    SELECT id,
                           datetime(ts,'unixepoch','localtime') AS ts_local,
                           type, value, meta
                    FROM events
                """)
                con.execute("DROP TABLE events")
                con.execute("ALTER TABLE events_new RENAME TO events")
                con.execute("COMMIT")
            except Exception:
                con.execute("ROLLBACK")
                raise

    # Índice (idemp.)
    con.execute("CREATE INDEX IF NOT EXISTS idx_events_type_id ON events(type, id)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_events_type_ts ON events(type, ts DESC)")

    # Vista humana: ahora ts ya está en local y es TEXT, no hace falta convertir
    con.execute("DROP VIEW IF EXISTS events_human")
    con.execute("""
        CREATE VIEW IF NOT EXISTS events_human AS
        SELECT id, ts, type, value, meta
        FROM events
    """)

def log_event(kind: str, value: str, meta: str = "") -> None:
    con = None
    try:
        con = _open_rw()
        _ensure_schema(con)
        ts_local = _now_local_str()
        con.execute(
            "INSERT INTO events(ts, type, value, meta) VALUES (?,?,?,?)",
            (ts_local, kind, value, meta)
        )
        con.commit()
    except Exception:
        if con is not None:
            with contextlib.suppress(Exception):
                con.rollback()
        raise
    finally:
        if con is not None:
            with contextlib.suppress(Exception):
                con.close()
                    
def fetch_events_since(kind: str, last_id: int, limit: int = 500) -> list[tuple[int,str,str,str]]:
    """
    Devuelve [(id, ts_local(TEXT), value, meta), ...] posteriores a last_id.
    """
    con = None
    try:
        con = _open_ro()
        cur = con.execute(
            "SELECT id, ts, value, meta FROM events WHERE type=? AND id>? ORDER BY id ASC LIMIT ?",
            (kind, int(last_id), int(limit))
        )
        return list(cur.fetchall())
    except sqlite3.OperationalError as e:
        if "no such table" in str(e).lower():
            return []
        raise
    finally:
        if con is not None:
            with contextlib.suppress(Exception):
                con.close()

# helperdb.py

# Límite de deduplicación (segundos). Ajusta si quieres 1–3 s.
_DEDUP_WINDOW = 2

def add_event_dedup(conn: sqlite3.Connection, ev_type: str, title: str, body: str, meta: str = "", key: str = "") -> int:
    """
    Inserta un evento pero evita duplicados muy recientes por 'key' (y título/cuerpo).
    Devuelve el id del evento insertado (o el existente si dedupea).
    """
    now_ts = int(time.time())  # ya estás guardando en hora local en otras funciones, si prefieres usa tu helper localtime

    cur = conn.cursor()
    try:
        if key:
            # ¿Hay un evento igual en la ventana de dedupe?
            cur.execute(
                "SELECT id FROM events WHERE key=? AND title=? AND body=? AND (ts >= ?) ORDER BY id DESC LIMIT 1",
                (key, title, body, now_ts - _DEDUP_WINDOW),
            )
            row = cur.fetchone()
            if row:
                return row[0]

        cur.execute(
            "INSERT INTO events (ts, type, title, body, meta, key) VALUES (?, ?, ?, ?, ?, ?)",
            (now_ts, ev_type, title, body, meta or "", key or "")
        )
        conn.commit()
        return cur.lastrowid
    finally:
        cur.close()
