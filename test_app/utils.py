# xiao_gui/utils.py — utilidades varias y helpers de test
import sqlite3
import time
from pathlib import Path
from app.logs import get_logger

log = get_logger("gui.utils")

# Rutas principales
BASE_DIR = Path(__file__).resolve().parent.parent  # raíz del proyecto
DB_PATH = BASE_DIR / "guardian.db"
ASSETS = BASE_DIR / "assets"
ICON_APP = ASSETS / "app_icon.ico"
ICON_LOCK_PNG = ASSETS / "lock.png"

def log_block_event_for_test(app_name: str = "PruebaApp.exe") -> bool:
    """
    Inserta un evento 'block' en guardian.db para que el notifier lo muestre.
    Devuelve True si se insertó correctamente, False si hubo error.
    """
    ok = False
    con = None
    try:
        if not DB_PATH.exists():
            log.warning("Base de datos no encontrada: %s (se creará)", DB_PATH)
        con = sqlite3.connect(str(DB_PATH))
        cur = con.cursor()
        cur.execute(
            """CREATE TABLE IF NOT EXISTS events(
                id INTEGER PRIMARY KEY,
                ts INTEGER,
                type TEXT,
                value TEXT,
                meta TEXT
            )"""
        )
        ts = int(time.time())
        cur.execute(
            "INSERT INTO events(ts,type,value,meta) VALUES(?,?,?,?)",
            (ts, "block", app_name, "test"),
        )
        con.commit()
        ok = True
        log.info("Evento de prueba 'block' insertado: %s (ts=%d)", app_name, ts)
    except Exception as e:
        log.error("Error insertando evento de prueba en DB: %s", e, exc_info=True)
    finally:
        if con:
            try:
                con.close()
            except Exception:
                pass
    return ok


if __name__ == "__main__":
    # Pequeña prueba manual
    print("Insertando evento de prueba…")
    if log_block_event_for_test():
        print("OK — revisa notifier/log o interfaz.")
    else:
        print("Error — revisa playtime.log.")
