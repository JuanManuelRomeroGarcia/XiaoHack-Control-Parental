# logs.py — Logger centralizado XiaoHack (ProgramFiles + ProgramData/LocalAppData compliant)
from __future__ import annotations
import logging
from logging.handlers import RotatingFileHandler
import os
import sys
import time
import threading
import traceback
from contextlib import contextmanager
from typing import Optional, Dict, Union
from pathlib import Path

# ==============================================================================
# Config base y estado global
# ==============================================================================
APP_VENDOR = "XiaoHackParental"
_DEFAULT_MAX_BYTES = 1_048_576  # 1 MiB
_DEFAULT_BACKUP_COUNT = 5

_LOGGERS: Dict[str, logging.Logger] = {}
_LOG_FILE: Optional[str] = None
_LOG_LEVEL = logging.INFO
_HANDLER: Optional[logging.Handler] = None
_CONSOLE_HANDLER: Optional[logging.Handler] = None
_INITIALIZED = False

# Si se llama set_data_dir(), se guarda aquí para forzar rutas
_OVERRIDE_DATA_DIR: Optional[Path] = None


# ==============================================================================
# Resolución robusta de rutas (SYSTEM vs usuario)
# ==============================================================================
def _is_system_account() -> bool:
    """
    Devuelve True si el proceso parece estar corriendo como cuenta SYSTEM
    (tareas programadas / servicios). En Windows USERNAME suele ser 'SYSTEM'.
    """
    user = (os.getenv("USERNAME") or "").strip().upper()
    if user == "SYSTEM":
        return True
    # pista adicional: muchas tareas de servicio tienen SESSIONNAME=Services
    sess = (os.getenv("SESSIONNAME") or "").strip().upper()
    return sess == "SERVICES"


def _get_env_flag(name: str) -> bool:
    val = (os.getenv(name) or "").strip().lower()
    return val in ("1", "true", "yes", "on")


def _resolve_data_dir() -> Path:
    r"""
    Determina el directorio base de datos/logs para la app.
    Prioridad:
      0) _OVERRIDE_DATA_DIR (si se llamó set_data_dir)
      1) ENV XH_DATA_DIR
      2) Si XH_ROLE=guardian o cuenta SYSTEM -> %ProgramData%\XiaoHackParental
      3) Usuario: %LOCALAPPDATA%\XiaoHackParental  (fallback: %APPDATA%)
      4) Último recurso: .\.xh_data
    """
    # 0) Override manual
    if _OVERRIDE_DATA_DIR:
        return _OVERRIDE_DATA_DIR

    # 1) ENV forzado
    env_dir = os.getenv("XH_DATA_DIR")
    if env_dir:
        p = Path(env_dir).expanduser()
        try:
            p.mkdir(parents=True, exist_ok=True)
            return p
        except Exception:
            pass  # caer a siguientes

    # 2) Guardian / SYSTEM
    role = (os.getenv("XH_ROLE") or "").strip().lower()
    if role == "guardian" or _is_system_account():
        programdata = os.getenv("PROGRAMDATA")
        if programdata:
            base = Path(programdata) / APP_VENDOR
            try:
                base.mkdir(parents=True, exist_ok=True)
                return base
            except Exception:
                pass
    
    # >>> NUEVO BLOQUE: preferir ProgramData si existe la instalación <<<
    programdata = os.getenv("PROGRAMDATA")
    if programdata:
        pd_base = Path(programdata) / APP_VENDOR
        # Si ya existe (instalación hecha) o hay ficheros clave, usarlo siempre
        if pd_base.exists() or (pd_base / "installed.json").exists() or (pd_base / "guardian.db").exists():
            try:
                pd_base.mkdir(parents=True, exist_ok=True)
                return pd_base
            except Exception:
                pass


    # 3) Usuario normal
    local_appdata = os.getenv("LOCALAPPDATA")
    if local_appdata:
        base = Path(local_appdata) / APP_VENDOR
        try:
            base.mkdir(parents=True, exist_ok=True)
            return base
        except Exception:
            pass

    appdata = os.getenv("APPDATA")
    if appdata:
        base = Path(appdata) / APP_VENDOR
        try:
            base.mkdir(parents=True, exist_ok=True)
            return base
        except Exception:
            pass

    # 4) Último recurso relativo
    base = Path.cwd() / ".xh_data"
    try:
        base.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    return base


def get_data_dir() -> str:
    """Devuelve el directorio base de datos/config/logs que está usando la app."""
    return str(_resolve_data_dir())


def set_data_dir(path: Union[str, Path]) -> None:
    """
    Fuerza el data_dir (útil para tests o entornos embebidos).
    Debe llamarse antes de configure()/get_logger() para influir en el log.
    """
    global _OVERRIDE_DATA_DIR
    _OVERRIDE_DATA_DIR = Path(path).expanduser()


def get_logs_dir() -> str:
    """Devuelve el directorio de logs dentro del data_dir."""
    base = _resolve_data_dir()
    logs = base / "logs"
    try:
        logs.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    return str(logs)


def _resolve_log_path() -> str:
    r"""
    Devuelve la ruta del archivo de log asegurando que es escribible.
    Prioridad:
      0) ENV XIAOHACK_LOG_FILE (ruta absoluta)
      1) <data_dir>/logs/control.log   (data_dir según reglas de arriba)
      2) .\logs\control.log
      3) .\control.log
    """
    # 0) Ruta directa por ENV
    env = os.getenv("XIAOHACK_LOG_FILE")
    if env:
        p = Path(env).expanduser()
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open("a", encoding="utf-8-sig") as f:
                f.write(time.strftime("%Y-%m-%d %H:%M:%S") + " [logs] logger-init(env)\n")
            return str(p)
        except Exception:
            pass

    # 1) Data dir deducido
    try:
        p = Path(get_logs_dir()) / "control.log"
        with p.open("a", encoding="utf-8-sig") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S") + " [logs] logger-init\n")
        return str(p)
    except Exception:
        pass

    # 2) y 3) fallback locales
    cwd = Path.cwd()
    for p in (cwd / "logs" / "control.log", cwd / "control.log"):
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open("a", encoding="utf-8-sig") as f:
                f.write(time.strftime("%Y-%m-%d %H:%M:%S") + " [logs] logger-init(fallback)\n")
            return str(p)
        except Exception:
            continue

    return str(cwd / "control.log")



# ==============================================================================
# Construcción de handlers
# ==============================================================================
def _build_file_handler(path: str,
                        max_bytes: int = _DEFAULT_MAX_BYTES,
                        backup_count: int = _DEFAULT_BACKUP_COUNT) -> RotatingFileHandler:
    """
    Handler con rotación. 'delay=True' evita abrir el archivo hasta el primer emit,
    reduciendo bloqueos al inicio en Windows.
    """
    handler = RotatingFileHandler(
        path,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8-sig",
        delay=True,
    )
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] [%(process)d:%(threadName)s] [%(name)s] %(message)s",
        "%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(fmt)
    return handler


def _build_console_handler() -> logging.Handler:
    handler = logging.StreamHandler(stream=sys.stdout)
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
        "%H:%M:%S",
    )
    handler.setFormatter(fmt)
    return handler


# ==============================================================================
# Inicialización / Config
# ==============================================================================
def _toggle_console(enabled: bool) -> None:
    global _CONSOLE_HANDLER
    base = logging.getLogger("xh")
    if enabled and _CONSOLE_HANDLER is None:
        _CONSOLE_HANDLER = _build_console_handler()
        base.addHandler(_CONSOLE_HANDLER)
    elif not enabled and _CONSOLE_HANDLER is not None:
        try:
            base.removeHandler(_CONSOLE_HANDLER)
        finally:
            _CONSOLE_HANDLER = None


def _ensure_initialized(level: Optional[Union[int, str]] = None,
                        log_path: Optional[str] = None,
                        console: Optional[bool] = None,
                        max_bytes: int = _DEFAULT_MAX_BYTES,
                        backup_count: int = _DEFAULT_BACKUP_COUNT) -> None:
    """
    Inicializa una sola vez el handler global y la ruta. Si ya estaba
    inicializado, permite actualizar nivel/console en caliente.
    """
    global _INITIALIZED, _LOG_FILE, _LOG_LEVEL, _HANDLER, _CONSOLE_HANDLER

    # Permitir strings "DEBUG"/"INFO"/etc.
    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)

    if _INITIALIZED:
        if level is not None:
            _LOG_LEVEL = level
            logging.getLogger("xh").setLevel(_LOG_LEVEL)
        if console is not None:
            _toggle_console(console)
        return

    _LOG_LEVEL = level or _LOG_LEVEL
    _LOG_FILE = log_path or _resolve_log_path()
    _HANDLER = _build_file_handler(_LOG_FILE, max_bytes=max_bytes, backup_count=backup_count)

    # Logger base de XiaoHack: todos los loggers serán hijos "xh.*"
    base = logging.getLogger("xh")
    base.setLevel(_LOG_LEVEL)
    base.propagate = False

    # Evitar duplicados si alguien reimporta/configura
    for h in list(base.handlers):
        base.removeHandler(h)
    base.addHandler(_HANDLER)

    # Console via ENV (1/true/yes/on)
    if console is None:
        env_console = (os.getenv("XIAOHACK_LOG_CONSOLE") or "").strip().lower()
        console = env_console in ("1", "true", "yes", "on")

    if console and _CONSOLE_HANDLER is None:
        _CONSOLE_HANDLER = _build_console_handler()
        base.addHandler(_CONSOLE_HANDLER)

    _INITIALIZED = True
    base.info("Logger inicializado → %s", _LOG_FILE)


def close_all() -> None:
    """
    Cierra todos los handlers y resetea el estado global.
    Útil para tests o relanzar el sistema de logs.
    """
    global _INITIALIZED, _HANDLER, _CONSOLE_HANDLER, _LOGGERS
    try:
        base = logging.getLogger("xh")
        for h in list(base.handlers):
            try:
                h.flush()
            except Exception:
                pass
            try:
                h.close()
            except Exception:
                pass
        base.handlers.clear()
    finally:
        _HANDLER = None
        _CONSOLE_HANDLER = None
        _LOGGERS.clear()
        _INITIALIZED = False


# ==============================================================================
# API pública principal
# ==============================================================================
def configure(*,
              level: Optional[Union[int, str]] = None,
              log_path: Optional[str] = None,
              console: Optional[bool] = None,
              max_bytes: int = _DEFAULT_MAX_BYTES,
              backup_count: int = _DEFAULT_BACKUP_COUNT) -> None:
    """
    Configura el logger global (idempotente).
    Úsalo temprano en el arranque si quieres ajustar valores por defecto.
    Puedes forzar el directorio con set_data_dir() o XH_DATA_DIR.
    """
    _ensure_initialized(level=level,
                        log_path=log_path,
                        console=console,
                        max_bytes=max_bytes,
                        backup_count=backup_count)


def get_logger(name: str = "app", level: Optional[int] = None) -> logging.Logger:
    """
    Devuelve un logger con nombre (app, scheduler, notifier, watcher…).
    Todos comparten el mismo archivo y formato, con un ÚNICO handler global.
    """
    global _LOGGERS
    _ensure_initialized()
    full_name = f"xh.{name}"
    if full_name in _LOGGERS:
        lg = _LOGGERS[full_name]
        if level is not None:
            lg.setLevel(level)
        return lg

    logger = logging.getLogger(full_name)
    if level is not None:
        logger.setLevel(level)
    # No añadir handlers aquí: cuelga del base "xh"
    logger.propagate = True  # Propaga al base "xh" (que tiene los handlers)
    logger.debug("logger-ready file=%s", _LOG_FILE)
    _LOGGERS[full_name] = logger
    return logger


def get_log_file() -> str:
    """Devuelve la ruta actual del archivo de log."""
    _ensure_initialized()
    assert _LOG_FILE is not None
    return _LOG_FILE


def set_level(level: Union[int, str]) -> None:
    """Cambia el nivel global en caliente (acepta int o 'DEBUG'/'INFO'/...)."""
    _ensure_initialized(level=level)


def enable_console(enabled: bool = True) -> None:
    """Activa/desactiva salida a consola en caliente."""
    _ensure_initialized()
    _toggle_console(enabled)


def log_debug(msg: str, *args, **kwargs) -> None:
    """Conveniencia: escribe directamente en el log global."""
    log = get_logger("global")
    log.debug(msg, *args, **kwargs)


@contextmanager
def log_timing(name: str, logger: Optional[logging.Logger] = None, level: int = logging.INFO):
    """
    Context manager para medir tiempos:

        with log_timing("cargar_config", get_logger("app")):
            load_config()
    """
    lg = logger or get_logger("perf")
    t0 = time.perf_counter()
    try:
        yield
    finally:
        dt = (time.perf_counter() - t0) * 1000.0
        lg.log(level, "%s: %.2f ms", name, dt)
        
# Helpers tipo Path (no rompen API existente de str)
def get_logs_dir_path() -> Path:
    return Path(get_logs_dir())

def get_log_file_path() -> Path:
    return Path(get_log_file())



# ==============================================================================
# Hooks de excepciones
# ==============================================================================
def install_exception_hooks(logger_name: str = "crash") -> None:
    """
    Redirige excepciones no capturadas (main thread + hilos) al log.
    No sustituye tu manejo habitual; simplemente registra el traceback.
    """
    lg = get_logger(logger_name)

    def _excepthook(exc_type, exc, tb):
        try:
            tb_txt = "".join(traceback.format_exception(exc_type, exc, tb))
        except Exception:  # pragma: no cover
            tb_txt = f"{exc_type.__name__}: {exc}"
        lg.error("UNCAUGHT EXCEPTION\n%s", tb_txt)

    def _thread_excepthook(args: threading.ExceptHookArgs):
        try:
            tb_txt = "".join(traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback))
        except Exception:  # pragma: no cover
            tb_txt = f"{args.exc_type.__name__}: {args.exc_value}"
        lg.error("UNCAUGHT THREAD EXCEPTION (thread=%s)\n%s", args.thread.name, tb_txt)

    sys.excepthook = _excepthook
    if hasattr(threading, "excepthook"):
        threading.excepthook = _thread_excepthook  # type: ignore[attr-defined]
    lg.info("exception-hooks-installed")


# ==============================================================================
# Tkinter helper opcional
# ==============================================================================
class _TkTextHandler(logging.Handler):
    """
    Envía los logs a un tk.Text de forma segura (via widget.after).
    Útil para paneles de depuración. No sustituye al archivo.
    """
    def __init__(self, text_widget, level=logging.INFO):
        super().__init__(level=level)
        self.text_widget = text_widget
        self.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", "%H:%M:%S"))

    def emit(self, record: logging.LogRecord) -> None:
        msg = self.format(record)
        try:
            self.text_widget.after(0, self._append, msg + "\n")
        except Exception:
            pass  # No romper el flujo si el widget ya no existe

    def _append(self, text: str):
        try:
            self.text_widget.insert("end", text)
            self.text_widget.see("end")
        except Exception:
            pass


def attach_tk_text_logger(text_widget, logger_name: str = "ui", level: int = logging.INFO) -> logging.Handler:
    """
    Adjunta un handler al logger indicado que escribe en un tk.Text.
    Devuelve el handler para que puedas removerlo más tarde si quieres.
    """
    lg = get_logger(logger_name)
    handler = _TkTextHandler(text_widget, level=level)
    lg.addHandler(handler)
    return handler


# ==============================================================================
# Auto-config por defecto
# ==============================================================================
# Si alguien importa logs.py y usa get_logger() sin llamar configure(),
# _ensure_initialized() aplicará los valores por defecto y ENV.
# No imprimimos nada aquí para evitar ruido en import.
