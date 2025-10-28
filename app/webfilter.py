# webfilter.py — XiaoHack Parental / hosts manager (con logs integrados)
import os
import re
import sys
import shutil
import tempfile
import subprocess
from datetime import datetime
from typing import List, Optional
from app.logs import get_logger

log = get_logger("webfilter")

# Ruta por defecto del hosts (Windows)
HOSTS = r"C:\Windows\System32\drivers\etc\hosts"
BACKUP = None  # se recalcula desde _recalc_backup()

BEGIN_MARK = "# === PARENTAL_BEGIN ==="
END_MARK   = "# === PARENTAL_END ==="


def _block_pattern(begin: str = BEGIN_MARK, end: str = END_MARK) -> re.Pattern:
    pat = rf"(?ms)^[ \t]*{re.escape(begin)}[ \t]*\r?\n.*?^[ \t]*{re.escape(end)}[ \t]*(?:\r?\n)?"
    return re.compile(pat)

GOOGLE_TLDS: List[str] = ["com", "es", "co.uk", "de", "fr", "it", "pt", "com.mx", "com.ar"]
BING_HOSTS:  List[str] = ["bing.com", "www.bing.com", "cn.bing.com"]
YOUTUBE_HOSTS: List[str] = [
    "youtube.com", "www.youtube.com", "m.youtube.com",
    "youtube-nocookie.com", "www.youtube-nocookie.com"
]
YANDEX_HOSTS: List[str] = ["yandex.com", "www.yandex.com", "yandex.ru", "www.yandex.ru"]

GOOGLE_SAFE_IP   = "216.239.38.120"
BING_STRICT_IP   = "150.171.28.16"
YANDEX_FAMILY_IP = "213.180.204.242"

# ---------- Ruta/backup ----------
def _recalc_backup() -> str:
    global BACKUP
    BACKUP = HOSTS + ".parental.bak"
    return BACKUP

def set_hosts_path(path: str) -> None:
    global HOSTS
    HOSTS = path
    _recalc_backup()
    log.debug("Ruta de hosts personalizada: %s", HOSTS)

_recalc_backup()

# ---------- Permisos ----------
def can_write_hosts() -> bool:
    """
    Devuelve True si parece posible escribir el archivo hosts.
    No modifica nada; útil para diagnosticar antes de intentar aplicar reglas.
    """
    try:
        if not os.path.exists(HOSTS):
            return False
        if not os.access(HOSTS, os.W_OK):
            return False
        dir_ = os.path.dirname(HOSTS) or "."
        fd, tmp = tempfile.mkstemp(prefix=".hosts_perm_test_", dir=dir_)
        os.close(fd)
        try:
            os.remove(tmp)
        except Exception:
            pass
        return True
    except Exception:
        return False

# ---------- IO texto ----------
def _read_hosts() -> str:
    try:
        with open(HOSTS, "r", encoding="utf-8", errors="ignore") as f:
            data = f.read()
            log.debug("Leído archivo hosts (%d bytes)", len(data))
            return data
    except FileNotFoundError:
        log.warning("Archivo hosts no encontrado: %s", HOSTS)
        return ""
    except Exception as e:
        log.error("Error leyendo hosts (utf-8): %s", e)
        try:
            with open(HOSTS, "r", errors="ignore") as f:
                return f.read()
        except Exception as e2:
            log.error("Error leyendo hosts (fallback): %s", e2)
            return ""

def _atomic_write(path: str, text: str) -> None:
    """
    Escribe en binario normalizando EOL a CRLF, permitiendo UNA sola línea en blanco.
    Si el sistema deniega el acceso, propaga un PermissionError.
    """
    try:
        # 1) Normaliza EOL a '\n'
        import re as _re
        txt = _re.sub(r'\r\n?|\n', '\n', text)
        # 2) Colapsa secuencias largas (3+ saltos) a 2 (una línea en blanco)
        txt = _re.sub(r'\n{3,}', '\n\n', txt)
        # 3) Asegura salto final
        if not txt.endswith('\n'):
            txt += '\n'
        # 4) Convierte a CRLF
        normalized = txt.replace('\n', '\r\n')

        dir_ = os.path.dirname(path) or "."
        fd, tmp = tempfile.mkstemp(prefix=".hosts_tmp_", dir=dir_)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(normalized.encode("utf-8"))
            try:
                os.replace(tmp, path)
                log.debug("Archivo hosts escrito (atomic replace, binario).")
            except PermissionError as e:
                log.warning("Permiso denegado al escribir hosts (atomic replace): %s", e)
                raise
            except Exception:
                try:
                    shutil.copyfile(tmp, path)
                    log.debug("Archivo hosts copiado (fallback, binario).")
                except PermissionError as e:
                    log.warning("Permiso denegado al copiar hosts (fallback): %s", e)
                    raise
        finally:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except Exception:
                pass
    except PermissionError as e:
        log.warning("Permiso denegado al escribir hosts: %s", e)
        raise
    except Exception as e:
        log.error("Error escribiendo hosts: %s", e)
        raise

def _write_hosts(text: str) -> None:
    _atomic_write(HOSTS, text)

def _ensure_backup() -> None:
    backup = _recalc_backup()
    if not os.path.exists(backup) and os.path.exists(HOSTS):
        try:
            shutil.copyfile(HOSTS, backup)
            log.info("Backup creado: %s", backup)
        except Exception as e:
            log.warning("No se pudo crear backup: %s", e)

# ---------- Helpers ----------
def _dedup_and_clean(lines: List[str]) -> List[str]:
    seen, out = set(), []
    for ln in lines:
        s = ln.strip()
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out

def _flush_dns():
    try:
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True, text=True, check=False, creationflags=0x08000000)
        log.info("DNS cache limpiada (ipconfig /flushdns).")
    except Exception as e:
        log.warning("No se pudo limpiar cache DNS: %s", e)

# ---------- Construcción del bloque ----------
def _norm_domain(x: str) -> Optional[str]:
    """
    Limpia un dominio ingresado por el usuario:
    - quita comillas, espacios
    - quita http:// o https://
    - quita path y query (todo tras el primer '/')
    - pasa a minúsculas
    - descarta entradas vacías o claramente inválidas
    """
    if not x:
        return None
    x = x.strip().strip('"').strip("'").lower()
    if not x:
        return None
    if x.startswith("http://"):
        x = x[7:]
    elif x.startswith("https://"):
        x = x[8:]
    if "/" in x:
        x = x.split("/", 1)[0]
    x = x.strip(". ")
    return x or None

def _build_safe_rules(enable_safe: bool,
                      blocked_domains: List[str],
                      google_tlds: Optional[List[str]] = None,
                      block_www: bool = True) -> str:
    header = [
        BEGIN_MARK,
        "# XiaoHack Parental — autogenerated block",
        f"# Timestamp: {datetime.now().isoformat(timespec='seconds')}",
        "# No edites manualmente dentro de este bloque (será regenerado)."
    ]
    rules: List[str] = []

    for d in blocked_domains or []:
        d = _norm_domain(d)
        if not d:
            continue
        # Evita líneas inválidas (hosts no admite '/')
        if "/" in d:
            continue
        rules.append(f"0.0.0.0 {d}")
        if block_www and not d.startswith("www."):
            parts = d.split(".")
            if len(parts) in (2, 3):
                rules.append(f"0.0.0.0 www.{d}")

    if enable_safe:
        tlds = google_tlds if (google_tlds and isinstance(google_tlds, list)) else GOOGLE_TLDS
        for tld in tlds:
            base = f"google.{tld}"
            rules += [f"{GOOGLE_SAFE_IP} {base}", f"{GOOGLE_SAFE_IP} www.{base}"]
        for h in YOUTUBE_HOSTS:
            rules.append(f"{GOOGLE_SAFE_IP} {h}")
        for h in BING_HOSTS:
            rules.append(f"{BING_STRICT_IP} {h}")
        for h in YANDEX_HOSTS:
            rules.append(f"{YANDEX_FAMILY_IP} {h}")
        log.debug("SafeSearch activado: %d TLDs + YouTube/Bing/Yandex", len(tlds))

    footer = [END_MARK]
    text = "\r\n".join(header + _dedup_and_clean(rules) + footer)
    return "\r\n".join(s.rstrip() for s in text.splitlines())

def _merge_block(original_text: str, new_block: str) -> str:
    """
    Inserta/reemplaza el bloque parental garantizando una línea en blanco antes del BEGIN.
    """
    rx = _block_pattern()
    m = rx.search(original_text)
    block = new_block.rstrip("\r\n")
    SEP_BEFORE = "\r\n\r\n"

    if m:
        head = original_text[:m.start()]
        tail = original_text[m.end():]

        out = (head + SEP_BEFORE) if head else ""
        out += block

        if tail and not tail.startswith(("\r", "\n")):
            out += "\r\n"
        out += tail
        return out

    base = original_text.rstrip("\r\n")
    if base:
        return base + SEP_BEFORE + block
    else:
        return block

# ---------- API pública (núcleo: SIN CAMBIOS DE COMPORTAMIENTO) ----------
def ensure_hosts_rules(cfg: dict) -> None:
    """
    Aplica bloque parental (con backup y flush DNS).
    - Respeta cfg['safesearch'] (por defecto: False)
    - Respeta cfg['domains_enabled'] (si es False, no escribe dominios)
    - Si no hay cambios efectivos, NO reescribe el archivo
    """
    log.info("Aplicando reglas de filtrado parental...")
    _ensure_backup()
    content = _read_hosts()

    enable_safe = bool(cfg.get("safesearch", False))
    blocked = list(cfg.get("blocked_domains", []))
    if not cfg.get("domains_enabled", True):
        blocked = []

    google_tlds = list(cfg.get("google_tlds", GOOGLE_TLDS)) if cfg.get("google_tlds") else None
    block_www = bool(cfg.get("block_www", True))

    new_block = _build_safe_rules(enable_safe, blocked, google_tlds, block_www)
    merged = _merge_block(content, new_block)

    if merged == content:
        log.info("Reglas ya aplicadas: no hay cambios en hosts.")
        return

    try:
        _write_hosts(merged)
    except PermissionError:
        log.warning("Sin permisos para escribir hosts (ejecuta como Administrador si quieres aplicar cambios).")
        raise

    _flush_dns()
    log.info("Bloque parental aplicado correctamente (%d dominios bloqueados).", len(blocked))

def remove_parental_block() -> bool:
    """
    Elimina SOLO el bloque parental usando el patrón regex.
    Propaga PermissionError si no hay permisos al escribir.
    """
    log.info("Eliminando bloque parental de hosts...")
    text = _read_hosts()
    rx = _block_pattern()
    m = rx.search(text)
    if not m:
        log.info("No se encontró bloque parental en hosts.")
        return False

    head = text[:m.start()]
    tail = text[m.end():]
    if head.endswith(("\r\n\r\n", "\n\n")) and tail.startswith(("\r\n", "\n")):
        tail = tail[2:] if tail.startswith("\r\n") else tail[1:]
    new_text = head + tail

    if new_text == text:
        log.info("Nada que eliminar; hosts ya sin bloque.")
        return False

    try:
        _write_hosts(new_text)
    except PermissionError:
        log.warning("Sin permisos para escribir hosts (ejecuta como Administrador si quieres eliminar el bloque).")
        raise

    _flush_dns()
    log.info("Bloque parental eliminado correctamente.")
    return True

def rollback_hosts() -> None:
    backup = _recalc_backup()
    if os.path.exists(backup):
        try:
            shutil.copyfile(backup, HOSTS)
            _flush_dns()
            log.info("Hosts restaurado desde backup: %s", backup)
        except PermissionError:
            log.warning("Sin permisos para restaurar hosts desde backup.")
            raise
    else:
        log.warning("No se encontró backup para restaurar: %s", backup)

def has_parental_block(text: Optional[str] = None) -> bool:
    text = _read_hosts() if text is None else text
    return bool(_block_pattern().search(text)) or (BEGIN_MARK in text and END_MARK in text)

def safesearch_effective(text: Optional[str] = None) -> bool:
    text = _read_hosts() if text is None else text
    m = _block_pattern().search(text)
    if not m:
        return False
    chunk = m.group(0)
    return any(ip in chunk for ip in (GOOGLE_SAFE_IP, BING_STRICT_IP, YANDEX_FAMILY_IP))


# ======================================================================
# ENVOLTORIOS CON ELEVACIÓN (UAC) — para panel/tutor
# ======================================================================
def _is_admin() -> bool:
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def _powershell_elevated_wait(args: list[str]) -> int:
    """
    Lanza un proceso elevado con UAC y espera a que termine, devolviendo su exit code.
    """
    py = os.path.normpath(os.path.abspath(os.environ.get("PYTHONW_EXE", sys.executable)))
    # Construimos: Start-Process -Verb RunAs -FilePath "<python>" -ArgumentList "-m","webfilter",<args...> -Wait -PassThru
    # y salimos con su ExitCode
    ps = [
        "PowerShell", "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-Command",
        r"$p=Start-Process -Verb RunAs -FilePath '{}' -ArgumentList {} -WindowStyle Hidden -PassThru -Wait; exit $p.ExitCode".format(
            py.replace("'", "''"),
            "'" + "','".join(["-m","webfilter"] + args).replace("'", "''") + "'"
        )
    ]
    try:
        cp = subprocess.run(ps, capture_output=True, text=True, creationflags=0x08000000)
        if cp.stdout:
            log.debug("PS STDOUT: %s", cp.stdout.strip())
        if cp.stderr:
            log.debug("PS STDERR: %s", cp.stderr.strip())
        return cp.returncode
    except Exception as e:
        log.error("Fallo lanzando elevación PowerShell: %s", e)
        return 1

def ensure_hosts_rules_or_elevate(cfg: dict) -> None:
    """
    Intenta aplicar reglas; si no hay permisos, pide elevación UAC y reintenta
    ejecutando este módulo en modo '--apply-tmp'.
    """
    try:
        ensure_hosts_rules(cfg)
        return
    except PermissionError:
        pass

    # Guardamos cfg en un JSON temporal para el proceso elevado
    import json
    import sys  # noqa: F401
    fd, tmp = tempfile.mkstemp(prefix="xh_apply_", suffix=".json")
    os.close(fd)
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)

    code = _powershell_elevated_wait(["--apply-tmp", tmp])
    try:
        os.remove(tmp)
    except Exception:
        pass
    if code != 0:
        raise PermissionError("No se pudo aplicar el bloque parental (se canceló UAC o falló el proceso elevado).")

def remove_parental_block_or_elevate() -> bool:
    """
    Intenta eliminar el bloque; si no hay permisos, pide elevación UAC y reintenta
    ejecutando este módulo en modo '--remove'.
    """
    try:
        return remove_parental_block()
    except PermissionError:
        pass
    code = _powershell_elevated_wait(["--remove"])
    if code != 0:
        raise PermissionError("No se pudo eliminar el bloque parental (se canceló UAC o falló el proceso elevado).")
    return True

def rollback_hosts_or_elevate() -> None:
    """
    Intenta restaurar el backup; si no hay permisos, pide elevación UAC y reintenta
    ejecutando este módulo en modo '--rollback'.
    """
    try:
        rollback_hosts()
        return
    except PermissionError:
        pass
    code = _powershell_elevated_wait(["--rollback"])
    if code != 0:
        raise PermissionError("No se pudo restaurar el backup (UAC cancelado o fallo en proceso elevado).")


# ======================================================================
# CLI de servicio para el proceso elevado
# ======================================================================
if __name__ == "__main__":
    import sys
    import json
    args = sys.argv[1:]
    if not args:
        sys.exit(0)

    if args[0] == "--apply-tmp" and len(args) >= 2:
        tmp = args[1]
        try:
            with open(tmp, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            ensure_hosts_rules(cfg)
            sys.exit(0)
        except PermissionError:
            sys.exit(5)
        except Exception:
            sys.exit(2)

    if args[0] == "--remove":
        try:
            ok = remove_parental_block()
            sys.exit(0 if ok else 0)
        except PermissionError:
            sys.exit(5)
        except Exception:
            sys.exit(2)
            
    if args[0] == "--rollback":
        try:
            rollback_hosts()
            sys.exit(0)
        except PermissionError:
            sys.exit(5)
        except Exception:
            sys.exit(2)

    sys.exit(0)
