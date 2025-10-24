# webfilter.py — XiaoHack Parental / hosts manager (con logs integrados)
import os
import re
import shutil
import tempfile
import subprocess
from datetime import datetime
from typing import List, Optional
from logs import get_logger

log = get_logger("webfilter")

# Ruta por defecto del hosts (Windows)
HOSTS = r"C:\Windows\System32\drivers\etc\hosts"
BACKUP = None  # se recalcula desde _recalc_backup()

BEGIN_MARK = "# === PARENTAL_BEGIN ==="
END_MARK   = "# === PARENTAL_END ==="


def _block_pattern(begin: str = BEGIN_MARK, end: str = END_MARK) -> re.Pattern:
    # (?m)=MULTILINE, (?s)=DOTALL
    # - línea begin: ^[ \t]*BEGIN[ \t]*\r?\n
    # - cuerpo: .*? (no codicioso)
    # - línea end: ^[ \t]*END[ \t]* (y capturamos opcionalmente un \r?\n final)
    pat = rf"(?ms)^[ \t]*{re.escape(begin)}[ \t]*\r?\n.*?^[ \t]*{re.escape(end)}[ \t]*(?:\r?\n)?"
    return re.compile(pat)

GOOGLE_TLDS: List[str] = ["com", "es", "co.uk", "de", "fr", "it", "pt", "com.mx", "com.ar"]
BING_HOSTS:  List[str] = ["bing.com", "www.bing.com", "cn.bing.com"]
YOUTUBE_HOSTS: List[str] = [
    "youtube.com", "www.youtube.com", "m.youtube.com",
    "youtube-nocookie.com", "www.youtube-nocookie.com"
]
YANDEX_HOSTS: List[str] = ["yandex.com", "www.yandex.com", "yandex.ru", "www.yandex.ru"]

GOOGLE_SAFE_IP = "216.239.38.120"
BING_STRICT_IP = "150.171.28.16"
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
    - Normaliza todo a '\n'
    - Colapsa 3+ saltos a exactamente 2 ('\n\n')  → conserva una línea en blanco
    - Convierte '\n' → '\r\n'
    """
    try:
        # 1) Normaliza EOL a '\n'
        txt = re.sub(r'\r\n?|\n', '\n', text)
        # 2) Colapsa secuencias largas (3 o más) a 2 saltos (una línea en blanco)
        txt = re.sub(r'\n{3,}', '\n\n', txt)
        # 3) Asegura que termina en salto
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
            except Exception:
                shutil.copyfile(tmp, path)
                log.debug("Archivo hosts copiado (fallback, binario).")
        finally:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except Exception:
                pass
    except Exception as e:
        log.error("Error escribiendo hosts: %s", e)

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
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True, text=True, check=False)
        log.info("DNS cache limpiada (ipconfig /flushdns).")
    except Exception as e:
        log.warning("No se pudo limpiar cache DNS: %s", e)

# ---------- Construcción del bloque ----------
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
        d = d.strip().strip('"').strip("'")
        if not d:
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
    Inserta/reemplaza el bloque parental garantizando:
    - **Una línea en blanco** antes del BEGIN (== "\r\n\r\n" si hay contenido previo).
    - Después del END: añade "\r\n" solo si el tail no empieza con salto.
    'new_block' debe venir SIN CRLF final (lo recortamos por seguridad).
    """
    rx = _block_pattern()
    m = rx.search(original_text)
    block = new_block.rstrip("\r\n")
    SEP_BEFORE = "\r\n\r\n"  # <-- exactamente un salto en blanco

    if m:
        head = original_text[:m.start()]
        tail = original_text[m.end():]

        # aplasta salvos previos y deja exactamente una línea en blanco
        head = head
        out = (head + SEP_BEFORE) if head else ""  # si estaba vacío, no metas la línea en blanco
        out += block

        # entre bloque y tail: añade CRLF sólo si el tail NO arranca con salto
        if tail and not tail.startswith(("\r", "\n")):
            out += "\r\n"
        out += tail
        return out

    # no había bloque: pega al final con una línea en blanco si hay contenido previo
    base = original_text.rstrip("\r\n")
    if base:
        return base + SEP_BEFORE + block
    else:
        return block

    
# ---------- API pública ----------
def ensure_hosts_rules(cfg: dict) -> None:
    """
    Aplica bloque parental (con backup y flush DNS).
    - Respeta cfg['safesearch'] (por defecto: False)
    - Respeta cfg['domains_enabled'] (si es False, no escribe dominios)
    """
    log.info("Aplicando reglas de filtrado parental...")
    _ensure_backup()
    content = _read_hosts()

    # SafeSearch SOLO si el usuario lo marcó
    enable_safe = bool(cfg.get("safesearch", False))

    # Dominios sólo si domains_enabled=True
    blocked = list(cfg.get("blocked_domains", []))
    if not cfg.get("domains_enabled", True):
        blocked = []

    # TLDs: usa los del cfg si vienen, o el default
    google_tlds = list(cfg.get("google_tlds", GOOGLE_TLDS)) if cfg.get("google_tlds") else None
    block_www = bool(cfg.get("block_www", True))

    new_block = _build_safe_rules(enable_safe, blocked, google_tlds, block_www)
    merged = _merge_block(content, new_block)
    _write_hosts(merged)
    _flush_dns()
    log.info("Bloque parental aplicado correctamente (%d dominios bloqueados).", len(blocked))


def remove_parental_block() -> bool:
    """
    Elimina SOLO el bloque parental usando el patrón regex.
    """
    log.info("Eliminando bloque parental de hosts...")
    text = _read_hosts()
    rx = _block_pattern()
    m = rx.search(text)
    if not m:
        log.info("No se encontró bloque parental en hosts.")
        return False

    # Cortamos el bloque y normalizamos espacios (evitar dobles saltos)
    head = text[:m.start()]
    tail = text[m.end():]
    # Si ambos lados tienen salto contiguo, elimina uno
    if head.endswith(("\r\n\r\n", "\n\n")) and tail.startswith(("\r\n", "\n")):
        tail = tail[2:] if tail.startswith("\r\n") else tail[1:]

    new_text = head + tail
    _write_hosts(new_text)
    _flush_dns()
    log.info("Bloque parental eliminado correctamente.")
    return True

def rollback_hosts() -> None:
    backup = _recalc_backup()
    if os.path.exists(backup):
        shutil.copyfile(backup, HOSTS)
        _flush_dns()
        log.info("Hosts restaurado desde backup: %s", backup)
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
