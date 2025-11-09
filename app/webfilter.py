# webfilter.py — XiaoHack Parental / hosts manager (robusto con portable + elevación)
from __future__ import annotations

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

# Archivo hosts por defecto (Windows)
HOSTS = r"C:\Windows\System32\drivers\etc\hosts"
BACKUP = None  # se recalcula con _recalc_backup()

BEGIN_MARK = "# === PARENTAL_BEGIN ==="
END_MARK   = "# === PARENTAL_END ==="

def _block_pattern(begin: str = BEGIN_MARK, end: str = END_MARK) -> re.Pattern:
    # bloque entre marcas, tolerante a espacios y EOL
    pat = rf"(?ms)^[ \t]*{re.escape(begin)}[ \t]*\r?\n.*?^[ \t]*{re.escape(end)}[ \t]*(?:\r?\n)?"
    return re.compile(pat)

# SafeSearch/YouTube/Bing/Yandex
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
    """Prueba simple de escritura en el directorio de hosts (sin modificar el archivo)."""
    try:
        if not os.path.exists(HOSTS):
            return False
        if not os.access(HOSTS, os.W_OK):
            # os.access no siempre refleja ACL reales, pero es una pista
            log.debug("os.access deniega escritura en hosts.")
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
            log.debug("Leído hosts (%d bytes)", len(data))
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

def _normalize_text_crlf(text: str) -> bytes:
    """
    Normaliza:
      - EOL -> '\n'
      - colapsa secuencias 3+ EOL a doble salto (una línea en blanco)
      - asegura salto final
      - convierte a CRLF
      - devuelve bytes utf-8
    """
    txt = re.sub(r"\r\n?|\n", "\n", text)
    txt = re.sub(r"\n{3,}", "\n\n", txt)
    if not txt.endswith("\n"):
        txt += "\n"
    return txt.replace("\n", "\r\n").encode("utf-8")

def _clear_rsh_attrs(path: str) -> None:
    """Quita atributos ReadOnly/Hidden/System antes de reemplazar."""
    try:
        # attrib -R -H -S "path"
        subprocess.run(
            ["cmd.exe", "/c", "attrib", "-R", "-H", "-S", path],
            capture_output=True, text=True, check=False, creationflags=0x08000000
        )
    except Exception:
        pass

def _grant_admins_system_full(path: str) -> None:
    """Otorga F a Administrators y SYSTEM (no falla si ya está). Requiere elevación."""
    try:
        subprocess.run(
            ["icacls", path, "/grant", "Administrators:F", "SYSTEM:F", "/T", "/C"],
            capture_output=True, text=True, check=False, creationflags=0x08000000
        )
    except Exception:
        pass

def _atomic_write(path: str, text: str) -> None:
    """
    Escritura robusta del hosts:
      1) escribe tmp (utf-8 CRLF)
      2) os.replace()
      3) si acceso denegado: limpia atributos, reintenta
      4) si sigue: copy /Y (plan C)
      5) último recurso: icacls para F y reintento
    Propaga PermissionError si persiste el bloqueo.
    """
    payload = _normalize_text_crlf(text)
    dir_ = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".hosts_tmp_", dir=dir_)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(payload)

        # Primer intento: replace directo
        try:
            os.replace(tmp, path)
            log.debug("hosts escrito (replace)")
            return
        except PermissionError as e:
            log.warning("Permiso denegado en replace: %s", e)

        # Intento 2: limpiar atributos y reintentar replace
        _clear_rsh_attrs(path)
        try:
            os.replace(tmp, path)
            log.debug("hosts escrito tras limpiar atributos (replace)")
            return
        except PermissionError as e:
            log.warning("Replace tras limpiar atributos falló: %s", e)

        # Intento 3: plan C con copy /Y (suele funcionar con AV molestos)
        try:
            cp = subprocess.run(
                ["cmd.exe", "/c", "copy", "/Y", "/B", tmp, path],
                capture_output=True, text=True, check=False, creationflags=0x08000000
            )
            if cp.returncode == 0:
                log.debug("hosts escrito con copy /Y")
                return
            else:
                log.warning("copy /Y falló (rc=%s): %s", cp.returncode, (cp.stderr or cp.stdout))
        except Exception as e:
            log.warning("copy /Y lanzó excepción: %s", e)

        # Intento 4: dar F a Admins/SYSTEM y reintentar replace
        _grant_admins_system_full(path)
        try:
            os.replace(tmp, path)
            log.debug("hosts escrito tras icacls (replace)")
            return
        except PermissionError as e:
            log.warning("Replace tras icacls falló: %s", e)

        # Si llegamos aquí, seguimos sin poder escribir
        raise PermissionError("Acceso denegado al escribir hosts")

    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass

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

# ---------- Helpers de contenido ----------
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

def _norm_domain(x: str) -> Optional[str]:
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
        "# No edites manualmente dentro de este bloque (se regenerará)."
    ]
    rules: List[str] = []

    for d in blocked_domains or []:
        d = _norm_domain(d)
        if not d:
            continue
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
    
def _extract_rules_only(block_text: str) -> list[str]:
    """
    Devuelve solo las líneas de reglas (IP dominio), ignorando comentarios,
    marcas y espacios, para comparar bloques sin tener en cuenta timestamps.
    """
    out = []
    for ln in block_text.splitlines():
        s = ln.strip()
        if not s:
            continue
        if s.startswith("#"):
            continue
        if s == BEGIN_MARK or s == END_MARK:
            continue
        out.append(s)
    return out


# ---------- API pública ----------
def ensure_hosts_rules(cfg: dict) -> None:
    """
    Aplica bloque parental (con backup y flush DNS).
    Respeta:
      - cfg['safesearch'] (bool)
      - cfg['blocked_domains'] (list[str])  // si cfg['domains_enabled'] es False, ignora dominios
      - cfg['google_tlds'] opcional (list[str])
      - cfg['block_www'] (bool, True por defecto)
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

    # --- Idempotencia REAL: si las REGLAS son equivalentes (ignorando timestamp/comentarios), no reescribir
    try:
        rx = _block_pattern()
        m_old = rx.search(content)
        if m_old:
            old_rules = _extract_rules_only(m_old.group(0))
            new_rules = _extract_rules_only(new_block)
            if old_rules == new_rules:
                log.info("Reglas ya aplicadas (sin cambios efectivos): no se reescribe hosts.")
                return
    except Exception:
        # Si algo falla en la comparación, seguimos con el chequeo normal
        pass

    if merged == content:
        log.info("Reglas ya aplicadas: no hay cambios en hosts.")
        return

    try:
        _write_hosts(merged)
    except PermissionError:
        log.warning("Sin permisos para escribir hosts (ejecuta como Administrador o usa elevación).")
        raise

    _flush_dns()
    log.info("Bloque parental aplicado correctamente (%d dominios bloqueados).", len(blocked))


def remove_parental_block() -> bool:
    """Elimina SOLO el bloque parental. Propaga PermissionError si no hay permisos."""
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
        log.warning("Sin permisos para escribir hosts (eleva para eliminar).")
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
        log.warning("No se encontró backup: %s", backup)

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
# Elevación (UAC) para panel/usuario
# ======================================================================
def _is_admin() -> bool:
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def _powershell_elevated_wait(args: list[str]) -> int:
    """
    Start-Process -Verb RunAs pythonw -m webfilter <args...> y esperar el ExitCode.
    Usa PYTHONW_EXE si está (ideal en portable), si no sys.executable.
    """
    pyw = os.path.normpath(
        os.path.abspath(os.environ.get("PYTHONW_EXE", sys.executable))
    )
    ps = [
        "PowerShell", "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-Command",
        r"$p=Start-Process -Verb RunAs -FilePath '{}' -ArgumentList {} -WindowStyle Hidden -PassThru -Wait; exit $p.ExitCode".format(
            pyw.replace("'", "''"),
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
        log.error("Fallo en elevación PowerShell: %s", e)
        return 1

def ensure_hosts_rules_or_elevate(cfg: dict) -> None:
    """
    Intenta aplicar; si no hay permisos, pide UAC y reintenta en proceso elevado.
    """
    try:
        ensure_hosts_rules(cfg)
        return
    except PermissionError:
        pass

    import json
    fd, tmp = tempfile.mkstemp(prefix="xh_apply_", suffix=".json")
    os.close(fd)
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        code = _powershell_elevated_wait(["--apply-tmp", tmp])
    finally:
        try:
            os.remove(tmp)
        except Exception:
            pass

    if code != 0:
        raise PermissionError("No se pudo aplicar el bloque (UAC cancelado o fallo).")

def remove_parental_block_or_elevate() -> bool:
    try:
        return remove_parental_block()
    except PermissionError:
        pass
    code = _powershell_elevated_wait(["--remove"])
    if code != 0:
        raise PermissionError("No se pudo eliminar el bloque (UAC cancelado o fallo).")
    return True

def rollback_hosts_or_elevate() -> None:
    try:
        rollback_hosts()
        return
    except PermissionError:
        pass
    code = _powershell_elevated_wait(["--rollback"])
    if code != 0:
        raise PermissionError("No se pudo restaurar backup (UAC cancelado o fallo).")

# ======================================================================
# CLI para el proceso elevado
# ======================================================================
if __name__ == "__main__":
    import sys as _sys
    import json as _json
    args = _sys.argv[1:]
    if not args:
        _sys.exit(0)

    if args[0] == "--apply-tmp" and len(args) >= 2:
        tmp = args[1]
        try:
            with open(tmp, "r", encoding="utf-8") as f:
                cfg = _json.load(f)
            ensure_hosts_rules(cfg)
            _sys.exit(0)
        except PermissionError:
            _sys.exit(5)
        except Exception:
            _sys.exit(2)

    if args[0] == "--remove":
        try:
            ok = remove_parental_block()
            _sys.exit(0 if ok else 0)
        except PermissionError:
            _sys.exit(5)
        except Exception:
            _sys.exit(2)

    if args[0] == "--rollback":
        try:
            rollback_hosts()
            _sys.exit(0)
        except PermissionError:
            _sys.exit(5)
        except Exception:
            _sys.exit(2)

    _sys.exit(0)
