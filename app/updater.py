# updater.py — XiaoHack Control Parental
# - Comprueba última versión en GitHub y (opcional) aplica update desde ZIP runtime
# - Elevación UAC sólo al aplicar (si faltan permisos)
# - Detiene/relanza tarea SYSTEM del Guardian de forma segura
# - No toca ProgramData ni LocalAppData (solo binarios en INSTALL_DIR)
# --- bootstrap de imports cuando se ejecuta por ruta --------------------------

from __future__ import annotations
import json
import os
import sys
import shutil
import traceback
from typing import NoReturn
import zipfile
import tempfile
import subprocess
import time
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError

# --- bootstrap de imports cuando se ejecuta por ruta --------------------------
# Permite "from app..." aunque se lance updater.py por ruta.
_ROOT = Path(__file__).resolve().parents[1]  # ...\XiaoHackParental
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
# ------------------------------------------------------------------------------

from app.logs import get_logger  # noqa: E402

try:
    import sys
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


log = get_logger("gui.Updater")
  # ya usas time, Path, etc.

def _apply_log_path() -> Path:
    try:
        base = Path(os.getenv("ProgramData", r"C:\ProgramData")) / "XiaoHackParental" / "logs"
        base.mkdir(parents=True, exist_ok=True)
        return base / "updater_apply.log"
    except Exception:
        td = Path(os.getenv("TEMP", os.getenv("TMP", ".")))
        return td / "updater_apply.log"

def _apply_log(msg: str) -> None:
    try:
        p = _apply_log_path()
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(p, "a", encoding="utf-8", errors="ignore") as f:
            f.write(f"[{ts}] {msg}\n")
    except Exception:
        pass

def _fail(code: int, message: str, exc: Exception | None = None) -> NoReturn:

    _apply_log(f"ERROR {code}: {message}")
    if exc:
        _apply_log("TRACEBACK:\n" + "".join(traceback.format_exception(exc)))
    print(message, file=sys.stdout, flush=True)  # <- la GUI lo capturará
    raise SystemExit(code)



# ---------------- Config GitHub (con overrides por entorno) ----------------
# [XH] Permitir override para pruebas con forks o ramas
OWNER = os.getenv("XH_GH_OWNER", "JuanManuelRomeroGarcia")  # [XH]
REPO  = os.getenv("XH_GH_REPO",  "XiaoHack-Control-Parental")  # [XH]
API_LATEST = f"https://api.github.com/repos/{OWNER}/{REPO}/releases/latest"


# [XH] Timeout y UA
HTTP_TIMEOUT = float(os.getenv("XH_HTTP_TIMEOUT", "60"))  # segs  # [XH]

# --- Texto / versiones: robusto con BOM y normalización ----------------------
def _read_text_clean(path):
    # Lee UTF-8 con/sin BOM y limpia espacios/BOM residuales
    return path.read_text(encoding="utf-8-sig").strip().lstrip("\ufeff")

def _write_text_utf8(path, text):
    # Escribe en UTF-8 sin BOM (con LF final estándar)
    path.write_text((text or "").rstrip() + "\n", encoding="utf-8")

def _normalize_version_str(v: str) -> str:
    # quita prefijo "v", recorta y deja solo "X.Y.Z" (o "X.Y")
    v = (v or "").strip()
    if v.lower().startswith("v"):
        v = v[1:].strip()
    return v
# -----------------------------------------------------------------------------


def _local_version_for_ua() -> str:  # [XH]
    try:
        return read_local_version()
    except Exception:
        return "0.0.0"

def _build_user_agent() -> str:  # [XH]
    return f"XiaoHack-Updater/{_local_version_for_ua()} (+https://github.com/{OWNER}/{REPO})"

# Rutas
BASE_DIR     = Path(__file__).resolve().parent   
INSTALL_DIR  = _ROOT                                        
VER_JSON = INSTALL_DIR / "VERSION.json"
VER_TXT  = INSTALL_DIR / "VERSION"



# Tarea programada del servicio guardian (SYSTEM)
TASK_GUARDIAN = r"XiaoHackParental\Guardian"

# Nombres de ZIP aceptados (por orden de preferencia)
def candidate_zip_names(tag: str):
    return [
        f"XiaoHackParental-{tag}-runtime.zip",
        f"XiaoHack-Control-Parental-{tag}-runtime.zip",
        f"XiaoHackParental-{tag}.zip",
        f"XiaoHack-Control-Parental-{tag}.zip",
    ]

# Carpetas/archivos a NO copiar nunca al cliente
EXCLUDE_DIRS = {".git", ".github", "test", "tests", "__pycache__", ".venv", "venv", "dist", "build", "node_modules"}
EXCLUDE_FILESUFFIX = {".md", ".MD", ".markdown", ".rst"}
EXCLUDE_FILES = {".gitignore", ".gitattributes", ".editorconfig", "README", "README.md", "CHANGELOG.md", "LICENSE"}

# ---------------- Utilidades ----------------
def _http_get(url: str) -> bytes:
    # [XH] UA + Accept + token opcional para evitar rate-limit en pruebas
    headers = {
        "User-Agent": _build_user_agent(),
        "Accept": "application/vnd.github+json",
    }
    token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = Request(url, headers=headers)
    try:
        with urlopen(req, timeout=HTTP_TIMEOUT) as r:  # [XH] timeout
            return r.read()
    except HTTPError as e:
        # Mensaje claro (rate limit, etc.)
        if e.code in (403, 429):
            raise RuntimeError(f"GitHub rate limit o acceso denegado ({e.code}). "
                               f"Intenta más tarde o configura GITHUB_TOKEN.")
        raise RuntimeError(f"HTTP {e.code} en {url}: {e.reason}")
    except URLError as e:
        raise RuntimeError(f"Error de red para {url}: {e.reason}")
    except Exception as e:
        raise RuntimeError(f"HTTP GET falló para {url}: {type(e).__name__}: {e}")

def _ver_tuple(v: str):
    # robusto: acepta "1.2.3" o "1.2"
    parts = []
    for tok in v.replace("-", ".").split("."):
        try:
            parts.append(int(tok))
        except Exception:
            break
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])

def read_local_version() -> str:
    # Prioriza JSON, luego texto; ambos BOM-safe
    try:
        if VER_JSON.exists():
            data = json.loads(_read_text_clean(VER_JSON))
            v = _normalize_version_str(data.get("version", ""))
            if v:
                return v
    except Exception:
        pass
    try:
        if VER_TXT.exists():
            return _normalize_version_str(_read_text_clean(VER_TXT)) or "0.0.0"
    except Exception:
        pass
    return "0.0.0"

def write_local_version(new_version: str) -> None:
    # Escribe SIEMPRE JSON bonito y sin BOM
    data = {"version": _normalize_version_str(new_version)}
    _write_text_utf8(VER_JSON, json.dumps(data, ensure_ascii=False))

def get_latest_release():
    """
    Devuelve (tag, zip_asset) o (None, None) en caso de error.
    Nunca lanza excepción.
    """
    try:
        data = json.loads(_http_get(API_LATEST).decode("utf-8"))
        tag = _normalize_version_str((data.get("tag_name") or data.get("name") or ""))
        assets = data.get("assets", []) or []
        # Intenta casar con tus nombres zip esperados según 'tag'
        wanted = set(candidate_zip_names(tag)) if tag else set()
        zip_asset = None
        by_name = {a.get("name", ""): a for a in assets}
        for name in wanted:
            if name in by_name:
                zip_asset = by_name[name]
                break
        if not zip_asset:
            zips = [a for a in assets if a.get("name", "").lower().endswith(".zip")]
            if len(zips) == 1:
                zip_asset = zips[0]
        return (tag or None), zip_asset
    except Exception as e:
        log.error("Error obteniendo última versión desde GitHub: %s", e, exc_info=True)
        return None, None


def get_latest_version_fallback(owner: str, repo: str, branch: str = "main"):
    """
    Intenta leer VERSION.json o VERSION desde la rama.
    Devuelve (latest_version, error_str|None).
    """
    last_err = None
    urls = [
        f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/VERSION.json",
        f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/VERSION",
    ]
    for url in urls:
        try:
            raw = _http_get(url)
            if url.endswith(".json"):
                data = json.loads(raw.decode("utf-8"))
                v = _normalize_version_str(data.get("version", ""))
            else:
                v = _normalize_version_str(raw.decode("utf-8-sig", "replace").strip().lstrip("\ufeff"))
            if v:
                return v, None
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"
    return None, (last_err or "No se pudo leer VERSION en raw.githubusercontent.com")


def resolve_latest_version(owner: str, repo: str, branch: str = "main"):
    """
    Devuelve (latest_version|None, error_str|None).
    Primero intenta releases, si no hay, cae a raw VERSION.
    """
    tag, _asset = get_latest_release()
    if tag:
        return tag, None
    latest, err = get_latest_version_fallback(owner, repo, branch)
    if latest:
        return latest, None
    return None, (err or "No se pudo obtener la versión de GitHub")



def _should_skip(path: str, is_dir: bool) -> bool:
    name = os.path.basename(path)
    if is_dir and name in EXCLUDE_DIRS:
        return True
    if not is_dir:
        if name in EXCLUDE_FILES:
            return True
        for suf in EXCLUDE_FILESUFFIX:
            if name.endswith(suf):
                return True
    return False

def _stop_guardian_task():
    try:
        subprocess.run(["schtasks", "/End", "/TN", TASK_GUARDIAN], check=False, capture_output=True, creationflags=0x08000000)
    except Exception:
        pass

def _start_guardian_task():
    try:
        subprocess.run(["schtasks", "/Run", "/TN", TASK_GUARDIAN], check=False, capture_output=True, creationflags=0x08000000)
    except Exception:
        pass

def _kill_processes_in_install(extra_names: tuple[str, ...] = ()) -> None:
    """
    Mata procesos cuyo ExecutablePath esté dentro de INSTALL_DIR,
    EXCEPTO el proceso actual (y, opcionalmente, nombres extra por si quieres preservarlos).
    Deja trazas en el apply log.
    """
    base = str(INSTALL_DIR).lower()
    me = os.getpid()
    try:
        myexe = str(Path(sys.executable).resolve())
    except Exception:
        myexe = ""

    _apply_log(f"KILL in install dir: base={base} pid_me={me} exe_me={myexe}")

    # PowerShell porque WMIC está deprecado y necesitamos ExecutablePath
    ps = rf"""
$base = '{base}'
$me   = {me}
Get-CimInstance Win32_Process |
  ForEach-Object {{
    try {{
      $exe = $_.ExecutablePath
      if (-not $exe) {{ return }}
      $exel = $exe.lower()
      if ($exel.StartsWith($base)) {{
        if ($_.ProcessId -eq $me) {{ return }}              # NO matarnos
        # Evitar matar el mismo intérprete que está ejecutando el updater (por path)
        if ($exel -eq '{myexe.lower()}') {{ return }}
        # Evitar matar por nombres extra, si se pasan
        $name = $_.Name.lower()
        {('' if not extra_names else "if (@(" + ",".join([f"'{n.lower()}'" for n in extra_names]) + ").Contains($name)) { return }")}
        Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop
        Write-Output ('KILLED ' + $_.ProcessId + ' ' + $exe)
      }}
    }} catch {{ }}
  }}
"""
    cp = subprocess.run(
        ["PowerShell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
        capture_output=True, text=True, creationflags=0x08000000
    )
    if cp.stdout:
        for line in cp.stdout.splitlines():
            _apply_log(line.strip())
    if cp.stderr:
        _apply_log("KILL STDERR: " + cp.stderr.strip())



def _find_zip_root(tmp_dir: Path) -> Path:
    """
    Si el ZIP trae una carpeta raíz única (p.ej. XiaoHackParental-1.2.3/...), úsala como root.
    Si no, usa tmp_dir directamente.
    """
    entries = [p for p in tmp_dir.iterdir()]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return tmp_dir

def _apply_zip_to_install(zip_path: Path):
    with tempfile.TemporaryDirectory() as tmp_s:
        tmp = Path(tmp_s)
        with zipfile.ZipFile(zip_path, "r") as z:
            z.extractall(tmp)
        root = _find_zip_root(tmp)
        # Copia filtrada
        for src_dir, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if not _should_skip(os.path.join(src_dir, d), True)]
            for f in files:
                src = Path(src_dir) / f
                if _should_skip(str(src), False):
                    continue
                rel = src.relative_to(root)
                dst = INSTALL_DIR / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)

        # Limpieza opcional de restos de versiones anteriores
        _cleanup_orphans_from_install(root)

                
def _cleanup_orphans_from_install(zip_root: Path):
    """
    Elimina archivos presentes en INSTALL_DIR que no están en el zip aplicado.
    Se activa sólo si XH_CLEAN_ORPHANS=1.
    Nunca borra: venv/, logs/, *.log, installed.json
    """
    if os.getenv("XH_CLEAN_ORPHANS", "0") != "1":
        return

    keep_dirs = {"venv", "logs"}
    keep_files = {"installed.json"}

    wanted = set()
    for src_dir, dirs, files in os.walk(zip_root):
        rel_dir = Path(src_dir).relative_to(zip_root)
        for f in files:
            if _should_skip(str(Path(src_dir) / f), False):
                continue
            wanted.add((rel_dir / f).as_posix())

    for cur_dir, dirs, files in os.walk(INSTALL_DIR):
        # filtra dirs que nunca borraríamos
        dirs[:] = [d for d in dirs if d not in keep_dirs]
        for f in files:
            if f in keep_files:
                continue
            p = Path(cur_dir) / f
            rel = p.relative_to(INSTALL_DIR).as_posix()
            # si el archivo no está en el zip y no es un excluido explícito, borra
            if rel not in wanted and not _should_skip(str(p), False):
                try:
                    p.unlink()
                except Exception:
                    pass

# ---------------- Elevación UAC (sólo al aplicar) ----------------
def _is_admin() -> bool:
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def _elevate_and_apply(tmp_json: Path) -> int:
    _apply_log(f"Elevando para aplicar. Payload: {tmp_json}")
    py = os.path.normpath(sys.executable)
    pyw = str(Path(py).with_name("pythonw.exe"))
    py_to_use = pyw if os.path.exists(pyw) else py

    exe     = py_to_use.replace("'", "''")
    script  = str(Path(__file__).resolve()).replace("'", "''")
    payload = str(tmp_json).replace("'", "''")

    ps_cmd = (
        "$argsList=@('{script}','--apply-elevated','{payload}');"
        "$p=Start-Process -Verb RunAs -WindowStyle Hidden -FilePath '{exe}' "
        "-ArgumentList $argsList -PassThru -Wait;"
        "exit $p.ExitCode"
    ).format(exe=exe, script=script, payload=payload)

    cp = subprocess.run(
        ["PowerShell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
        text=True, capture_output=True, creationflags=0x08000000
    )
    _apply_log(f"Elevación terminada. rc={cp.returncode}")
    if cp.stdout:
        _apply_log("ELEVATION STDOUT:\n" + cp.stdout.strip())
    if cp.stderr:
        _apply_log("ELEVATION STDERR:\n" + cp.stderr.strip())
    return cp.returncode

def cmd_check() -> int:
    info = check_for_update(auto_apply=False)
    print(json.dumps(info, ensure_ascii=False))
    return 0

def cmd_apply() -> int:
    _apply_log("BEGIN --apply")
    try:
        current = read_local_version()
        _apply_log(f"Versión local: {current}; INSTALL_DIR={INSTALL_DIR}")

        latest, err = resolve_latest_version(OWNER, REPO, branch="main")  # cambia a "master" si procede
        if not latest:
            _fail(15, f"No se pudo obtener la versión de GitHub: {err}")

        _apply_log(f"Latest en GitHub: {latest}")
        if _ver_tuple(latest) <= _ver_tuple(current):
            msg = f"Ya está actualizado (local={current}, latest={latest})."
            _apply_log(msg) 
            print(msg)
            return 0

        tag, zip_asset = get_latest_release()
        if not tag or _normalize_version_str(tag) != _normalize_version_str(latest):
            _fail(15, "No se encontró un release con ZIP para esta versión. "
                      "Sube el asset runtime al release o ajusta get_latest_release().")
        if not zip_asset:
            _fail(15, "No se encontró un ZIP de runtime en el release. "
                      "Sugerido: XiaoHackParental-<version>-runtime.zip")

        zip_url  = zip_asset.get("browser_download_url")
        zip_name = zip_asset.get("name", "update.zip")
        if not zip_url:
            _fail(15, "El asset ZIP del release no tiene browser_download_url.")

        with tempfile.TemporaryDirectory() as td:
            td_p = Path(td)
            local_zip = td_p / zip_name
            _apply_log(f"Descargando ZIP: {zip_url}")
            local_zip.write_bytes(_http_get(zip_url))
            _apply_log(f"ZIP descargado: {local_zip} ({local_zip.stat().st_size} bytes)")

            can_write = os.access(INSTALL_DIR, os.W_OK)
            if not can_write or not _is_admin():
                payload = {"zip": str(local_zip), "latest": latest, "install_dir": str(INSTALL_DIR)}
                tmp_json = td_p / "apply.json"
                tmp_json.write_text(json.dumps(payload), encoding="utf-8")
                _apply_log(f"Sin permisos. Elevando con payload: {tmp_json}")
                code = _elevate_and_apply(tmp_json)
                if code != 0:
                    _fail(code or 15, f"Operación cancelada o fallida durante la elevación (rc={code}).")
                _apply_log("OK: actualización aplicada por proceso elevado.")
                print("OK: actualización aplicada (elevado).")
                return 0

            _apply_log("Parando guardian y aplicando ZIP en línea (somos admin).")
            _stop_guardian_task()
            _kill_processes_in_install()
            time.sleep(0.5)
            _apply_zip_to_install(local_zip)
            try:
                write_local_version(latest)
            except Exception as e:
                _apply_log(f"WARNING: no pude escribir VERSION.json: {e}")
            _start_guardian_task()
            _apply_log("OK: actualización aplicada (en línea).")
            print("OK: actualización aplicada.") 
            return 0

    except SystemExit:
        raise
    except Exception as e:
        _fail(15, f"Fallo inesperado en --apply: {e}", e)

# ---------------- API pública ----------------
def check_for_update(auto_apply=False) -> dict:
    """
    Comprueba versión y, si auto_apply=True, aplica update con elevación si hace falta.
    Devuelve: {"current","latest","update_available","applied","error"}
    """
    info = {"current": read_local_version(), "latest": None, "update_available": False, "applied": False, "error": None}

    # 1) Resolver latest con releases -> fallback a raw VERSION(.json)
    latest, err = resolve_latest_version(OWNER, REPO, branch="main")  # cambia a "master" si toca
    if not latest:
        info["error"] = f"No se pudo obtener la versión de GitHub: {err}"
        return info

    info["latest"] = latest
    if _ver_tuple(latest) <= _ver_tuple(info["current"]):
        return info  # ya al día

    info["update_available"] = True
    if not auto_apply:
        return info

    # 2) Para auto-apply necesitamos localizar el ZIP en releases
    tag, zip_asset = get_latest_release()
    if not tag or _normalize_version_str(tag) != _normalize_version_str(latest):
        info["error"] = ("No se encontró un release con ZIP para esta versión. "
                         "Descarga manual o publica el asset runtime.")
        return info
    if not zip_asset:
        info["error"] = ("No se encontró un ZIP de runtime en el release. "
                         "Sugerido: XiaoHackParental-<version>-runtime.zip")
        return info

    zip_url  = zip_asset.get("browser_download_url")
    zip_name = zip_asset.get("name", "update.zip")
    if not zip_url:
        info["error"] = "El asset ZIP no tiene URL de descarga."
        return info

    # 3) Descarga/aplica (eleva si hace falta)
    try:
        with tempfile.TemporaryDirectory() as td:
            td_p = Path(td)
            local_zip = td_p / zip_name
            local_zip.write_bytes(_http_get(zip_url))

            can_write = os.access(INSTALL_DIR, os.W_OK)
            if not can_write or not _is_admin():
                payload = {"zip": str(local_zip), "latest": latest, "install_dir": str(INSTALL_DIR)}
                tmp_json = td_p / "apply.json"
                tmp_json.write_text(json.dumps(payload), encoding="utf-8")
                code = _elevate_and_apply(tmp_json)
                if code != 0:
                    info["error"] = "Operación cancelada o fallida durante la elevación."
                    return info
                info["applied"] = True
                return info

            _stop_guardian_task()
            _kill_processes_in_install()
            time.sleep(0.5)
            _apply_zip_to_install(local_zip)
            try:
                write_local_version(latest)
            except Exception:
                pass
            _start_guardian_task()
            info["applied"] = True
            return info

    except Exception as e:
        try:
            _start_guardian_task()
        except Exception:
            pass
        info["error"] = f"Fallo al actualizar: {e}"
        return info


# ---------------- Entrada CLI (modo elevado) ----------------
def _apply_elevated_from_payload(payload_path: Path) -> int:
    _apply_log(f"BEGIN --apply-elevated payload={payload_path}")
    try:
        payload = json.loads(payload_path.read_text(encoding="utf-8"))
        zip_path = Path(payload["zip"])
        latest = payload.get("latest", "")
        if not zip_path.exists():
            _fail(3, f"ZIP temporal no existe: {zip_path}")

        _stop_guardian_task()
        _kill_processes_in_install()
        time.sleep(0.5)
        _apply_zip_to_install(zip_path)
        try:
            write_local_version(latest)
        except Exception as e:
            _apply_log(f"WARNING: no pude escribir VERSION.json elevado: {e}")
        _start_guardian_task()
        _apply_log("OK: actualización aplicada (elevado).")
        print("OK: actualización aplicada (elevado).")
        return 0
    except SystemExit:
        raise
    except Exception as e:
        try:
            _start_guardian_task()
        except Exception:
            pass
        _fail(2, f"Fallo en --apply-elevated: {e}", e)



if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(prog="app.updater")
    parser.add_argument("--check", action="store_true", help="Solo comprobar (JSON)")
    parser.add_argument("--apply", action="store_true", help="Aplicar actualización (elevar si hace falta)")
    parser.add_argument("--apply-elevated", metavar="PAYLOAD", help="Uso interno (proceso elevado)")
    args = parser.parse_args()

    if args.apply_elevated:
        sys.exit(_apply_elevated_from_payload(Path(args.apply_elevated)))
    if args.apply:
        sys.exit(cmd_apply())
    # por defecto o --check:
    sys.exit(cmd_check())
