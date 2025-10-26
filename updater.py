# updater.py — XiaoHack Control Parental
# - Comprueba última versión en GitHub y (opcional) aplica update desde ZIP runtime
# - Elevación UAC sólo al aplicar (si faltan permisos)
# - Detiene/relanza tarea SYSTEM del Guardian de forma segura
# - No toca ProgramData ni LocalAppData (solo binarios en INSTALL_DIR)

from __future__ import annotations
import json
import os
import sys
import shutil
import zipfile
import tempfile
import subprocess
import time
from pathlib import Path
from urllib.request import urlopen, Request

try:
    import sys
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

from logs import get_logger
log = get_logger("gui.Updater")


OWNER = "JuanManuelRomeroGarcia"
REPO  = "XiaoHack-Control-Parental"
API_LATEST = f"https://api.github.com/repos/{OWNER}/{REPO}/releases/latest"
USER_AGENT = "XiaoHack-Updater"

# Rutas
BASE_DIR     = Path(__file__).resolve().parent             # carpeta instalada (Program Files\XiaoHackParental)
INSTALL_DIR  = BASE_DIR
VERSION_FILE = INSTALL_DIR / "VERSION"

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
    req = Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(req, timeout=60) as r:
            return r.read()
    except Exception as e:
        # Propagamos con mensaje claro
        raise RuntimeError(f"HTTP GET failed for {url}: {type(e).__name__}: {e}")

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

def read_local_version():
    try:
        return VERSION_FILE.read_text(encoding="utf-8").strip()
    except Exception:
        return "0.0.0"

def get_latest_release():
    """
    Devuelve (tag, zip_asset) o (None, None) en caso de error.
    Nunca lanza excepción.
    """
    try:
        data = json.loads(_http_get(API_LATEST).decode("utf-8"))
        tag = (data.get("tag_name") or data.get("name") or "").lstrip("v").strip()
        assets = data.get("assets", [])
        wanted = set(candidate_zip_names(tag)) if tag else set()
        zip_asset = None
        by_name = {a.get("name", ""): a for a in assets}
        for name in wanted:
            if name in by_name:
                zip_asset = by_name[name]
                break
        if not zip_asset:
            zips = [a for a in assets if (a.get("name", "").lower().endswith(".zip"))]
            if len(zips) == 1:
                zip_asset = zips[0]
        return tag, zip_asset
    except Exception as e:
        log.error("Error obteniendo última versión desde GitHub: %s", e, exc_info=True)
        return None, None  # señal de error controlado

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
        subprocess.run(["schtasks", "/End", "/TN", TASK_GUARDIAN], check=False, capture_output=True)
    except Exception:
        pass

def _start_guardian_task():
    try:
        subprocess.run(["schtasks", "/Run", "/TN", TASK_GUARDIAN], check=False, capture_output=True)
    except Exception:
        pass

def _kill_processes_in_install():
    """Mejor-esfuerzo: cierra procesos que ejecuten desde INSTALL_DIR (notifier/panel)."""
    try:
        import psutil  # opcional
    except Exception:
        # fallback agresivo: nada (evitamos matar python global)
        return
    inst = str(INSTALL_DIR).lower()
    for p in psutil.process_iter(attrs=["pid","name","exe","cwd","cmdline"]):
        try:
            exe = (p.info.get("exe") or "").lower()
            cwd = (p.info.get("cwd") or "").lower()
            cmd = " ".join(p.info.get("cmdline") or []).lower()
            if inst in exe or inst in cwd or inst in cmd:
                if p.pid == os.getpid():
                    continue
                for c in p.children(recursive=True):
                    try:
                        c.terminate()
                    except Exception:
                        pass
                p.terminate()
        except Exception:
            continue
    # espera corta; si sigue vivo lo mata
    time.sleep(0.7)
    if 'psutil' in sys.modules:
        import psutil
        for p in psutil.process_iter(attrs=["pid"]):
            try:
                if not p.is_running():
                    continue
            except Exception:
                continue

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
            # filtra dirs in-place (para evitar descender)
            dirs[:] = [d for d in dirs if not _should_skip(os.path.join(src_dir, d), True)]
            for f in files:
                src = Path(src_dir) / f
                if _should_skip(str(src), False):
                    continue
                rel = src.relative_to(root)
                dst = INSTALL_DIR / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                # No tocamos ProgramData/LocalAppData: sólo copiamos a INSTALL_DIR
                shutil.copy2(src, dst)

# ---------------- Elevación UAC (sólo al aplicar) ----------------
def _is_admin() -> bool:
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def _elevate_and_apply(tmp_json: Path) -> int:
    """
    Re-lanza este updater con UAC y espera a que termine.
    """
    py = os.path.normpath(sys.executable)
    ps = [
        "PowerShell", "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-Command",
        r"$p=Start-Process -Verb RunAs -FilePath '{}' -ArgumentList '{}','--apply-elevated','{}' -PassThru -Wait; exit $p.ExitCode".format(
            py.replace("'", "''"),
            str(Path(__file__).resolve()).replace("'", "''"),
            str(tmp_json).replace("'", "''"),
        )
    ]
    cp = subprocess.run(ps, capture_output=True, text=True)
    return cp.returncode

# ---------------- API pública ----------------
def check_for_update(auto_apply=False) -> dict:
    """
    Comprueba versión y, si auto_apply=True, aplica update con elevación si hace falta.
    Devuelve: {"current","latest","update_available", "applied", "error"}
    """
    info = {"current": read_local_version(), "latest": None, "update_available": False, "applied": False, "error": None}
    try:
        latest, zip_asset = get_latest_release()
        info["latest"] = latest
    except Exception as e:
        info["error"] = f"No se pudo consultar GitHub: {e}"
        return info

    if not latest:
        info["error"] = "No se pudo leer la versión de GitHub."
        return info

    if _ver_tuple(latest) <= _ver_tuple(info["current"]):
        return info  # ya al día

    info["update_available"] = True
    if not auto_apply:
        return info

    if not zip_asset:
        info["error"] = ("No se encontró un ZIP de runtime en el release. "
                         "Sugerido: XiaoHackParental-<version>-runtime.zip")
        return info

    zip_url = zip_asset.get("browser_download_url")
    zip_name = zip_asset.get("name","update.zip")
    if not zip_url:
        info["error"] = "El asset ZIP no tiene URL de descarga."
        return info

    # Descarga y aplica (con elevación si hace falta)
    try:
        with tempfile.TemporaryDirectory() as td:
            td_p = Path(td)
            local_zip = td_p / zip_name
            local_zip.write_bytes(_http_get(zip_url))

            # Si no hay permisos de escritura en INSTALL_DIR, elevamos
            can_write = os.access(INSTALL_DIR, os.W_OK)
            if not can_write or not _is_admin():
                # Guardamos la info temporal (ruta del zip descargado) para el proceso elevado
                payload = {"zip": str(local_zip), "latest": latest, "install_dir": str(INSTALL_DIR)}
                tmp_json = td_p / "apply.json"
                tmp_json.write_text(json.dumps(payload), encoding="utf-8")
                code = _elevate_and_apply(tmp_json)
                if code != 0:
                    info["error"] = "Operación cancelada o fallida durante la elevación."
                    return info
                info["applied"] = True
                return info

            # Caso: ya somos admin — aplicar en línea
            _stop_guardian_task()
            _kill_processes_in_install()
            time.sleep(0.5)
            _apply_zip_to_install(local_zip)
            try:
                VERSION_FILE.write_text(latest + "\n", encoding="utf-8")
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
    try:
        payload = json.loads(payload_path.read_text(encoding="utf-8"))
        zip_path = Path(payload["zip"])
        latest = payload.get("latest", "")
        # Asegurar que el ZIP sigue existiendo (si no, abortar)
        if not zip_path.exists():
            return 3
        _stop_guardian_task()
        _kill_processes_in_install()
        time.sleep(0.5)
        _apply_zip_to_install(zip_path)
        try:
            VERSION_FILE.write_text(latest + "\n", encoding="utf-8")
        except Exception:
            pass
        _start_guardian_task()
        return 0
    except Exception:
        try:
            _start_guardian_task()
        except Exception:
            pass
        return 2

if __name__ == "__main__":
    # Modos:
    #   (1) python updater.py            -> sólo check (sin aplicar)
    #   (2) python updater.py --apply    -> aplica (eleva si hace falta)
    #   (3) python updater.py --apply-elevated <payload.json> -> uso interno
    if "--apply-elevated" in sys.argv:
        i = sys.argv.index("--apply-elevated")
        payload = Path(sys.argv[i+1]) if i+1 < len(sys.argv) else None
        if not payload:
            sys.exit(2)
        sys.exit(_apply_elevated_from_payload(payload))

    auto = "--apply" in sys.argv
    out = check_for_update(auto_apply=auto)
    print(json.dumps(out, ensure_ascii=False, indent=2))
