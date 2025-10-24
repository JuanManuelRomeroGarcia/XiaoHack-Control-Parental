# updater.py — XiaoHack Control Parental (simple, sin manifest, sin git en clientes)
import json, os, sys, shutil, zipfile, tempfile, subprocess, time, hashlib
from urllib.request import urlopen, Request

OWNER = "JuanManuelRomeroGarcia"
REPO  = "XiaoHack-Control-Parental"
API_LATEST = f"https://api.github.com/repos/{OWNER}/{REPO}/releases/latest"
USER_AGENT = "XiaoHack-Updater"

BASE_DIR    = os.path.abspath(os.path.dirname(__file__))  # carpeta instalada
INSTALL_DIR = BASE_DIR
VERSION_FILE = os.path.join(INSTALL_DIR, "VERSION")
TASK_GUARDIAN = r"XiaoHackParental\Guardian"

# Nombres de ZIP aceptados (por orden de preferencia)
def candidate_zip_names(tag: str):
    # preferidos: sin dev ni git—solo runtime
    return [
        f"XiaoHackParental-{tag}-runtime.zip",
        f"XiaoHack-Control-Parental-{tag}-runtime.zip",
        f"XiaoHackParental-{tag}.zip",
        f"XiaoHack-Control-Parental-{tag}.zip",
    ]

# Carpetas/archivos a NO copiar nunca al cliente
EXCLUDE_DIRS = {".git", ".github", "test", "tests", "__pycache__", ".venv", "venv", "dist", "build"}
EXCLUDE_FILESUFFIX = {".md", ".MD", ".markdown", ".rst"}
EXCLUDE_FILES = {".gitignore", ".gitattributes", ".editorconfig", "README", "README.md", "CHANGELOG.md", "LICENSE"}

def read_local_version():
    try:
        with open(VERSION_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return "0.0.0"

def _http_get(url: str) -> bytes:
    req = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(req, timeout=60) as r:
        return r.read()

def _ver_tuple(v: str):
    parts = [int(x) for x in v.split(".") if x.isdigit()]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])

def get_latest_release():
    data = json.loads(_http_get(API_LATEST).decode("utf-8"))
    tag = (data.get("tag_name") or data.get("name") or "").lstrip("v").strip()
    assets = data.get("assets", [])
    # Elegir ZIP por nombre exacto preferido
    wanted = set(candidate_zip_names(tag)) if tag else set()
    zip_asset = None
    by_name = {a.get("name",""): a for a in assets}
    for name in wanted:
        if name in by_name:
            zip_asset = by_name[name]
            break
    # Fallback: si no coinciden nombres, usar el ÚNICO .zip si solo hay uno
    if not zip_asset:
        zips = [a for a in assets if (a.get("name","").lower().endswith(".zip"))]
        if len(zips) == 1:
            zip_asset = zips[0]
    return tag, zip_asset

def stop_guardian_task():
    try:
        subprocess.run(["schtasks", "/End", "/TN", TASK_GUARDIAN], check=False, capture_output=True)
    except Exception:
        pass

def start_guardian_task():
    try:
        subprocess.run(["schtasks", "/Run", "/TN", TASK_GUARDIAN], check=False, capture_output=True)
    except Exception:
        pass

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

def apply_zip(zip_path: str):
    with tempfile.TemporaryDirectory() as tmp:
        with zipfile.ZipFile(zip_path, "r") as z:
            z.extractall(tmp)
        # Copiar sobre instalación filtrando basura de dev
        for root, dirs, files in os.walk(tmp):
            # filtra dirs in-place (para que os.walk no entre)
            dirs[:] = [d for d in dirs if not _should_skip(os.path.join(root, d), True)]
            for f in files:
                src = os.path.join(root, f)
                if _should_skip(src, False):
                    continue
                # ruta relativa dentro del zip
                rel = os.path.relpath(src, tmp)
                dst = os.path.join(INSTALL_DIR, rel)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copy2(src, dst)

def check_for_update(auto_apply=False) -> dict:
    current = read_local_version()
    latest, zip_asset = get_latest_release()
    info = {"current": current, "latest": latest, "update_available": False, "applied": False, "error": None}

    if not latest:
        info["error"] = "No se pudo leer la versión de GitHub."
        return info

    if _ver_tuple(latest) <= _ver_tuple(current):
        return info  # ya al día

    info["update_available"] = True
    if not auto_apply:
        return info

    if not zip_asset:
        info["error"] = ("No se encontró un ZIP de runtime en el release. "
                         "Sugerido: XiaoHackParental-<version>-runtime.zip")
        return info

    zip_url = zip_asset.get("browser_download_url")
    if not zip_url:
        info["error"] = "El asset ZIP no tiene URL de descarga."
        return info

    try:
        with tempfile.TemporaryDirectory() as tmp:
            local_zip = os.path.join(tmp, zip_asset["name"])
            with open(local_zip, "wb") as f:
                f.write(_http_get(zip_url))

            stop_guardian_task()
            time.sleep(1.0)
            apply_zip(local_zip)
            # Asegura VERSION
            try:
                with open(VERSION_FILE, "w", encoding="utf-8") as vf:
                    vf.write(latest + "\n")
            except Exception:
                pass
            start_guardian_task()
            info["applied"] = True
            return info
    except Exception as e:
        info["error"] = f"Fallo al actualizar: {e}"
        start_guardian_task()
        return info

if __name__ == "__main__":
    auto = "--apply" in sys.argv
    out = check_for_update(auto_apply=auto)
    print(json.dumps(out, ensure_ascii=False, indent=2))
