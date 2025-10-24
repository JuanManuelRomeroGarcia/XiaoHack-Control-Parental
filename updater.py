# updater.py — Auto-actualización desde GitHub Releases (mínimo cambios)
import json, os, sys, shutil, zipfile, tempfile, hashlib, subprocess, time
from urllib.request import urlopen, Request

OWNER = "JuanManuelRomeroGarcia"
REPO  = "XiaoHack-Control-Parental"
API_LATEST = f"https://api.github.com/repos/{OWNER}/{REPO}/releases/latest"
USER_AGENT = "XiaoHack-Updater"

# Dónde está instalada la app actualmente
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
PROGRAMDATA_DIR = r"C:\ProgramData\XiaoHack"
INSTALL_DIR = PROGRAMDATA_DIR      # carpeta raíz de instalación
VERSION_FILE = os.path.join(INSTALL_DIR, "VERSION")

# Tarea programada (nombre exacto usado por el installer)
TASK_GUARDIAN = r"XiaoHackParental\Guardian"

def read_local_version() -> str:
    try:
        with open(VERSION_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return "0.0.0"

def _http_get(url: str) -> bytes:
    req = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(req, timeout=30) as r:
        return r.read()

def get_latest_release():
    data = json.loads(_http_get(API_LATEST).decode("utf-8"))
    tag = (data.get("tag_name") or data.get("name") or "").lstrip("v").strip()
    assets = data.get("assets", [])
    # Buscamos el ZIP principal y un manifest opcional
    zip_asset = None
    manifest_asset = None
    for a in assets:
        n = a.get("name","")
        if n.endswith(".zip") and "Control" in n:
            zip_asset = a
        if n == "manifest.json":
            manifest_asset = a
    return tag, zip_asset, manifest_asset

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1<<20), b""):
            h.update(chunk)
    return h.hexdigest()

def stop_guardian_task():
    # Detiene la tarea programada para poder reemplazar ficheros
    try:
        subprocess.run(["schtasks", "/End", "/TN", TASK_GUARDIAN], check=False, capture_output=True)
    except Exception:
        pass

def start_guardian_task():
    try:
        subprocess.run(["schtasks", "/Run", "/TN", TASK_GUARDIAN], check=False, capture_output=True)
    except Exception:
        pass

def replace_tree(src_dir: str, dst_dir: str):
    # Copia segura: primero a carpeta temporal, luego swap
    backup_dir = dst_dir + ".bak"
    if os.path.exists(backup_dir):
        shutil.rmtree(backup_dir, ignore_errors=True)
    if os.path.exists(dst_dir):
        os.replace(dst_dir, backup_dir)
    shutil.copytree(src_dir, dst_dir)
    shutil.rmtree(backup_dir, ignore_errors=True)

def apply_zip(zip_path: str):
    with tempfile.TemporaryDirectory() as tmp:
        with zipfile.ZipFile(zip_path, "r") as z:
            z.extractall(tmp)
        # Si el zip ya contiene la estructura (INSTALL_DIR), copia pieza a pieza
        # Mantenemos STATE/CONFIG de ProgramData si existiera (ajústalo si tus rutas cambian)
        for name in os.listdir(tmp):
            src = os.path.join(tmp, name)
            dst = os.path.join(INSTALL_DIR, name)
            if os.path.isdir(src):
                if name.lower() in ("logs",):
                    continue
                if os.path.exists(dst):
                    shutil.rmtree(dst, ignore_errors=True)
                shutil.copytree(src, dst)
            else:
                shutil.copy2(src, dst)

def verify_with_manifest(local_zip: str, manifest_bytes: bytes) -> bool:
    try:
        m = json.loads(manifest_bytes.decode("utf-8"))
        # Toma el sha256 del asset cuyo nombre coincide
        local_name = os.path.basename(local_zip)
        for a in m.get("assets", []):
            if a.get("name") == local_name:
                want = a.get("sha256")
                have = sha256_file(local_zip)
                return (want and have.lower() == want.lower())
    except Exception:
        pass
    return False

def check_for_update(auto_apply=False) -> dict:
    current = read_local_version()
    latest, zip_asset, manifest_asset = get_latest_release()
    info = {"current": current, "latest": latest, "update_available": False, "applied": False, "error": None}

    if not latest:
        info["error"] = "No se pudo leer la versión de GitHub."
        return info

    def ver_tuple(v):
        return tuple(int(x) for x in v.split(".") if x.isdigit())

    if ver_tuple(latest) <= ver_tuple(current):
        return info  # ya estamos al día

    info["update_available"] = True
    if not auto_apply or not zip_asset:
        return info

    # Descargar ZIP (y manifest si existe)
    zip_url = zip_asset.get("browser_download_url")
    if not zip_url:
        info["error"] = "Asset ZIP no encontrado en release."
        return info

    try:
        with tempfile.TemporaryDirectory() as tmp:
            zip_path = os.path.join(tmp, zip_asset["name"])
            with open(zip_path, "wb") as f:
                f.write(_http_get(zip_url))

            if manifest_asset:
                man_url = manifest_asset.get("browser_download_url")
                if man_url:
                    ok = verify_with_manifest(zip_path, _http_get(man_url))
                    if not ok:
                        info["error"] = "SHA256 no coincide con manifest."
                        return info

            stop_guardian_task()
            time.sleep(1.0)
            apply_zip(zip_path)
            # escribe VERSION
            with open(VERSION_FILE, "w", encoding="utf-8") as vf:
                vf.write(latest + "\n")
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
