# app/updater.py — XiaoHack Control Parental (portable)
# - Comprueba última versión en GitHub y (opcional) aplica update desde ZIP runtime
# - Elevación UAC solo al aplicar (si faltan permisos)
# - Detiene/relanza tarea SYSTEM del Guardian de forma segura
# - Diseñado para instalación con Python embebido en INSTALL_DIR\py312
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

# --- bootstrap para imports relativos cuando se ejecuta por ruta --------------
_ROOT = Path(__file__).resolve().parents[1]  # ...\XiaoHackParental
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from app.logs import get_logger  # noqa: E402

try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

log = get_logger("gui.Updater")

# ---------------- Rutas base / ficheros de versión ----------------------------
BASE_DIR    = Path(__file__).resolve().parent
INSTALL_DIR = _ROOT
VER_JSON    = INSTALL_DIR / "VERSION.json"
VER_TXT     = INSTALL_DIR / "VERSION"

# Python portable preferido para relanzar GUI
def _portable_pythonw() -> Path:
    pyw = INSTALL_DIR / "py312" / "pythonw.exe"
    if pyw.exists():
        return pyw
    py = INSTALL_DIR / "py312" / "python.exe"
    return py if py.exists() else Path(sys.executable)

# Tarea programada del servicio guardian (SYSTEM)
TASK_GUARDIAN = r"XiaoHackParental\Guardian"

# ---------------- Config GitHub (con overrides por entorno) -------------------
OWNER = os.getenv("XH_GH_OWNER", "JuanManuelRomeroGarcia")
REPO  = os.getenv("XH_GH_REPO",  "XiaoHack-Control-Parental")
API_LATEST = f"https://api.github.com/repos/{OWNER}/{REPO}/releases/latest"
HTTP_TIMEOUT = float(os.getenv("XH_HTTP_TIMEOUT", "60"))

# ---------------- Utilidades de texto / versión --------------------------------
def _read_text_clean(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig").strip().lstrip("\ufeff")

def _write_text_utf8(path: Path, text: str) -> None:
    path.write_text((text or "").rstrip() + "\n", encoding="utf-8")

def _normalize_version_str(v: str) -> str:
    v = (v or "").strip()
    if v.lower().startswith("v"):
        v = v[1:].strip()
    return v

def _ver_tuple(v: str):
    parts = []
    for tok in v.replace("-", ".").split("."):
        try:
            parts.append(int(tok))
        except Exception:
            break
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])

# ---------------- Log auxiliar persistente ------------------------------------
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

def _write_result_json(ok: bool, latest: str, mode: str) -> None:
    try:
        p = _apply_log_path().parent / "updater_result.json"
        data = {"ok": ok, "latest": latest, "mode": mode, "ts": time.strftime("%Y-%m-%d %H:%M:%S")}
        p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        _apply_log(f"RESULT written: {p}")
    except Exception as e:
        _apply_log(f"RESULT write failed: {e}")

def _fail(code: int, message: str, exc: Exception | None = None) -> NoReturn:
    _apply_log(f"ERROR {code}: {message}")
    if exc:
        _apply_log("TRACEBACK:\n" + "".join(traceback.format_exception(exc)))
    print(message, file=sys.stdout, flush=True)
    raise SystemExit(code)

# ---------------- Versión local / remota --------------------------------------
def read_local_version() -> str:
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
    data = {"version": _normalize_version_str(new_version)}
    _write_text_utf8(VER_JSON, json.dumps(data, ensure_ascii=False))

def _local_version_for_ua() -> str:
    try:
        return read_local_version()
    except Exception:
        return "0.0.0"

def _build_user_agent() -> str:
    return f"XiaoHack-Updater/{_local_version_for_ua()} (+https://github.com/{OWNER}/{REPO})"

def _http_get(url: str) -> bytes:
    headers = {
        "User-Agent": _build_user_agent(),
        "Accept": "application/vnd.github+json",
    }
    token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = Request(url, headers=headers)
    try:
        with urlopen(req, timeout=HTTP_TIMEOUT) as r:
            return r.read()
    except HTTPError as e:
        if e.code in (403, 429):
            raise RuntimeError(f"GitHub rate limit o acceso denegado ({e.code}).")
        raise RuntimeError(f"HTTP {e.code} en {url}: {e.reason}")
    except URLError as e:
        raise RuntimeError(f"Error de red para {url}: {e.reason}")
    except Exception as e:
        raise RuntimeError(f"HTTP GET falló para {url}: {type(e).__name__}: {e}")

def get_latest_release():
    try:
        data = json.loads(_http_get(API_LATEST).decode("utf-8"))
        tag = _normalize_version_str((data.get("tag_name") or data.get("name") or ""))
        assets = data.get("assets", []) or []
        # Elegimos cualquier .zip si solo hay uno; si hay varios, preferimos nombres típicos
        preferred = {
            f"XiaoHackParental-{tag}-runtime.zip",
            f"XiaoHack-Control-Parental-{tag}-runtime.zip",
            f"XiaoHackParental-{tag}.zip",
            f"XiaoHack-Control-Parental-{tag}.zip",
        } if tag else set()
        by_name = {a.get("name", ""): a for a in assets}
        zip_asset = None
        for name in preferred:
            if name in by_name:
                zip_asset = by_name[name]
                break
        if not zip_asset:
            zips = [a for a in assets if a.get("name", "").lower().endswith(".zip")]
            if len(zips) == 1:
                zip_asset = zips[0]
        return (tag or None), zip_asset
    except Exception as e:
        log.error("Error obteniendo última versión (releases): %s", e, exc_info=True)
        return None, None

def get_latest_version_fallback(owner: str, repo: str, branch: str = "main"):
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
    return None, (last_err or "No se pudo leer VERSION")

def resolve_latest_version(owner: str, repo: str, branch: str = "main"):
    tag, _ = get_latest_release()
    if tag:
        return tag, None
    latest, err = get_latest_version_fallback(owner, repo, branch)
    if latest:
        return latest, None
    return None, (err or "No se pudo obtener la versión de GitHub")

# ---------------- Filtros de copia --------------------------------------------
EXCLUDE_DIRS = {".git", ".github", "test", "tests", "__pycache__", ".venv", "venv", "dist", "build", "node_modules"}
EXCLUDE_FILESUFFIX = {".md", ".MD", ".markdown", ".rst"}
EXCLUDE_FILES = {".gitignore", ".gitattributes", ".editorconfig", "README", "README.md", "CHANGELOG.md", "LICENSE"}

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

# ---------------- Gestión de tareas/Procesos ----------------------------------
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
    base = str(INSTALL_DIR).lower()
    me = os.getpid()
    try:
        myexe = str(Path(sys.executable).resolve())
    except Exception:
        myexe = sys.executable

    _apply_log(f"KILL in install dir: base={base} pid_me={me} exe_me={myexe}")

    base_ps  = base.replace("'", "''")
    myexe_ps = myexe.lower().replace("'", "''")

    allow_block = ""
    if extra_names:
        allow = ",".join([f"'{n.lower()}'" for n in extra_names])
        allow_block = f"$allow=@({allow}); if ($allow -contains $name) {{ return }}"

    ps = rf"""
$base = '{base_ps}'
$me   = {me}
Get-CimInstance Win32_Process | ForEach-Object {{
  try {{
    $exe = $_.ExecutablePath
    if (-not $exe) {{ return }}
    $exel = $exe.ToLower()
    if ($exel.StartsWith($base)) {{
      if ($_.ProcessId -eq $me) {{ return }}
      if ($exel -eq '{myexe_ps}') {{ return }}
      $name = ($_.Name); if ($name) {{ $name = $name.ToLower() }} else {{ $name = '' }}
      {allow_block}
      Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop
      Write-Output ('KILLED ' + $_.ProcessId + ' ' + $exe)
    }}
  }} catch {{ }}
}}
"""
    cp = subprocess.run(["PowerShell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
                        capture_output=True, text=True, creationflags=0x08000000)
    if cp.stdout:
        for line in cp.stdout.splitlines():
            _apply_log(line.strip())
    if cp.stderr:
        _apply_log("KILL STDERR: " + cp.stderr.strip())

def _kill_gui_explicit(gui_pid: int | None, gui_exe: str | None) -> None:
    try:
        pid = int(gui_pid) if gui_pid is not None else 0
    except Exception:
        pid = 0
    exe = (gui_exe or "").strip().lower()

    _apply_log(f"KILL GUI explicit: pid={pid} exe={exe}")

    exe_ps = exe.replace("'", "''")
    ps = rf"""
$pidTarget = {pid}
$exeTarget = '{exe_ps}'
try {{
  if ($pidTarget -gt 0) {{
    try {{ Stop-Process -Id $pidTarget -Force -ErrorAction Stop; Write-Output ('KILLED_GUI_PID ' + $pidTarget) }} catch {{}}
    try {{ Wait-Process -Id $pidTarget -Timeout 7 -ErrorAction SilentlyContinue }} catch {{}}
  }}
  Get-CimInstance Win32_Process | ForEach-Object {{
    try {{
      $exe = $_.ExecutablePath
      if (-not $exe) {{ return }}
      $exel = $exe.ToLower()
      if ($exeTarget -and $exel -eq $exeTarget) {{
        Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop
        Write-Output ('KILLED_GUI_EXE ' + $_.ProcessId + ' ' + $exe)
        return
      }}
      $cmd = ($_.CommandLine)
      if ($cmd) {{
        $cl = $cmd.ToLower()
        if ($cl.Contains('run.py') -or ($cl.Contains('--xh-role') -and $cl.Contains('panel'))) {{
          Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop
          Write-Output ('KILLED_GUI_CMD ' + $_.ProcessId + ' ' + $cmd)
        }}
      }}
    }} catch {{}}
  }}
}} catch {{ }}
"""
    cp = subprocess.run(["PowerShell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
                        capture_output=True, text=True, creationflags=0x08000000)
    if cp.stdout:
        for line in cp.stdout.splitlines():
            _apply_log(line.strip())
    if cp.stderr:
        _apply_log("KILL GUI STDERR: " + cp.stderr.strip())

# ---------------- Aplicación del ZIP ------------------------------------------
def _find_zip_root(tmp_dir: Path) -> Path:
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

        _cleanup_orphans_from_install(root)

def _cleanup_orphans_from_install(zip_root: Path):
    """
    Limpia archivos huérfanos si XH_CLEAN_ORPHANS=1.
    Nunca borra: logs/, *.log, installed.json
    """
    if os.getenv("XH_CLEAN_ORPHANS", "0") != "1":
        return
    keep_dirs = {"logs"}
    keep_files = {"installed.json"}

    wanted = set()
    for src_dir, dirs, files in os.walk(zip_root):
        rel_dir = Path(src_dir).relative_to(zip_root)
        for f in files:
            if _should_skip(str(Path(src_dir) / f), False):
                continue
            wanted.add((rel_dir / f).as_posix())

    for cur_dir, dirs, files in os.walk(INSTALL_DIR):
        dirs[:] = [d for d in dirs if d not in keep_dirs]
        for f in files:
            if f in keep_files:
                continue
            p = Path(cur_dir) / f
            rel = p.relative_to(INSTALL_DIR).as_posix()
            if rel not in wanted and not _should_skip(str(p), False):
                try:
                    p.unlink()
                except Exception:
                    pass

# ---------------- Elevación UAC y relanzado GUI -------------------------------
def _is_admin() -> bool:
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def _build_relaunch_plan_from_env() -> dict:
    exe = os.getenv("XH_GUI_EXE") or str(_portable_pythonw())
    script = os.getenv("XH_GUI_SCRIPT") or ""
    try:
        args = json.loads(os.getenv("XH_GUI_ARGS_JSON") or "[]")
    except Exception:
        args = []
    return {"exe": exe, "script": script, "args": args}

def _build_relaunch_plan_from_payload(payload: dict) -> dict:
    exe = payload.get("gui_exe") or str(_portable_pythonw())
    script = payload.get("gui_script") or ""
    argsj = payload.get("gui_args_json") or "[]"
    try:
        args = json.loads(argsj)
    except Exception:
        args = []
    return {"exe": exe, "script": script, "args": args}

def _relaunch_panel(plan: dict | None = None) -> bool:
    try:
        if plan is None:
            plan = _build_relaunch_plan_from_env()

        exe = Path(plan.get("exe") or _portable_pythonw())
        script = plan.get("script") or ""
        args = plan.get("args") or []

        if script and Path(script).exists():
            cmd = [str(exe), script] + list(args)
        else:
            # Fallback robusto: módulo principal de la GUI
            cmd = [str(exe), "-m", "xiao_gui.app"]

        _apply_log("RELAUNCH panel: " + " ".join(map(str, cmd)))
        subprocess.Popen(cmd, cwd=str(INSTALL_DIR), creationflags=0x08000000)
        return True
    except Exception as e:
        _apply_log(f"RELAUNCH failed: {e}")
        return False

# ---------------- Comandos públicos -------------------------------------------
def check_for_update(auto_apply=False) -> dict:
    info = {"current": read_local_version(), "latest": None, "update_available": False, "applied": False, "error": None}

    latest, err = resolve_latest_version(OWNER, REPO, branch="main")
    if not latest:
        info["error"] = f"No se pudo obtener la versión de GitHub: {err}"
        return info

    info["latest"] = latest
    if _ver_tuple(latest) <= _ver_tuple(info["current"]):
        return info

    info["update_available"] = True
    if not auto_apply:
        return info

    tag, zip_asset = get_latest_release()
    if not tag or _normalize_version_str(tag) != _normalize_version_str(latest):
        info["error"] = ("No se encontró un release con ZIP para esta versión. "
                         "Publica el asset runtime.")
        return info
    if not zip_asset:
        info["error"] = "No se encontró un ZIP de runtime en el release."
        return info

    zip_url  = zip_asset.get("browser_download_url")
    zip_name = zip_asset.get("name", "update.zip")
    if not zip_url:
        info["error"] = "El asset ZIP no tiene URL de descarga."
        return info

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

def _elevate_and_apply(tmp_json: Path) -> int:
    _apply_log(f"Elevando para aplicar. Payload: {tmp_json}")
    py  = os.path.normpath(str(_portable_pythonw()))
    exe = py.replace("'", "''")
    script  = str(Path(__file__).resolve()).replace("'", "''")
    payload = str(tmp_json).replace("'", "''")

    ps_cmd = (
        "$argsList=@('{script}','--apply-elevated','{payload}');"
        "$p=Start-Process -Verb RunAs -WindowStyle Hidden -FilePath '{exe}' "
        "-ArgumentList $argsList -PassThru -Wait;"
        "exit $p.ExitCode"
    ).format(exe=exe, script=script, payload=payload)

    cp = subprocess.run(["PowerShell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
                        text=True, capture_output=True, creationflags=0x08000000)
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

        latest, err = resolve_latest_version(OWNER, REPO, branch="main")
        if not latest:
            _fail(15, f"No se pudo obtener la versión de GitHub: {err}")

        _apply_log(f"Latest en GitHub: {latest}")
        if _ver_tuple(latest) <= _ver_tuple(current):
            msg = f"Ya está actualizado (local={current}, latest={latest})."
            _apply_log(msg)
            print(msg, flush=True)
            _write_result_json(True, latest, mode="noop")
            return 0

        tag, zip_asset = get_latest_release()
        if not tag or _normalize_version_str(tag) != _normalize_version_str(latest):
            _fail(15, "No se encontró un release con ZIP para esta versión.")
        if not zip_asset:
            _fail(15, "No se encontró un ZIP de runtime en el release.")

        zip_url  = zip_asset.get("browser_download_url")
        zip_name = zip_asset.get("name", "update.zip")
        if not zip_url:
            _fail(15, "El asset ZIP del release no tiene browser_download_url.")

        manual = (os.getenv("XH_MANUAL_RELAUNCH") == "1")

        with tempfile.TemporaryDirectory() as td:
            td_p = Path(td)
            local_zip = td_p / zip_name
            _apply_log(f"Descargando ZIP: {zip_url}")
            local_zip.write_bytes(_http_get(zip_url))
            _apply_log(f"ZIP descargado: {local_zip} ({local_zip.stat().st_size} bytes)")

            can_write = os.access(INSTALL_DIR, os.W_OK)
            if not can_write or not _is_admin():
                payload = {
                    "zip": str(local_zip),
                    "latest": latest,
                    "install_dir": str(INSTALL_DIR),
                    "gui_pid": int(os.getenv("XH_GUI_PID") or "0"),
                    "gui_exe": os.getenv("XH_GUI_EXE"),
                    "gui_script": os.getenv("XH_GUI_SCRIPT"),
                    "gui_args_json": os.getenv("XH_GUI_ARGS_JSON"),
                    "manual": 1 if manual else 0,
                }
                tmp_json = td_p / "apply.json"
                tmp_json.write_text(json.dumps(payload), encoding="utf-8")
                _apply_log(f"Sin permisos. Elevando con payload: {tmp_json}")
                code = _elevate_and_apply(tmp_json)
                if code != 0:
                    _fail(code or 15, f"Operación cancelada o fallida durante la elevación (rc={code}).")
                _apply_log("OK: actualización aplicada por proceso elevado (hijo).")
                print("OK: actualización aplicada (elevado).", flush=True)
                return 0

            # Aplicación en línea (somos admin)
            _apply_log("Parando guardian y aplicando ZIP en línea (somos admin).")
            _stop_guardian_task()

            if not manual:
                _kill_gui_explicit(os.getenv("XH_GUI_PID"), os.getenv("XH_GUI_EXE"))

            _kill_processes_in_install()
            time.sleep(0.5)
            _apply_zip_to_install(local_zip)
            try:
                write_local_version(latest)
            except Exception as e:
                _apply_log(f"WARNING: no pude escribir VERSION.json: {e}")
            _start_guardian_task()

            _write_result_json(True, latest, mode=("manual" if manual else "inline"))

            if manual:
                _apply_log("Manual mode: no relaunch/kill; devuelve control a la GUI.")
                print("OK: actualización aplicada (manual).", flush=True)
                return 0

            plan = _build_relaunch_plan_from_env()
            _ok = _relaunch_panel(plan)
            _apply_log("OK: actualización aplicada (en línea). Relaunch=" + ("yes" if _ok else "no"))
            print("OK: actualización aplicada.", flush=True)
            return 0

    except SystemExit:
        raise
    except Exception as e:
        _fail(15, f"Fallo inesperado en --apply: {e}", e)

# ---------------- Entrada CLI --------------------------------------------------
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(prog="app.updater")
    parser.add_argument("--check", action="store_true", help="Solo comprobar (JSON)")
    parser.add_argument("--apply", action="store_true", help="Aplicar actualización (elevar si hace falta)")
    parser.add_argument("--apply-elevated", metavar="PAYLOAD", help="Uso interno (proceso elevado)")
    args = parser.parse_args()

    if args.apply_elevated:
        # Reutilizamos la misma lógica inline pero con payload (ya lo hace cmd_apply elevando)
        payload_path = Path(args.apply_elevated)
        # Implementación simple: leemos y ejecutamos como en cmd_apply pero elevado
        # Para no duplicar demasiada lógica, reusamos _elevate_and_apply al revés:
        # aquí simplemente cargamos el JSON y aplicamos en caliente (somos admin).
        try:
            data = json.loads(payload_path.read_text(encoding="utf-8"))
            # Mínimo: zip + latest
            zip_path = Path(data["zip"])
            latest = data.get("latest", "")
            manual = bool(data.get("manual"))
            _apply_log(f"BEGIN --apply-elevated payload={payload_path}")
            _stop_guardian_task()
            if not manual:
                _kill_gui_explicit(data.get("gui_pid", 0) or 0, data.get("gui_exe", ""))
            _kill_processes_in_install()
            time.sleep(0.5)
            _apply_zip_to_install(zip_path)
            try:
                write_local_version(latest)
            except Exception as ex:
                _apply_log(f"WARNING: no pude escribir VERSION.json elevado: {ex}")
            _start_guardian_task()
            _write_result_json(True, latest, mode=("manual" if manual else "elevated"))
            if not manual:
                _relaunch_panel(_build_relaunch_plan_from_payload(data))
            sys.exit(0)
        except Exception as ex:
            try:
                _start_guardian_task()
            except Exception:
                pass
            _fail(2, f"Fallo en --apply-elevated: {ex}", ex)

    if args.apply:
        sys.exit(cmd_apply())
    sys.exit(cmd_check())
