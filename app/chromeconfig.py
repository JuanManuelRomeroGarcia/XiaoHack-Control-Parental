# chromeconfig.py — Políticas de DoH para Google Chrome/Chromium
from __future__ import annotations
import json
import winreg
from utils.cache import memo_ttl
from utils.winproc import _ps
from app.logs import get_logger
log = get_logger("chrome")

# Ramas de políticas
HKCU = r"HKCU:\Software\Policies\Google\Chrome"
HKLM = r"HKLM:\SOFTWARE\Policies\Google\Chrome"

# Proveedor: CleanBrowsing Family (datos que compartiste)
CLEANBROWSING = {
    "name": "CleanBrowsing Family",
    "ipv4": ["185.228.168.168", "185.228.169.168"],
    "ipv6": ["2a0d:2a00:1::", "2a0d:2a00:2::"],
    "doh":  "https://doh.cleanbrowsing.org/doh/family-filter/",
    "dot":  "family-filter-dns.cleanbrowsing.org",
}

# ---------------------------------------------------------------------
# Escritura de políticas Chrome DoH
# ---------------------------------------------------------------------
def _set_pol(mode: str | None, template: str | None, scope: str) -> tuple[bool, str]:
    """
    mode: "off" | "secure" | "automatic" | None  (None -> borra DnsOverHttpsMode)
    template: url o None (None -> borra DnsOverHttpsTemplates)
    scope: "HKCU" | "HKLM" | "BOTH"
    Además, ajusta BuiltInDnsClientEnabled:
      - secure/automatic -> 1
      - off              -> 0
      - None             -> elimina (valor por defecto)
    """
    paths: list[str] = []
    if scope in ("HKCU", "BOTH"):
        paths.append(HKCU)
    if scope in ("HKLM", "BOTH"):
        paths.append(HKLM)
    if not paths:
        log.error("Scope inválido en _set_pol: %s", scope)
        return False, "scope inválido"

    ps = []
    for p in paths:
        ps.append(f'New-Item -Path "{p}" -Force | Out-Null')
        # DnsOverHttpsMode
        if mode is None:
            ps.append(f'Remove-ItemProperty -Path "{p}" -Name "DnsOverHttpsMode" -ErrorAction SilentlyContinue')
        else:
            ps.append(f'Set-ItemProperty -Path "{p}" -Name "DnsOverHttpsMode" -Type String -Value "{mode}"')
        # DnsOverHttpsTemplates
        if template is None:
            ps.append(f'Remove-ItemProperty -Path "{p}" -Name "DnsOverHttpsTemplates" -ErrorAction SilentlyContinue')
        else:
            ps.append(f'Set-ItemProperty -Path "{p}" -Name "DnsOverHttpsTemplates" -Type String -Value "{template}"')
        # BuiltInDnsClientEnabled (Chrome la respeta)
        if mode in ("secure", "automatic"):
            ps.append(f'Set-ItemProperty -Path "{p}" -Name "BuiltInDnsClientEnabled" -Type DWord -Value 1')
        elif mode == "off":
            ps.append(f'Set-ItemProperty -Path "{p}" -Name "BuiltInDnsClientEnabled" -Type DWord -Value 0')
        else:
            ps.append(f'Remove-ItemProperty -Path "{p}" -Name "BuiltInDnsClientEnabled" -ErrorAction SilentlyContinue')

    ps.append('Write-Output "OK"')

    rc, out, err = _ps("\n".join(ps))
    text = (out or err or "").strip()
    ok = text.startswith("OK")
    if ok:
        log.info("Chrome DoH cambiado → mode=%s scope=%s template=%s", mode or "unset", scope, template or "—")
        return True, "OK"
    else:
        msg = f"[PS rc={rc}] {text or '(sin salida)'}"
        log.warning("Error al aplicar políticas Chrome DoH (mode=%s scope=%s): %s", mode, scope, msg)
        return False, msg

# --- lector crudo desde winreg ------------------------------------------------
def _read_policy_winreg() -> dict | None:
    """
    Devuelve el primer bloque encontrado (HKCU preferente, luego HKLM).
    Estructura: {"scope":"HKCU|HKLM","mode":"off|secure|automatic|unset","templates":"...", "builtIn":0/1/None}
    """
    def _read(root, path, scope):
        try:
            for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
                try:
                    with winreg.OpenKey(root, path, 0, winreg.KEY_READ | view) as k:
                        def _val(name):
                            try:
                                v, _ = winreg.QueryValueEx(k, name)
                                return v
                            except FileNotFoundError:
                                return None
                        mode = _val("DnsOverHttpsMode")
                        tmpl = _val("DnsOverHttpsTemplates")
                        built = _val("BuiltInDnsClientEnabled")
                        if mode is None and tmpl is None and built is None:
                            continue
                        return {
                            "scope": scope,
                            "mode": str(mode) if mode else "unset",
                            "templates": str(tmpl) if tmpl else "",
                            "builtIn": int(built) if built is not None else None,
                        }
                except FileNotFoundError:
                    continue
        except Exception as e:
            log.debug("winreg read error (%s): %s", scope, e)
        return None

    val = _read(winreg.HKEY_CURRENT_USER, r"Software\Policies\Google\Chrome", "HKCU")
    if val:
        return val
    val = _read(winreg.HKEY_LOCAL_MACHINE, r"Software\Policies\Google\Chrome", "HKLM")
    if val:
        return val
    return None

# --- fallback PowerShell -------------------------------------------------------
def _read_policy_powershell() -> dict:
    ps = r'''
function Read-Pol($root) {
  $path = "$root\Software\Policies\Google\Chrome"
  if (Test-Path $path) {
    $p = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
    if ($p) {
      $mode = $p.DnsOverHttpsMode
      $tmpl = $p.DnsOverHttpsTemplates
      $dnscli = $p.BuiltInDnsClientEnabled
      return @{
        scope = $root.Replace("HKEY_CURRENT_USER","HKCU").Replace("HKEY_LOCAL_MACHINE","HKLM")
        mode = if ($mode) { [string]$mode } else { "unset" }
        templates = if ($tmpl) { [string]$tmpl } else { "" }
        builtIn = if ($dnscli -ne $null) { [int]$dnscli } else { $null }
      } | ConvertTo-Json -Compress
    }
  }
  return $null
}
$hcu = Read-Pol "HKEY_CURRENT_USER"
if ($hcu) { $hcu; exit 0 }
$hlm = Read-Pol "HKEY_LOCAL_MACHINE"
if ($hlm) { $hlm; exit 0 }
@{ scope = "NONE"; mode = "unset"; templates = ""; builtIn = $null } | ConvertTo-Json -Compress
'''
    rc, out, err = _ps(ps)
    raw = (out or "").strip()
    if rc != 0:
        log.warning("PS read Chrome DoH rc=%s: %s", rc, err)
    try:
        return json.loads(raw) if raw else {"scope":"NONE","mode":"unset","templates":"","builtIn":None}
    except Exception as e:
        log.error("PS JSON parse error: %s", e)
        return {"scope":"NONE","mode":"unset","templates":"","builtIn":None}

# --- API público --------------------------------------------------------------
def get_chrome_doh_status(force: bool = False) -> dict:
    """
    Lee políticas de Chrome (HKCU→HKLM). Si force=True, salta la caché.
    """
    def _fetch():
        data = _read_policy_winreg()
        if data:
            log.debug("Chrome DoH (winreg): %s", data)
            return data
        data = _read_policy_powershell()
        log.debug("Chrome DoH (PS): %s", data)
        return data

    if force:
        return _fetch()
    return memo_ttl("chrome_doh_status", 10, _fetch)

def summarize_chrome_status(d: dict) -> str:
    """
    Convierte el dict de estado en texto claro para la UI (con emojis).
    """
    if not d:
        return "⚪ No configurado"

    scope = d.get("scope", "NONE")
    mode = (d.get("mode") or "unset").lower()
    tmpl = (d.get("templates") or "").lower()

    provider = "personalizado"
    if "cleanbrowsing" in tmpl:
        provider = "CleanBrowsing Family"
    elif "cloudflare" in tmpl:
        provider = "Cloudflare Family"
    elif "adguard" in tmpl:
        provider = "AdGuard Family"

    if scope == "NONE" or mode == "unset":
        return "⚪ No configurado (sin política)"
    if mode == "secure":
        return f"🟢 Protección familiar activa ({provider})"
    if mode == "off":
        return "🔴 DoH desactivado"
    if mode == "automatic":
        return "🟡 DoH automático"
    return f"⚙️ Estado desconocido ({mode})"

def summarize_chrome_status_plain(d: dict) -> tuple[str, str]:
    """
    Devuelve (texto, kind) para UI sin emojis: kind ∈ {'ok','off','auto','unset','unknown'}
    """
    if not d or d.get("scope") == "NONE":
        return "No configurado (sin política)", "unset"

    mode = (d.get("mode") or "unset").lower()
    tmpl = (d.get("templates") or "").lower()

    if "cleanbrowsing" in tmpl:
        provider = "CleanBrowsing Family"
    elif "cloudflare" in tmpl:
        provider = "Cloudflare Family"
    elif "adguard" in tmpl:
        provider = "AdGuard Family"
    else:
        provider = "personalizado"

    if mode == "secure":
        return f"Protección familiar activa ({provider})", "ok"
    if mode == "off":
        return "DoH desactivado", "off"
    if mode == "automatic":
        return "DoH automático", "auto"
    if mode == "unset":
        return "No configurado (sin política)", "unset"
    return f"Estado desconocido ({mode})", "unknown"

# Wrappers de conveniencia
def set_chrome_doh_off(scope: str = "BOTH") -> tuple[bool, str]:
    """Desactiva DNS-over-HTTPS en Chrome."""
    log.debug("Desactivando DoH en Chrome (scope=%s)", scope)
    return _set_pol(mode="off", template=None, scope=scope)

def set_chrome_doh_provider(template_url: str, scope: str = "BOTH") -> tuple[bool, str]:
    """Activa DoH en Chrome con la plantilla dada (una o varias, separadas por comas)."""
    template_url = (template_url or "").strip()
    if not template_url:
        log.warning("Template vacío al configurar DoH (Chrome).")
        return False, "Template vacío"
    log.debug("Configurando DoH provider (Chrome): %s (scope=%s)", template_url, scope)
    return _set_pol(mode="secure", template=template_url, scope=scope)

def clear_chrome_policy(scope: str = "BOTH") -> tuple[bool, str]:
    """Elimina cualquier política de DoH aplicada en Chrome."""
    log.debug("Limpiando políticas Chrome DoH (scope=%s)", scope)
    return _set_pol(mode=None, template=None, scope=scope)

# Atajo específico para CleanBrowsing Family
def set_chrome_doh_cleanbrowsing(scope: str = "BOTH") -> tuple[bool, str]:
    """Configura DoH con CleanBrowsing Family (lo que pediste)."""
    return set_chrome_doh_provider(CLEANBROWSING["doh"], scope=scope)
