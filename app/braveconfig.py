import json
import winreg
from utils.cache import memo_ttl
from utils.winproc import _ps
from app.logs import get_logger
log = get_logger("brave")

HKCU = r"HKCU:\Software\Policies\BraveSoftware\Brave"
HKLM = r"HKLM:\SOFTWARE\Policies\BraveSoftware\Brave"


# ---------------------------------------------------------------------
# Configuración de políticas Brave DoH
# ---------------------------------------------------------------------
def _set_pol(mode: str | None, template: str | None, scope: str) -> tuple[bool, str]:
    """
    mode: "off" | "secure" | None  (None -> borra DnsOverHttpsMode)
    template: url o None (None -> borra DnsOverHttpsTemplates)
    scope: "HKCU" | "HKLM" | "BOTH"
    Además, ajusta BuiltInDnsClientEnabled:
      - secure -> 1
      - off    -> 0
      - None   -> elimina (valor por defecto)
    """
    paths = []
    if scope in ("HKCU", "BOTH"):
        paths.append(r"HKCU:\Software\Policies\BraveSoftware\Brave")
    if scope in ("HKLM", "BOTH"):
        paths.append(r"HKLM:\Software\Policies\BraveSoftware\Brave")
    if not paths:
        log.error("Scope inválido en _set_pol: %s", scope)
        return False, "scope inválido"

    script = []
    for p in paths:
        script.append(f'New-Item -Path "{p}" -Force | Out-Null')
        # DnsOverHttpsMode
        if mode is None:
            script.append(f'Remove-ItemProperty -Path "{p}" -Name "DnsOverHttpsMode" -ErrorAction SilentlyContinue')
        else:
            script.append(f'Set-ItemProperty -Path "{p}" -Name "DnsOverHttpsMode" -Type String -Value "{mode}"')
        # DnsOverHttpsTemplates
        if template is None:
            script.append(f'Remove-ItemProperty -Path "{p}" -Name "DnsOverHttpsTemplates" -ErrorAction SilentlyContinue')
        else:
            script.append(f'Set-ItemProperty -Path "{p}" -Name "DnsOverHttpsTemplates" -Type String -Value "{template}"')
        # BuiltInDnsClientEnabled
        if mode == "secure":
            script.append(f'Set-ItemProperty -Path "{p}" -Name "BuiltInDnsClientEnabled" -Type DWord -Value 1')
        elif mode == "off":
            script.append(f'Set-ItemProperty -Path "{p}" -Name "BuiltInDnsClientEnabled" -Type DWord -Value 0')
        else:
            script.append(f'Remove-ItemProperty -Path "{p}" -Name "BuiltInDnsClientEnabled" -ErrorAction SilentlyContinue')

    # Salida para diagnóstico
    script.append('Write-Output "OK"')

    try:
        from utils.winproc import _ps  # usa tu misma función PowerShell
    except Exception:
        log.error("No se pudo importar _ps desde dnsconfig")
        return False, "_ps no disponible"

    rc, out, err = _ps("\n".join(script))
    text = (out or err or "").strip()
    ok = text.strip().startswith("OK")

    if ok:
        log.info("Brave DoH cambiado → mode=%s scope=%s template=%s", mode or "unset", scope, template or "—")
        return True, "OK"
    else:
        msg = f"[PS rc={rc}] {text or '(sin salida)'}"
        log.warning("Error al aplicar políticas Brave DoH (mode=%s scope=%s): %s", mode, scope, msg)
        return False, msg


# --- lector crudo desde winreg ------------------------------------------------
def _read_policy_winreg() -> dict | None:
    """
    Devuelve el primer bloque de políticas encontrado (HKCU preferente, luego HKLM).
    Estructura: {"scope":"HKCU|HKLM","mode":"off|secure|unset","templates":"...", "builtIn":0/1/None}
    """
    def _read(root, path, scope):
        try:
            # Intenta vista 64-bit y 32-bit por compatibilidad con Python 32-bit
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

    # HKCU preferente
    val = _read(winreg.HKEY_CURRENT_USER, r"Software\Policies\BraveSoftware\Brave", "HKCU")
    if val:
        return val
    # HKLM si no hay usuario
    val = _read(winreg.HKEY_LOCAL_MACHINE, r"Software\Policies\BraveSoftware\Brave", "HKLM")
    if val:
        return val
    return None

# --- fallback PowerShell (tu _ps ya existe) -----------------------------------
def _read_policy_powershell() -> dict:
    ps = r'''
function Read-Pol($root) {
  $path = "$root\Software\Policies\BraveSoftware\Brave"
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
        log.warning("PS read Brave DoH rc=%s: %s", rc, err)
    try:
        return json.loads(raw) if raw else {"scope":"NONE","mode":"unset","templates":"","builtIn":None}
    except Exception as e:
        log.error("PS JSON parse error: %s", e)
        return {"scope":"NONE","mode":"unset","templates":"","builtIn":None}

# --- API público --------------------------------------------------------------
def get_brave_doh_status(force: bool = False) -> dict:
    """
    Lee políticas de Brave (HKCU→HKLM). Si force=True, salta la caché.
    """
    def _fetch():
        data = _read_policy_winreg()
        if data:
            log.debug("Brave DoH (winreg): %s", data)
            return data
        data = _read_policy_powershell()
        log.debug("Brave DoH (PS): %s", data)
        return data

    if force:
        return _fetch()
    return memo_ttl("brave_doh_status", 10, _fetch)

def summarize_brave_status(d: dict) -> str:
    """
    Convierte el dict de estado en texto claro y normalizado para la UI.
    """
    if not d:
        return "⚪ No configurado"

    scope = d.get("scope", "NONE")
    mode = (d.get("mode") or "unset").lower()
    tmpl = (d.get("templates") or "").lower()

    # --- detectar proveedor por URL ---
    provider = "personalizado"
    if "cleanbrowsing" in tmpl:
        provider = "CleanBrowsing Family"
    elif "cloudflare" in tmpl:
        provider = "Cloudflare Family"
    elif "adguard" in tmpl:
        provider = "AdGuard Family"

    # --- generar texto según estado ---
    if scope == "NONE" or mode == "unset":
        return "⚪ No configurado (sin política)"
    if mode == "secure":
        return f"🟢 Protección familiar activa ({provider})"
    if mode == "off":
        return "🔴 DoH desactivado"
    if mode == "automatic":
        return "🟡 DoH automático"
    return f"⚙️ Estado desconocido ({mode})"

def summarize_brave_status_plain(d: dict) -> tuple[str, str]:
    """
    Devuelve (texto, kind) para UI sin emojis.
    kind ∈ {'ok','off','auto','unset','unknown'}
    """
    if not d or d.get("scope") == "NONE":
        return "No configurado (sin política)", "unset"

    mode = (d.get("mode") or "unset").lower()
    tmpl = (d.get("templates") or "").lower()

    # proveedor
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



# ---------------------------------------------------------------------
# Wrappers públicos
# ---------------------------------------------------------------------
def set_brave_doh_off(scope: str = "BOTH") -> tuple[bool, str]:
    """Desactiva DNS over HTTPS en Brave."""
    log.debug("Desactivando DoH en Brave (scope=%s)", scope)
    return _set_pol(mode="off", template=None, scope=scope)

def set_brave_doh_provider(template_url: str, scope: str = "BOTH") -> tuple[bool, str]:
    """Activa DoH en Brave con el proveedor especificado."""
    template_url = (template_url or "").strip()
    if not template_url:
        log.warning("Template vacío al configurar DoH.")
        return False, "Template vacío"
    log.debug("Configurando DoH provider: %s (scope=%s)", template_url, scope)
    return _set_pol(mode="secure", template=template_url, scope=scope)

def clear_brave_policy(scope: str = "BOTH") -> tuple[bool, str]:
    """Elimina todas las políticas de DoH aplicadas."""
    log.debug("Limpiando políticas Brave DoH (scope=%s)", scope)
    return _set_pol(mode=None, template=None, scope=scope)