# dnsconfig.py — utilidades para fijar/leer DNS del sistema (Windows)
import re
import json
from utils.winproc import _ps, run_quiet
from utils.cache import memo_ttl
from app.logs import get_logger

log = get_logger("dns")


# =====================================================================
# Funciones principales
# =====================================================================

def _ps_escape(s: str) -> str:
    """
    Escapa cadena para usar dentro de comillas dobles en PowerShell.
    Reglas básicas: ` -> ``   y   " -> `"
    """
    return s.replace("`", "``").replace('"', '`"')

def _dedup_preserve(seq):
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def list_adapters():
    """
    Devuelve lista de adaptadores habilitados con sus DNS actuales (IPv4).
    Cachea el resultado 15 s para evitar múltiples llamadas al abrir el panel.
    """
    def _fetch():
        ps = r'''
# Tomamos todas las interfaces IPv4 activas (Status=Up) y su lista de DNS si existe
$cfg = Get-NetIPConfiguration |
    Where-Object { $_.IPv4Address -ne $null -and $_.NetAdapter.Status -eq "Up" } |
    Select-Object InterfaceAlias, InterfaceIndex,
        @{Name="ServerAddresses"; Expression = {
            if ($_.DnsServer -and $_.DnsServer.ServerAddresses) { $_.DnsServer.ServerAddresses } else { @() }
        }}
$cfg | ConvertTo-Json -Depth 4
'''
        rc, out, err = _ps(ps)
        # ✅ aquí va sintaxis Python, no PowerShell
        if rc != 0 or not out or not out.strip():
            log.warning("No se pudieron listar adaptadores DNS (rc=%s): %s", rc, err)
            return []

        try:
            data = json.loads(out.strip())
            # Normalizamos a lista
            if isinstance(data, dict):
                data = [data]
            log.debug("Detectados %d adaptadores activos.", len(data))
            return data
        except Exception as e:
            log.error("Error parseando salida JSON de PowerShell: %s", e)
            return []

    return memo_ttl("dns_adapters", 15, _fetch)


def set_dns_servers(servers_ipv4: list[str], interface_alias: str | None = None) -> tuple[bool, str]:
    """
    Fija DNS IPv4 (lista de IPs) en uno o todos los adaptadores activos.
    """
    addrs = ",".join(f'"{s}"' for s in servers_ipv4 if s.strip())
    if not addrs:
        log.warning("Intento de fijar DNS con lista vacía.")
        return False, "Lista vacía de DNS"

    if interface_alias:
        esc = _ps_escape(interface_alias)
        target = f' -InterfaceAlias "{esc}" '
        scope = f'adaptador \"{interface_alias}\"'
    else:
        target = r' -InterfaceAlias (Get-NetIPConfiguration | Where-Object {$_.IPv4Address -ne $null -and $_.NetAdapter.Status -eq "Up"} | Select-Object -ExpandProperty InterfaceAlias) '
        scope = "todos los adaptadores activos"

    ps = fr'''
try {{
    Set-DnsClientServerAddress {target} -ServerAddresses @({addrs}) -ErrorAction Stop
    Write-Output "OK:{scope}"
}} catch {{
    Write-Output "ERR:$($_.Exception.Message)"
}}
'''
    rc, out, err = _ps(ps)
    out = (out or "").strip() or err
    ok = out.startswith("OK:")
    if ok:
        log.info("DNS establecidos correctamente en %s: %s", scope, addrs)
    else:
        log.warning("Error fijando DNS (%s): %s", scope, out)
    return ok, out

def set_dns_auto(interface_alias: str | None = None) -> tuple[bool, str]:
    """
    Vuelve a “Obtener direcciones de servidor DNS automáticamente”.
    """
    if interface_alias:
        esc = _ps_escape(interface_alias)
        target = f' -InterfaceAlias "{esc}" '
        scope = f'adaptador \"{interface_alias}\"'
    else:
        target = r' -InterfaceAlias (Get-NetIPConfiguration | Where-Object {$_.IPv4Address -ne $null -and $_.NetAdapter.Status -eq "Up"} | Select-Object -ExpandProperty InterfaceAlias) '
        scope = "todos los adaptadores activos"

    ps = fr'''
try {{
    Set-DnsClientServerAddress {target} -ResetServerAddresses -ErrorAction Stop
    Write-Output "OK:{scope}"
}} catch {{
    Write-Output "ERR:$($_.Exception.Message)"
}}
'''
    rc, out, err = _ps(ps)
    out = (out or "").strip() or err
    ok = out.startswith("OK:")
    if ok:
        log.info("DNS reiniciados a automático en %s", scope)
    else:
        log.warning("Error al resetear DNS (%s): %s", scope, out)
    return ok, out

# =====================================================================
# Estado DNS real (netsh)
# =====================================================================
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def _run_netsh(args: list[str]) -> tuple[bool, str]:
    try:
        rc, out, err = run_quiet(["netsh", *args])
        text = (out or "") + (err or "")
        if rc != 0:
            log.warning("netsh error rc=%s args=%s out=%s", rc, args, text.strip()[:200])
        else:
            log.debug("netsh ok args=%s", args)
        return (rc == 0), text
    except Exception as e:
        log.error("Error ejecutando netsh %s: %s", args, e)
        return False, str(e)

def _qname(alias: str) -> str:
    return f'name="{alias}"'

def _parse_dnsservers_output(text: str) -> tuple[str, list[str]]:
    t = text.lower()
    servers = _dedup_preserve(_IP_RE.findall(text))


    # Señales claras
    if ("dhcp" in t and "configur" in t and "dns" in t) or ("dhcp configured dns servers" in t):
        return "dhcp", servers
    if "estátic" in t or "static" in t:
        return "static", servers

    # Variantes (“obtener automáticamente…”, etc.)
    if "obtener" in t and "automátic" in t and "dns" in t:
        return "dhcp", servers

    # Si no vemos textos, pero hay IPs listadas, asumimos 'static'
    if servers:
        return "static", servers

    return "unknown", servers

def _parse_showconfig_output(text: str) -> tuple[str, list[str]]:
    t = text.lower()
    servers = _dedup_preserve(_IP_RE.findall(text))


    if ("dhcp habilitado: sí" in t) or ("dhcp enabled: yes" in t):
        return "dhcp", servers
    if ("dhcp habilitado: no" in t) or ("dhcp enabled: no" in t):
        return "static", servers

    # Otra línea típica:
    if ("obtener direccion de servidor dns automaticamente" in t) or \
       ("obtener dirección de servidor dns automáticamente" in t) or \
       ("obtain dns server address automatically" in t):
        # Si contiene "no" o "disabled" cerca, tratamos como static
        if "no" in t or "disabled" in t:
            return "static", servers
        return "dhcp", servers

    return "unknown", servers

def get_dns_status(interface_alias: str | None = None) -> dict:
    """
    Lee el estado REAL de DNS por interfaz (cacheado 10 s).
    """
    def _fetch():
        aliases = []
        for a in (list_adapters() or []):
            al = (a.get("InterfaceAlias") or "").strip()
            if al:
                aliases.append(al)
        if interface_alias:
            aliases = [interface_alias]

        seen = set()
        out_all = {"interfaces": []}
        for al in aliases:
            if not al or al in seen:
                continue
            seen.add(al)
            ok, out = _run_netsh(["interface", "ipv4", "show", "dnsservers", _qname(al)])
            mode, servers = ("unknown", [])
            if ok:
                mode, servers = _parse_dnsservers_output(out)
            if mode == "unknown":
                ok2, out2 = _run_netsh(["interface", "ip", "show", "config", _qname(al)])
                if ok2:
                    mode2, servers2 = _parse_showconfig_output(out2)
                    if mode == "unknown" and mode2 != "unknown":
                        mode = mode2
                    if not servers:
                        servers = servers2
            out_all["interfaces"].append({"alias": al, "mode": mode, "servers": servers})
            log.debug("DNS estado %s → %s %s", al, mode, servers)
        return out_all

    key = f"dns_status_{interface_alias or 'ALL'}"
    return memo_ttl(key, 10, _fetch)

def summarize_dns_status(status: dict) -> str:
    if not status or not status.get("interfaces"):
        return "Estado: no se pudo leer el DNS."
    parts = []
    for it in status["interfaces"]:
        al = it.get("alias") or "?"
        mode = it.get("mode") or "unknown"
        srvs = ", ".join(_dedup_preserve(it.get("servers") or []))
        if mode == "static":
            parts.append(f"{al}: fijo → {srvs or '—'}")
        elif mode == "dhcp":
            parts.append(f"{al}: automático (DHCP) → {srvs or '—'}")
        else:
            parts.append(f"{al}: desconocido")
    msg = " · ".join(parts)
    log.info("Resumen DNS: %s", msg)
    return msg
