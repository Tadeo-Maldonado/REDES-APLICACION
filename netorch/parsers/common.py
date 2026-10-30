"""Funciones compartidas por los parsers: capacidades, bloques y fallback a NTC-Templates."""
from __future__ import annotations

import logging
import re
from typing import Iterable, Optional

from ..utils import IPV4, MAC_ANY, normalize_mac, normalize_port, is_multicast_or_special
from ..models import ArpEntry, MacEntry

log = logging.getLogger(__name__)

_CAP_WORDS = {
    "router": "Router", "r": "Router",
    "switch": "Switch", "bridge": "Switch", "b": "Switch", "source-route-bridge": "Switch",
    "trans-bridge": "AP", "wlan": "AP", "wlan access point": "AP", "w": "AP",
    "phone": "Phone", "telephone": "Phone", "t": "Phone",
    "host": "Station", "station": "Station", "station-only": "Station",
    "station only": "Station", "s": "Station",
    "repeater": "Repeater", "p": "Repeater",
}


def normalize_caps(text: Optional[str]) -> list[str]:
    """'Router Switch IGMP' / 'B,R' / 'bridge, router' -> ['Router', 'Switch']."""
    if not text:
        return []
    caps: list[str] = []
    for token in re.split(r"[,\s]+", text.strip()):
        tok = token.strip().lower()
        if not tok:
            continue
        cap = _CAP_WORDS.get(tok)
        if cap and cap not in caps:
            caps.append(cap)
    # "WLAN Access Point" llega partido en tokens
    if "wlan" in text.lower() and "AP" not in caps:
        caps.append("AP")
    return caps


def split_blocks(text: str, start_regex: str) -> list[str]:
    """Divide la salida en bloques que empiezan con una línea que cumple start_regex."""
    blocks, current = [], []
    pattern = re.compile(start_regex, re.IGNORECASE)
    for line in (text or "").splitlines():
        if pattern.search(line):
            if current:
                blocks.append("\n".join(current))
            current = [line]
        elif current:
            current.append(line)
    if current:
        blocks.append("\n".join(current))
    return blocks


def kv(block: str, *keys: str, sep: str = ":") -> Optional[str]:
    """Busca 'Clave <sep> valor' en un bloque (insensible a mayúsculas)."""
    for key in keys:
        m = re.search(rf"^\s*{re.escape(key)}\s*{re.escape(sep)}[ \t]*(.*?)[,]?\s*$",
                      block, re.IGNORECASE | re.MULTILINE)
        if m and m.group(1).strip():
            return m.group(1).strip()
    return None


def first_ip(text: Optional[str]) -> Optional[str]:
    m = IPV4.search(text or "")
    return m.group(1) if m else None


SKIP_MAC_PORTS = re.compile(r"^(cpu|router|drop|sup-eth|switch|self|vtep|nve|vlan|"
                            r"lo\d|loopback|mgmt|--|n/a|\(r\)|vpc|peer-link)", re.IGNORECASE)


def generic_arp(text: str) -> list[ArpEntry]:
    """Cualquier tabla ARP: busca líneas con una IP y una MAC.

    Funciona para Cisco IOS/NX-OS, Aruba AOS-S/CX y Alcatel AOS.
    """
    out: list[ArpEntry] = []
    for line in (text or "").splitlines():
        ip_m = IPV4.search(line)
        mac_m = MAC_ANY.search(line)
        if not ip_m or not mac_m:
            continue
        mac = normalize_mac(mac_m.group(1))
        if not mac or is_multicast_or_special(mac):
            continue
        tail = line[mac_m.end():].split()
        iface = None
        for tok in tail:
            if re.match(r"(?i)^(vlan\s*\d+|vlan\d+|gi|te|eth|po|\d+/\d+)", tok) or tok.isdigit():
                iface = tok
        out.append(ArpEntry(ip=ip_m.group(1), mac=mac, interface=iface))
    return out


def clean_mac_entries(entries: Iterable[MacEntry]) -> list[MacEntry]:
    """Quita MACs de CPU/multicast y duplicados exactos."""
    seen, out = set(), []
    for e in entries:
        if not e.mac or not e.port or SKIP_MAC_PORTS.match(e.port):
            continue
        if is_multicast_or_special(e.mac):
            continue
        key = (e.mac, e.port, e.vlan)
        if key in seen:
            continue
        seen.add(key)
        out.append(e)
    return out


# ---------------------------------------------------------------------------
# Fallback con NTC-Templates (TextFSM). Se usa si el parser propio no encontró nada.
# ---------------------------------------------------------------------------
def textfsm_parse(platform: str, command: str, output: str) -> list[dict]:
    try:
        from ntc_templates.parse import parse_output
        rows = parse_output(platform=platform, command=command, data=output)
        return [{k.lower(): v for k, v in r.items()} for r in rows]
    except Exception as exc:  # plantilla inexistente o salida inesperada
        log.debug("TextFSM sin resultado para %s / %s: %s", platform, command, exc)
        return []


def pick(row: dict, *keys: str) -> Optional[str]:
    """Primer valor no vacío de varias claves posibles (los nombres cambian entre versiones)."""
    for k in keys:
        v = row.get(k)
        if isinstance(v, list):
            v = v[0] if v else None
        if v not in (None, "", []):
            return str(v)
    return None


def textfsm_macs(platform: str, command: str, output: str) -> list[MacEntry]:
    out = []
    for r in textfsm_parse(platform, command, output):
        mac = normalize_mac(pick(r, "destination_address", "mac_address", "mac") or "")
        port = pick(r, "destination_port", "ports", "port", "interface")
        vlan = pick(r, "vlan_id", "vlan")
        if mac and port:
            out.append(MacEntry(mac=mac, port=normalize_port(port),
                                vlan=int(vlan) if vlan and vlan.isdigit() else None))
    return clean_mac_entries(out)


def tagging_mode(iface) -> Optional[str]:
    """Aruba AOS-S / Alcatel no tienen 'modo trunk' explícito: se deduce del etiquetado.

    Un puerto con VLAN untagged y como máximo UNA VLAN tagged (típicamente la de voz)
    se trata como puerto de acceso; con 2+ VLANs tagged, o solo tagged, es trunk/uplink.
    """
    if len(iface.tagged_vlans) >= 2 or (iface.tagged_vlans and iface.access_vlan is None):
        return "trunk"
    if iface.access_vlan is not None:
        return "access"
    return None


class Guard:
    """Ejecuta cada sección del parseo aislada: si una falla, se registra y sigue el resto.

    Así una salida inesperada de un comando nunca tumba toda la ejecución.
    """

    def __init__(self, data):
        self.data = data

    def __call__(self, section: str, fn, *args, default=None):
        try:
            return fn(*args)
        except Exception as exc:              # noqa: BLE001 - se reporta como advertencia
            log.warning("Parser %s falló: %s", section, exc, exc_info=True)
            self.data.warnings.append(
                f"No se pudo interpretar «{section}» ({type(exc).__name__}: {exc}). "
                "La salida cruda quedó en Raw logs.")
            return default
