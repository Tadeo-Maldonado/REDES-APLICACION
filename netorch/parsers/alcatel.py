"""Parsers para Alcatel-Lucent Enterprise OmniSwitch (AOS 6 y AOS 8).

AOS no tiene buenas plantillas TextFSM para todo, así que aquí se usan RegEx propias.
"""
from __future__ import annotations

import re

from ..models import Interface, MacEntry, Neighbor, ParsedData, Vlan
from ..utils import IPV4, MAC_ANY, normalize_mac
from .common import tagging_mode, clean_mac_entries, first_ip, generic_arp, normalize_caps, textfsm_macs

PORT_RE = r"\d+/\d+(?:/\d+)?"


def parse_lldp(text: str) -> list[Neighbor]:
    """'show lldp remote-system': bloques por puerto local, campos 'Clave = valor,'."""
    neighbors: list[Neighbor] = []
    local_port = None
    current: dict | None = None

    def flush():
        if current and local_port:
            name = current.get("system name")
            chassis = current.get("chassis")
            caps = current.get("capabilites enabled") or current.get("capabilities enabled") \
                or current.get("capabilites supported") or current.get("capabilities supported")
            mgmt = current.get("management ip address") or current.get("management address")
            neighbors.append(Neighbor(
                local_port=local_port,
                name=(name if name and name.lower() not in ("(null)", "null", "") else None)
                     or chassis or "desconocido",
                protocol="LLDP",
                remote_port=current.get("port"),
                platform=current.get("system description"),
                capabilities=normalize_caps(caps),
                mgmt_ip=first_ip(mgmt),
                chassis_mac=normalize_mac(chassis) if chassis and MAC_ANY.search(chassis) else None,
            ))

    for line in (text or "").splitlines():
        m_local = re.search(rf"Local (?:Slot/)?Port\s+({PORT_RE})\s*:", line, re.IGNORECASE)
        if m_local:
            flush()
            current = None
            local_port = m_local.group(1)
            continue
        m_ch = re.match(r"^\s*Chassis\s+(.+?),\s*Port\s+(.+?):\s*$", line)
        if m_ch:
            flush()
            current = {"chassis": m_ch.group(1).strip(), "port": m_ch.group(2).strip()}
            continue
        m_kv = re.match(r"^\s*([A-Za-z][A-Za-z /\-]+?)\s*=\s*(.*?),?\s*$", line)
        if m_kv and current is not None:
            current[m_kv.group(1).strip().lower()] = m_kv.group(2).strip()
    flush()
    return neighbors


def parse_mac(text: str) -> list[MacEntry]:
    out = []
    for line in (text or "").splitlines():
        mac_m = MAC_ANY.search(line)
        if not mac_m:
            continue
        before = line[:mac_m.start()].split()
        after = line[mac_m.end():].split()
        if not after:
            continue
        port = after[-1]
        if not re.fullmatch(rf"{PORT_RE}|\d+/\d+", port):
            continue
        vlan = next((int(t) for t in reversed(before) if t.isdigit()), None)
        out.append(MacEntry(mac=normalize_mac(mac_m.group(1)), port=port, vlan=vlan))
    entries = clean_mac_entries(out)
    if not entries and (text or "").strip():
        entries = textfsm_macs("alcatel_aos", "show mac-address-table", text)
    return entries


def parse_interfaces(text: str) -> dict[str, Interface]:
    """'show interfaces status': AOS no muestra el estado oper. directo; se deduce de la
    velocidad detectada (número = enlace arriba, '-' = abajo)."""
    result = {}
    for line in (text or "").splitlines():
        m = re.match(rf"^\s*({PORT_RE})\s+(en|dis|enable|disable)\w*\s+(\S+)\s+(\S+)\s+(\S+)",
                     line, re.IGNORECASE)
        if not m:
            continue
        port, admin, speed = m.group(1), m.group(2).lower(), m.group(4)
        if admin.startswith("dis"):
            status = "disabled"
        else:
            status = "up" if speed.isdigit() else "down"
        result[port] = Interface(port=port, status=status, speed=speed if speed.isdigit() else None)
    return result


def apply_link_status(text: str, interfaces: dict[str, Interface]) -> None:
    """'show interfaces alias': estado real del enlace + descripción (alias).

     1/1/1      enable          up          "PC-01"
    """
    for line in (text or "").splitlines():
        m = re.match(rf"^\s*({PORT_RE})\s+(enable|disable)\w*\s+(up|down)\b\s*(.*)$",
                     line, re.IGNORECASE)
        if not m:
            continue
        port = m.group(1)
        iface = interfaces.setdefault(port, Interface(port=port))
        if m.group(2).lower().startswith("disable"):
            iface.status = "disabled"
        else:
            iface.status = m.group(3).lower()
        alias = m.group(4).strip().strip('"').strip()
        if alias:
            iface.description = alias


def parse_linkagg_ports(text: str) -> dict[str, list[str]]:
    """'show linkagg port': puerto físico -> número de agregado.

     1/1/25    Dynamic    1025    ATTACHED    1    UP    UP   YES
    En la tabla MAC el agregado aparece como '0/<n>'.
    """
    lags: dict[str, list[str]] = {}
    for line in (text or "").splitlines():
        m = re.match(rf"^\s*({PORT_RE})\s+(Static|Dynamic)\s+\d+\s+\S+\s+(\d+)\b",
                     line, re.IGNORECASE)
        if m:
            lags.setdefault(f"0/{m.group(3)}", []).append(m.group(1))
    return lags


def apply_vlan_ports(text: str, interfaces: dict[str, Interface]) -> None:
    for line in (text or "").splitlines():
        m = re.match(r"^\s*(\d{1,4})\s+(\S+)\s+(default|untagged|qtagged|tagged|dynamic|mobile)\b",
                     line, re.IGNORECASE)
        if not m:
            continue
        vid, port, typ = int(m.group(1)), m.group(2), m.group(3).lower()
        iface = interfaces.setdefault(port, Interface(port=port))
        if typ in ("default", "untagged", "dynamic", "mobile"):
            iface.access_vlan = vid
        elif vid not in iface.tagged_vlans:
            iface.tagged_vlans.append(vid)
    for iface in interfaces.values():
        iface.tagged_vlans.sort()
        iface.mode = tagging_mode(iface)


_STATE_TOKENS = {"on", "off", "ena", "dis", "enable", "disable", "na"}


def parse_vlans(text: str) -> dict[int, Vlan]:
    vlans = {}
    for line in (text or "").splitlines():
        m = re.match(r"^\s*(\d{1,4})\s+(std|vcm|vstk|gvrp|mvrp|svlan|ipmvlan|\w+)\s+(on|off|ena|dis)\b",
                     line, re.IGNORECASE)
        if not m:
            continue
        tokens = line.split()
        idx = 1                                   # tokens[1] = tipo (std, vcm...)
        for i, tok in enumerate(tokens[2:], start=2):
            if tok.lower() in _STATE_TOKENS or tok.isdigit():
                idx = i
            else:
                break                             # empieza el nombre
        vid = int(m.group(1))
        vlans[vid] = Vlan(vlan_id=vid, name=" ".join(tokens[idx + 1:]) or None)
    return vlans


def parse_svis(text: str, vlans: dict[int, Vlan]) -> None:
    for line in (text or "").splitlines():
        ip_m = IPV4.search(line)
        if not ip_m or line.lower().strip().startswith("loopback"):
            continue
        dev = re.search(r"vlan\s*(\d+)\s*$", line, re.IGNORECASE)
        if dev:
            vid = int(dev.group(1))
            vlans.setdefault(vid, Vlan(vlan_id=vid)).svi_ip = ip_m.group(1)


def parse(outputs: dict[str, str], platform: str) -> ParsedData:
    data = ParsedData()
    data.neighbors = parse_lldp(outputs.get("neighbors_lldp", ""))
    data.macs = parse_mac(outputs.get("mac", ""))
    data.arp = generic_arp(outputs.get("arp", ""))
    data.interfaces = parse_interfaces(outputs.get("interfaces", ""))
    apply_link_status(outputs.get("link_status", ""), data.interfaces)
    apply_vlan_ports(outputs.get("vlan_ports", ""), data.interfaces)
    data.vlans = parse_vlans(outputs.get("vlans", ""))
    parse_svis(outputs.get("svis", ""), data.vlans)
    data.lags = parse_linkagg_ports(outputs.get("lags", ""))
    return data
