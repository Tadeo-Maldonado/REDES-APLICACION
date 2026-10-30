"""Parsers para Aruba AOS-S (ProCurve) y AOS-CX."""
from __future__ import annotations

import re

from ..models import Interface, MacEntry, Neighbor, ParsedData, Vlan
from ..utils import MAC_ANY, expand_vlan_list, normalize_mac
from .common import (Guard, clean_mac_entries, tagging_mode, first_ip, generic_arp, kv, normalize_caps,
                     split_blocks, textfsm_macs)


# ---------------------------------------------------------------- comunes ----
def parse_lldp_aoss(text: str) -> list[Neighbor]:
    neighbors = []
    for block in split_blocks(text, r"^\s*Local Port\s*:"):
        local = kv(block, "Local Port")
        if not local:
            continue
        chassis = kv(block, "ChassisId", "Chassis Id")
        name = kv(block, "SysName", "System Name")
        caps = kv(block, "System Capabilities Enabled") or kv(block, "System Capabilities Supported")
        mgmt = re.search(r"Remote Management Address(.*?)(?:\n\s*\n\S|\Z)", block, re.DOTALL)
        chassis_mac = normalize_mac(chassis) if chassis and MAC_ANY.search(chassis) else None
        neighbors.append(Neighbor(
            local_port=local.strip(),
            name=name or chassis or "desconocido",
            protocol="LLDP",
            remote_port=kv(block, "PortId", "Port Id"),
            platform=kv(block, "System Descr", "System Description"),
            capabilities=normalize_caps(caps),
            mgmt_ip=first_ip(mgmt.group(1)) if mgmt else None,
            chassis_mac=chassis_mac,
        ))
    return neighbors


def parse_lldp_cx(text: str) -> list[Neighbor]:
    neighbors = []
    for block in split_blocks(text, r"^\s*Port\s*:"):
        local = kv(block, "Port")
        if not local:
            continue
        chassis = kv(block, "Neighbor Chassis-ID", "Chassis-ID")
        name = kv(block, "Neighbor Chassis-Name", "Neighbor System-Name", "System Name")
        if not name and not chassis:
            continue     # puerto listado sin vecino ("Neighbor Entries : 0")
        caps = kv(block, "Chassis Capabilities Enabled", "Chassis Capabilities Available")
        chassis_mac = normalize_mac(chassis) if chassis and MAC_ANY.search(chassis) else None
        neighbors.append(Neighbor(
            local_port=local.strip(),
            name=name or chassis,
            protocol="LLDP",
            remote_port=kv(block, "Neighbor Port-ID", "Port-ID"),
            platform=kv(block, "Neighbor Chassis-Description", "Chassis-Description"),
            capabilities=normalize_caps(caps),
            mgmt_ip=first_ip(kv(block, "Neighbor Management-Address", "Management-Address")),
            chassis_mac=chassis_mac,
        ))
    return neighbors


# ----------------------------------------------------------------- AOS-S -----
def parse_mac_aoss(text: str) -> list[MacEntry]:
    out = []
    for line in (text or "").splitlines():
        m = re.match(r"^\s*([0-9a-fA-F]{6}-[0-9a-fA-F]{6})\s+(\S+)(?:\s+(\d+))?", line)
        if m:
            out.append(MacEntry(mac=normalize_mac(m.group(1)), port=m.group(2),
                                vlan=int(m.group(3)) if m.group(3) else None))
    entries = clean_mac_entries(out)
    if not entries and (text or "").strip():
        entries = textfsm_macs("hp_procurve", "show mac-address", text)
    return entries


def parse_interfaces_aoss(text: str) -> dict[str, Interface]:
    result = {}
    for line in (text or "").splitlines():
        m = re.match(r"^\s*(\S+)\s+(\S+)\s*\|?\s*(\S+)\s+(Yes|No)\s+(Up|Down)\s+(\S+)", line)
        if not m:
            continue
        port, enabled, status = m.group(1), m.group(4), m.group(5)
        result[port] = Interface(
            port=port,
            status="disabled" if enabled == "No" else status.lower(),
            speed=m.group(6),
        )
    return result


def parse_vlans_aoss(text: str) -> dict[int, Vlan]:
    vlans = {}
    for line in (text or "").splitlines():
        m = re.match(r"^\s*(\d{1,4})\s+(.+?)\s+\|", line)
        if m:
            vid = int(m.group(1))
            vlans[vid] = Vlan(vlan_id=vid, name=m.group(2).strip())
    return vlans


def apply_vlan_detail_aoss(vid: int, text: str, interfaces: dict[str, Interface]) -> None:
    """'show vlans <id>': lista cada puerto como Untagged o Tagged."""
    for line in (text or "").splitlines():
        m = re.match(r"^\s*(\S+)\s+(Untagged|Tagged)\b", line, re.IGNORECASE)
        if not m:
            continue
        iface = interfaces.setdefault(m.group(1), Interface(port=m.group(1)))
        if m.group(2).lower() == "untagged":
            iface.access_vlan = vid
        elif vid not in iface.tagged_vlans:
            iface.tagged_vlans.append(vid)


def parse_svis_aoss(text: str, vlans: dict[int, Vlan]) -> None:
    by_name = {(v.name or "").lower(): v for v in vlans.values()}
    for line in (text or "").splitlines():
        m = re.match(r"^\s*(.+?)\s+\|\s+\S+\s+(\d+\.\d+\.\d+\.\d+)", line)
        if m and m.group(1).strip().lower() in by_name:
            by_name[m.group(1).strip().lower()].svi_ip = m.group(2)


def parse_trunks_aoss(text: str) -> dict[str, list[str]]:
    """'show trunks': '  49   |   SFP+SR   | Trk1   LACP'."""
    lags: dict[str, list[str]] = {}
    for line in (text or "").splitlines():
        m = re.match(r"^\s*(\S+)\s+\|.*\|\s*(Trk\d+)\b", line)
        if m:
            lags.setdefault(m.group(2), []).append(m.group(1))
    return lags


# ----------------------------------------------------------------- AOS-CX ----
def parse_mac_cx(text: str) -> list[MacEntry]:
    out = []
    for line in (text or "").splitlines():
        m = re.match(r"^\s*((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\s+(\d+)\s+(.*)$", line)
        if m and m.group(3).split():
            out.append(MacEntry(mac=normalize_mac(m.group(1)), port=m.group(3).split()[-1],
                                vlan=int(m.group(2))))
    entries = clean_mac_entries(out)
    if not entries and (text or "").strip():
        entries = textfsm_macs("aruba_aoscx", "show mac-address-table", text)
    return entries


def parse_interfaces_cx(text: str) -> dict[str, Interface]:
    result = {}
    for line in (text or "").splitlines():
        m = re.match(r"^\s*(\d+/\d+/\d+|lag\d+)\s+(\S+)\s+(access|trunk|routed|--)\s+(\S+)\s+"
                     r"(yes|no)\s+(up|down)", line, re.IGNORECASE)
        if not m:
            continue
        port, native, mode, enabled, status = (m.group(1), m.group(2), m.group(3).lower(),
                                               m.group(5).lower(), m.group(6).lower())
        result[port] = Interface(
            port=port,
            status="disabled" if enabled == "no" else status,
            mode=None if mode == "--" else mode,
            access_vlan=int(native) if native.isdigit() else None,
        )
    return result


def apply_port_config_cx(text: str, interfaces: dict[str, Interface],
                         lags: dict[str, list[str]] | None = None) -> None:
    """'show running-config interface': vlan access / trunk native / trunk allowed / lag N."""
    lags = lags if lags is not None else {}
    for block in split_blocks(text, r"^interface\s+\S+"):
        port = "".join(block.splitlines()[0].split()[1:])      # "interface lag 1" -> "lag1"
        if port.lower().startswith("vlan") or port.lower().startswith("loopback"):
            continue
        iface = interfaces.setdefault(port, Interface(port=port))
        for line in block.splitlines()[1:]:
            line = line.strip()
            if m := re.match(r"^vlan access (\d+)", line):
                iface.mode, iface.access_vlan = "access", int(m.group(1))
            elif m := re.match(r"^vlan trunk native (\d+)", line):
                iface.mode, iface.access_vlan = "trunk", int(m.group(1))
            elif m := re.match(r"^vlan trunk allowed (\S+)", line):
                iface.mode = "trunk"
                iface.allowed_raw = m.group(1) if not iface.allowed_raw else \
                    f"{iface.allowed_raw},{m.group(1)}"
                iface.tagged_vlans = sorted(set(iface.tagged_vlans) |
                                            set(expand_vlan_list(m.group(1))))
            elif line == "routing":
                iface.mode = "routed"
            elif m := re.match(r"^lag (\d+)$", line):
                lags.setdefault(f"lag{m.group(1)}", []).append(port)
    for iface in interfaces.values():
        if iface.mode == "trunk" and iface.access_vlan is None:
            iface.access_vlan = 1
        if iface.access_vlan in iface.tagged_vlans:
            iface.tagged_vlans.remove(iface.access_vlan)


def parse_vlans_cx(text: str) -> dict[int, Vlan]:
    vlans = {}
    for line in (text or "").splitlines():
        m = re.match(r"^\s*(\d{1,4})\s+(\S+)\s+(up|down)\b", line, re.IGNORECASE)
        if m:
            vid = int(m.group(1))
            vlans[vid] = Vlan(vlan_id=vid, name=m.group(2))
    return vlans


def parse_svis_cx(text: str, vlans: dict[int, Vlan]) -> None:
    for line in (text or "").splitlines():
        m = re.match(r"^\s*vlan\s?(\d+)\s+(\d+\.\d+\.\d+\.\d+)", line, re.IGNORECASE)
        if m:
            vid = int(m.group(1))
            vlans.setdefault(vid, Vlan(vlan_id=vid)).svi_ip = m.group(2)


# ------------------------------------------------------------------ entrada ---
def parse(outputs: dict[str, str], platform: str) -> ParsedData:
    data = ParsedData()
    g = Guard(data)
    data.arp = g("tabla ARP", generic_arp, outputs.get("arp", ""), default=[])
    if platform == "aruba_aoscx":
        data.neighbors = g("LLDP", parse_lldp_cx, outputs.get("neighbors_lldp", ""), default=[])
        data.macs = g("tabla MAC", parse_mac_cx, outputs.get("mac", ""), default=[])
        data.interfaces = g("estado de puertos", parse_interfaces_cx,
                            outputs.get("interfaces", ""), default={})
        g("configuración de puertos", apply_port_config_cx, outputs.get("port_config", ""),
          data.interfaces, data.lags)
        data.vlans = g("VLANs", parse_vlans_cx, outputs.get("vlans", ""), default={})
        g("SVIs", parse_svis_cx, outputs.get("svis", ""), data.vlans)
    else:
        data.neighbors = g("LLDP", parse_lldp_aoss, outputs.get("neighbors_lldp", ""), default=[])
        data.macs = g("tabla MAC", parse_mac_aoss, outputs.get("mac", ""), default=[])
        data.interfaces = g("estado de puertos", parse_interfaces_aoss,
                            outputs.get("interfaces", ""), default={})
        data.vlans = g("VLANs", parse_vlans_aoss, outputs.get("vlans", ""), default={})
        for key, text in outputs.items():
            if key.startswith("vlan_detail:") and key.split(":")[1].isdigit():
                g(f"VLAN {key.split(':')[1]}", apply_vlan_detail_aoss, int(key.split(":")[1]),
                  text, data.interfaces)
        for iface in data.interfaces.values():
            iface.tagged_vlans.sort()
            iface.mode = tagging_mode(iface)
        g("SVIs", parse_svis_aoss, outputs.get("svis", ""), data.vlans)
        data.lags = g("trunks (LAG)", parse_trunks_aoss, outputs.get("lags", ""), default={})
    return data
