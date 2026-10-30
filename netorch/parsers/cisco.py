"""Parsers para Cisco IOS / IOS-XE / NX-OS."""
from __future__ import annotations

import re

from ..models import Interface, MacEntry, Neighbor, ParsedData, Vlan
from ..utils import (IPV4, MAC_ANY, expand_vlan_list, mac_from_cisco_phone_name,
                     normalize_mac, normalize_port)
from .common import (Guard, clean_mac_entries, first_ip, generic_arp, kv, normalize_caps,
                     split_blocks, textfsm_macs, textfsm_parse, pick)

STATUS_WORDS = {
    "connected": "up", "up": "up",
    "notconnect": "down", "notconnec": "down", "down": "down", "sfpabsent": "down",
    "xcvrabsent": "down", "xcvrabsen": "down", "nooperm": "down", "nooper": "down",
    "inactive": "down", "suspended": "down", "suspnd": "down", "monitoring": "up",
    "faulty": "down", "linkflapdisabled": "disabled",
    "disabled": "disabled", "err-disabled": "err-disabled", "err-disabl": "err-disabled",
}


def parse_cdp(text: str) -> list[Neighbor]:
    neighbors = []
    for block in split_blocks(text, r"^\s*Device ID\s*:"):
        name = kv(block, "Device ID")
        local = re.search(r"Interface\s*:\s*([^,]+),", block)
        if not name or not local:
            continue
        remote = re.search(r"Port ID \(outgoing port\)\s*:\s*(.+?)\s*$", block, re.MULTILINE)
        platform = re.search(r"Platform\s*:\s*([^,]+?)\s*,", block)
        caps = re.search(r"Capabilities\s*:\s*(.+)$", block, re.MULTILINE)
        ip_section = re.search(r"(?:Entry|Interface|Management) address\(es\)\s*:(.*?)(?:\n\S|\Z)",
                               block, re.DOTALL | re.IGNORECASE)
        mgmt_ip = first_ip(ip_section.group(1)) if ip_section else first_ip(block)
        neighbors.append(Neighbor(
            local_port=normalize_port(local.group(1)),
            name=name.strip(),
            protocol="CDP",
            remote_port=normalize_port(remote.group(1)) if remote else None,
            platform=platform.group(1).strip() if platform else None,
            capabilities=normalize_caps(caps.group(1) if caps else ""),
            mgmt_ip=mgmt_ip,
            chassis_mac=mac_from_cisco_phone_name(name),
        ))
    return neighbors


def parse_lldp(text: str) -> list[Neighbor]:
    neighbors = []
    for block in split_blocks(text, r"^\s*Local (?:Intf|Port id)\s*:"):
        local = kv(block, "Local Intf", "Local Port id")
        name = kv(block, "System Name")
        chassis = kv(block, "Chassis id")
        if not local:
            continue
        sysdesc = re.search(r"System Description\s*:\s*\n?(.*?)(?:\n\s*\n|\n\s*Time remaining)",
                            block, re.DOTALL)
        caps = kv(block, "Enabled Capabilities") or kv(block, "System Capabilities")
        mgmt = re.search(r"Management Address(?:es)?\s*:?(.*?)(?:\n\s*\n|\nAuto|\nVlan|\Z)",
                         block, re.DOTALL | re.IGNORECASE)
        chassis_mac = normalize_mac(chassis) if chassis and MAC_ANY.search(chassis) else None
        neighbors.append(Neighbor(
            local_port=normalize_port(local),
            name=(name if name and name.lower() not in ("not advertised", "null") else None)
                 or chassis or "desconocido",
            protocol="LLDP",
            remote_port=kv(block, "Port id"),
            platform=" ".join(sysdesc.group(1).split())[:200] if sysdesc else None,
            capabilities=normalize_caps(caps),
            mgmt_ip=first_ip(mgmt.group(1)) if mgmt else None,
            chassis_mac=chassis_mac,
        ))
    return neighbors


def parse_mac(text: str, platform: str = "cisco_ios") -> list[MacEntry]:
    out = []
    for line in (text or "").splitlines():
        m = re.match(r"^[\s*+GROCV~]*?(\d+|All|N/A|-)\s+([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+(.*)$",
                     line.strip())
        if not m or not m.group(1).isdigit():
            continue
        tokens = m.group(3).split()
        if not tokens:
            continue
        port = tokens[-1].split(",")[0]
        out.append(MacEntry(mac=normalize_mac(m.group(2)), port=normalize_port(port),
                            vlan=int(m.group(1))))
    entries = clean_mac_entries(out)
    if not entries and text and text.strip():
        entries = textfsm_macs(platform, "show mac address-table", text)
    return entries


def _status_positions(header: str) -> dict[str, int]:
    cols = {}
    for name in ("Port", "Name", "Status", "Vlan", "Duplex", "Speed", "Type"):
        idx = header.find(name)
        if idx >= 0:
            cols[name] = idx
    return cols


def parse_interfaces_status(text: str) -> dict[str, Interface]:
    """'show interfaces status' (IOS) / 'show interface status' (NX-OS), por columnas."""
    result: dict[str, Interface] = {}
    lines = (text or "").splitlines()
    cols = {}
    for line in lines:
        if re.match(r"^\s*Port\s+Name\s+Status\s+Vlan", line):
            cols = _status_positions(line)
            continue
        if not cols or not line.strip() or line.startswith("-"):
            continue
        port = line.split()[0]
        if not re.match(r"^[A-Za-z]+[\d/.:]+$", port):
            continue
        # Lectura por columnas: la descripción puede tener espacios
        def col(name, nxt):
            a = cols.get(name)
            b = cols.get(nxt) if nxt else None
            if a is None:
                return ""
            return line[a:b].strip() if b else line[a:].strip()
        status_raw = col("Status", "Vlan").split()[0] if col("Status", "Vlan") else ""
        vlan_raw = col("Vlan", "Duplex").split()[0] if col("Vlan", "Duplex") else ""
        # Respaldo si las columnas están corridas
        if status_raw.lower() not in STATUS_WORDS:
            for tok in line.split()[1:]:
                if tok.lower() in STATUS_WORDS:
                    status_raw = tok
                    after = line.split()[line.split().index(tok) + 1:]
                    vlan_raw = after[0] if after else ""
                    break
        iface = Interface(port=normalize_port(port),
                          status=STATUS_WORDS.get(status_raw.lower(), "unknown"),
                          description=col("Name", "Status") or None,
                          speed=col("Speed", "Type") or None)
        vl = vlan_raw.lower()
        if vl == "trunk":
            iface.mode = "trunk"
        elif vl == "routed":
            iface.mode = "routed"
        elif vl.isdigit():
            iface.mode = "access"
            iface.access_vlan = int(vl)
        result[iface.port] = iface
    return result


def parse_trunks(text: str, interfaces: dict[str, Interface]) -> None:
    """Completa VLAN nativa y VLANs permitidas en los trunks."""
    section = None
    for line in (text or "").splitlines():
        low = line.lower().strip()
        if not low or low.startswith("---") or low.startswith("vlan"):
            continue
        if low.startswith("port "):            # encabezado de sección
            if "native" in low and "mode" in low:
                section = "native_ios"
            elif "native" in low:
                section = "native_nxos"
            elif "allowed on trunk" in low:
                section = "allowed"
            else:
                section = None
            continue
        parts = line.split()
        if section is None or not re.match(r"^[A-Za-z]+[\d/.:]+$", parts[0]):
            continue
        port = normalize_port(parts[0])
        iface = interfaces.setdefault(port, Interface(port=port))
        if section == "native_ios" and len(parts) >= 5 and parts[-1].isdigit():
            iface.mode = "trunk"
            iface.access_vlan = int(parts[-1])
        elif section == "native_nxos" and len(parts) >= 2 and parts[1].isdigit():
            iface.mode = "trunk"
            iface.access_vlan = int(parts[1])
        elif section == "allowed" and len(parts) >= 2:
            iface.mode = "trunk"
            iface.allowed_raw = parts[1]
            iface.tagged_vlans = [v for v in expand_vlan_list(parts[1]) if v != iface.access_vlan]


def parse_vlans(text: str) -> dict[int, Vlan]:
    vlans = {}
    for line in (text or "").splitlines():
        m = re.match(r"^(\d{1,4})\s+(\S+)\s+(active|act/lshut|act/unsup|suspended|act/ishut|sus/lshut)",
                     line.strip())
        if m:
            vid = int(m.group(1))
            if 1002 <= vid <= 1005:      # VLANs legacy FDDI/Token Ring
                continue
            vlans[vid] = Vlan(vlan_id=vid, name=m.group(2))
    return vlans


def parse_svis(text: str, vlans: dict[int, Vlan]) -> None:
    for line in (text or "").splitlines():
        m = re.match(r"^\s*Vlan(\d+)\s+(\S+)", line, re.IGNORECASE)
        if m and IPV4.match(m.group(2)):
            vid = int(m.group(1))
            vlans.setdefault(vid, Vlan(vlan_id=vid)).svi_ip = m.group(2)


def parse_lags(text: str) -> dict[str, list[str]]:
    """'show etherchannel summary' (IOS) / 'show port-channel summary' (NX-OS).

    Ej.:  1      Po1(SU)         LACP      Gi1/0/47(P)  Gi1/0/48(P)
    Los miembros pueden continuar en la línea siguiente.
    """
    lags: dict[str, list[str]] = {}
    current = None
    for line in (text or "").splitlines():
        m = re.search(r"\b(Po\d+)\(\w+\)", line)
        if m:
            current = normalize_port(m.group(1))
            lags[current] = []
        elif not (current and line[:1].isspace() and line.strip()):
            current = None          # encabezados, líneas en blanco, etc.
            continue
        for tok in line.split():
            mm = re.match(r"^([A-Za-z]+[\d/.:]+)\((\w+)\)$", tok)
            if mm and not tok.startswith("Po"):
                lags[current].append(normalize_port(mm.group(1)))
    return {k: v for k, v in lags.items() if v}


def _textfsm_neighbors(platform: str, command: str, text: str, proto: str) -> list[Neighbor]:
    out = []
    for r in textfsm_parse(platform, command, text):
        local = pick(r, "local_interface", "local_port")
        name = pick(r, "neighbor_name", "destination_host", "neighbor", "system_name")
        if not local or not name:
            continue
        out.append(Neighbor(
            local_port=normalize_port(local), name=name, protocol=proto,
            remote_port=pick(r, "neighbor_interface", "remote_port", "neighbor_port_id"),
            platform=pick(r, "platform", "neighbor_description", "system_description"),
            capabilities=normalize_caps(pick(r, "capabilities", "capabilities_enabled") or ""),
            mgmt_ip=pick(r, "mgmt_address", "management_ip", "mgmt_ip", "management_address"),
        ))
    return out


def parse(outputs: dict[str, str], platform: str) -> ParsedData:
    data = ParsedData()
    g = Guard(data)
    cdp_text = outputs.get("neighbors_cdp", "")
    lldp_text = outputs.get("neighbors_lldp", "")
    cdp = g("show cdp neighbors detail", parse_cdp, cdp_text, default=[]) or \
        g("CDP (TextFSM)", _textfsm_neighbors, platform, "show cdp neighbors detail", cdp_text,
          "CDP", default=[])
    lldp = g("show lldp neighbors detail", parse_lldp, lldp_text, default=[]) or \
        g("LLDP (TextFSM)", _textfsm_neighbors, platform, "show lldp neighbors detail", lldp_text,
          "LLDP", default=[])
    data.neighbors = cdp + lldp
    data.macs = g("tabla MAC", parse_mac, outputs.get("mac", ""), platform, default=[])
    data.arp = g("tabla ARP", generic_arp, outputs.get("arp", ""), default=[])
    data.interfaces = g("estado de puertos", parse_interfaces_status,
                        outputs.get("interfaces", ""), default={})
    g("trunks", parse_trunks, outputs.get("trunks", ""), data.interfaces)
    data.vlans = g("VLANs", parse_vlans, outputs.get("vlans", ""), default={})
    g("SVIs", parse_svis, outputs.get("svis", ""), data.vlans)
    data.lags = g("port-channels", parse_lags, outputs.get("lags", ""), default={})
    if outputs.get("interfaces") and not data.interfaces:
        data.warnings.append("No se pudo interpretar el estado de puertos (show interfaces status).")
    return data
