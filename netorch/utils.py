"""Utilidades de normalización (MACs, nombres de interfaz, rangos de VLAN/puertos)."""
from __future__ import annotations

import re
from typing import Optional

MAC_ANY = re.compile(
    r"\b([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}"      # 0011.2233.4455 (Cisco)
    r"|[0-9a-fA-F]{6}-[0-9a-fA-F]{6}"                          # 001122-334455 (Aruba AOS-S)
    r"|(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}"                 # 00:11:22:33:44:55
    r"|(?:[0-9a-fA-F]{2} ){5}[0-9a-fA-F]{2})\b"                 # 00 11 22 33 44 55 (LLDP AOS-S)
)
IPV4 = re.compile(r"\b((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})\b")


def normalize_mac(mac: str) -> Optional[str]:
    """Cualquier formato -> aa:bb:cc:dd:ee:ff. Devuelve None si no es una MAC."""
    if not mac:
        return None
    hex_only = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    if len(hex_only) != 12:
        return None
    return ":".join(hex_only[i:i + 2] for i in range(0, 12, 2))


def is_multicast_or_special(mac: str) -> bool:
    """MACs que nunca son un host real (multicast, broadcast, todo ceros)."""
    first = int(mac[:2], 16)
    return bool(first & 1) or mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00")


# Nombres largos de interfaz Cisco -> forma corta (como en "show mac address-table")
_IF_ABBR = [
    ("hundredgigabitethernet", "Hu"), ("hundredgige", "Hu"),
    ("fortygigabitethernet", "Fo"), ("fortygige", "Fo"),
    ("twentyfivegigabitethernet", "Twe"), ("twentyfivegige", "Twe"),
    ("tengigabitethernet", "Te"), ("tengige", "Te"),
    ("fivegigabitethernet", "Fi"), ("twogigabitethernet", "Tw"),
    ("appgigabitethernet", "Ap"), ("gigabitethernet", "Gi"),
    ("fastethernet", "Fa"), ("port-channel", "Po"), ("ethernet", "Eth"),
    ("vlan", "Vlan"), ("loopback", "Lo"), ("mgmt", "mgmt"),
]


def normalize_port(port: str) -> str:
    """Unifica nombres de puerto: 'GigabitEthernet1/0/1' -> 'Gi1/0/1', 'Eth1/1' igual.

    Puertos de Aruba/Alcatel (1, A1, 1/1/1, lag1) se devuelven tal cual (sin espacios).
    """
    if not port:
        return port
    p = port.strip().rstrip(",")
    low = p.lower()
    for long, short in _IF_ABBR:
        if low.startswith(long):
            return short + p[len(long):].strip()
    # Formas cortas ya abreviadas con distinta capitalización (gi1/0/1, ETH1/1, po1)
    m = re.match(r"^(gi|fa|te|tw|twe|fo|hu|ap|po|eth|fi)(\d.*)$", low)
    if m:
        abbr = {"gi": "Gi", "fa": "Fa", "te": "Te", "tw": "Tw", "twe": "Twe", "fo": "Fo",
                "hu": "Hu", "ap": "Ap", "po": "Po", "eth": "Eth", "fi": "Fi"}[m.group(1)]
        return abbr + p[len(m.group(1)):]
    return p


def expand_vlan_list(text: str) -> list[int]:
    """'1,10-12,20' -> [1, 10, 11, 12, 20]. Ignora 'none'/'all' y rangos gigantes."""
    vlans: set[int] = set()
    if not text:
        return []
    for part in re.split(r"[,\s]+", text.strip()):
        if not part or part.lower() in ("none", "all", "--"):
            continue
        m = re.match(r"^(\d+)-(\d+)$", part)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            if b - a > 1000:          # "1-4094": no se expande, se reporta como texto
                continue
            vlans.update(range(a, b + 1))
        elif part.isdigit():
            vlans.add(int(part))
    return sorted(vlans)


def compact_vlan_list(vlans: list[int]) -> str:
    """[1, 10, 11, 12, 20] -> '1,10-12,20'."""
    if not vlans:
        return ""
    vlans = sorted(set(vlans))
    out, start, prev = [], vlans[0], vlans[0]
    for v in vlans[1:]:
        if v == prev + 1:
            prev = v
            continue
        out.append(f"{start}-{prev}" if start != prev else str(start))
        start = prev = v
    out.append(f"{start}-{prev}" if start != prev else str(start))
    return ",".join(out)


def expand_port_list(text: str) -> list[str]:
    """Rangos de puertos de Aruba AOS-S / CX: '1-4,A1-A2,Trk1,1/1/1-1/1/3'."""
    ports: list[str] = []
    for part in re.split(r"[,\s]+", (text or "").strip()):
        if not part:
            continue
        m = re.match(r"^([A-Za-z]*)(\d+)-\1?(\d+)$", part)                 # 1-4, A1-A4
        m2 = re.match(r"^((?:\d+/)+)(\d+)-\1?(\d+)$", part)                # 1/1/1-1/1/3
        if m2:
            pre, a, b = m2.group(1), int(m2.group(2)), int(m2.group(3))
            ports += [f"{pre}{i}" for i in range(a, b + 1)]
        elif m:
            pre, a, b = m.group(1), int(m.group(2)), int(m.group(3))
            ports += [f"{pre}{i}" for i in range(a, b + 1)]
        else:
            ports.append(part)
    return ports


def short_hostname(name: Optional[str]) -> str:
    """'SW-CORE.lab.local(FOC123)' -> 'sw-core' (para empatar nombres entre CDP/LLDP)."""
    if not name:
        return ""
    n = re.sub(r"\(.*?\)", "", name).strip()
    if not IPV4.fullmatch(n):
        n = n.split(".")[0]
    return n.lower()


def mac_from_cisco_phone_name(name: str) -> Optional[str]:
    """Los IP Phone Cisco se anuncian como 'SEP001122334455': la MAC va en el nombre."""
    m = re.match(r"^SEP([0-9A-Fa-f]{12})$", (name or "").strip())
    return normalize_mac(m.group(1)) if m else None


ERROR_MARKERS = ("% invalid", "invalid input", "unknown command", "invalid command",
                 "% incomplete", "error: ", "not supported", "% ambiguous",
                 "unrecognized command", "syntax error", "command not found")


def looks_like_error(output: str) -> bool:
    """¿La salida es un error de sintaxis del CLI (comando no soportado)?"""
    head = (output or "").strip().lower()[:400]
    return any(marker in head for marker in ERROR_MARKERS)
