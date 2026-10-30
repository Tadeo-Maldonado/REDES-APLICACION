"""Plataformas soportadas y comandos base por vendor.

Cada comando tiene una "clave" lógica (neighbors_cdp, mac, arp...) y una lista de
alternativas: si la primera devuelve error de sintaxis se prueba la siguiente
(útil entre versiones, p. ej. Alcatel AOS6 vs AOS8).
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Platform:
    key: str
    label: str
    vendor: str            # cisco | aruba | alcatel
    netmiko_type: str
    textfsm_platform: str  # prefijo de ntc-templates
    commands: dict[str, list[str]] = field(default_factory=dict)
    demo_key: str = ""     # carpeta de demo_data a usar si no tiene una propia

    @property
    def demo_dir(self) -> str:
        return self.demo_key or self.key


PLATFORMS: dict[str, Platform] = {
    "cisco_ios": Platform(
        key="cisco_ios", label="Cisco Catalyst · IOS (2960, 3560, 3750, 4500…)", vendor="cisco",
        netmiko_type="cisco_ios", textfsm_platform="cisco_ios",
        commands={
            "neighbors_cdp": ["show cdp neighbors detail"],
            "neighbors_lldp": ["show lldp neighbors detail"],
            "mac": ["show mac address-table", "show mac-address-table"],
            "arp": ["show ip arp"],
            "interfaces": ["show interfaces status"],
            "trunks": ["show interfaces trunk"],
            "vlans": ["show vlan brief"],
            "svis": ["show ip interface brief"],
            "lags": ["show etherchannel summary"],
        },
    ),
    "cisco_xe": Platform(
        key="cisco_xe", label="Cisco Catalyst · IOS-XE (3650, 3850, 9200, 9300, 9400, 9500…)",
        vendor="cisco", netmiko_type="cisco_xe", textfsm_platform="cisco_ios", demo_key="cisco_ios",
        commands={
            "neighbors_cdp": ["show cdp neighbors detail"],
            "neighbors_lldp": ["show lldp neighbors detail"],
            "mac": ["show mac address-table", "show mac-address-table"],
            "arp": ["show ip arp"],
            "interfaces": ["show interfaces status"],
            "trunks": ["show interfaces trunk"],
            "vlans": ["show vlan brief"],
            "svis": ["show ip interface brief"],
            "lags": ["show etherchannel summary"],
        },
    ),
    "cisco_nxos": Platform(
        key="cisco_nxos", label="Cisco Nexus · NX-OS (3000, 5000, 7000, 9000)", vendor="cisco",
        netmiko_type="cisco_nxos", textfsm_platform="cisco_nxos",
        commands={
            "neighbors_cdp": ["show cdp neighbors detail"],
            "neighbors_lldp": ["show lldp neighbors detail"],
            "mac": ["show mac address-table"],
            "arp": ["show ip arp vrf all", "show ip arp"],
            "interfaces": ["show interface status"],
            "trunks": ["show interface trunk"],
            "vlans": ["show vlan brief"],
            "svis": ["show ip interface brief vrf all", "show ip interface brief"],
            "lags": ["show port-channel summary"],
        },
    ),
    "aruba_aoss": Platform(
        key="aruba_aoss", label="Aruba AOS-S / ProCurve (2530, 2930F, 3810, 5400R…)", vendor="aruba",
        netmiko_type="hp_procurve", textfsm_platform="hp_procurve",
        commands={
            "neighbors_lldp": ["show lldp info remote-device detail"],
            "mac": ["show mac-address"],
            "arp": ["show arp"],
            "interfaces": ["show interfaces brief"],
            "vlans": ["show vlans"],
            # Se ejecuta "show vlans <id>" por cada VLAN para saber tagged/untagged
            "vlan_detail": ["show vlans {vlan}"],
            "svis": ["show ip"],
            "lags": ["show trunks"],
        },
    ),
    "aruba_aoscx": Platform(
        key="aruba_aoscx", label="Aruba AOS-CX (6100, 6200, 6300, 6400, 8320…)", vendor="aruba",
        netmiko_type="aruba_aoscx", textfsm_platform="aruba_aoscx",
        commands={
            "neighbors_lldp": ["show lldp neighbor-info detail"],
            "mac": ["show mac-address-table"],
            "arp": ["show arp all-vrfs", "show arp"],
            "interfaces": ["show interface brief"],
            "vlans": ["show vlan"],
            "port_config": ["show running-config interface"],
            "svis": ["show ip interface brief all-vrfs", "show ip interface brief"],
        },
    ),
    "alcatel_aos": Platform(
        key="alcatel_aos", label="Alcatel-Lucent Enterprise AOS 6/8 (OS6860, OS6900, OS6560…)", vendor="alcatel",
        netmiko_type="alcatel_aos", textfsm_platform="alcatel_aos",
        commands={
            "neighbors_lldp": ["show lldp remote-system"],
            "mac": ["show mac-address-table", "show mac-learning"],
            "arp": ["show arp"],
            "interfaces": ["show interfaces status"],
            # Estado real del enlace (up/down) y descripción: status no lo muestra en AOS 8
            "link_status": ["show interfaces alias"],
            "vlans": ["show vlan"],
            "vlan_ports": ["show vlan members", "show vlan port"],
            "svis": ["show ip interface"],
            "lags": ["show linkagg port"],
        },
    ),
}


def platform_label(key: str) -> str:
    """Etiqueta legible; tolera claves de versiones anteriores de la app."""
    p = PLATFORMS.get(key or "")
    return p.label if p else (key or "desconocida")


def platform_choices() -> dict[str, str]:
    return {k: p.label for k, p in PLATFORMS.items()}


_HINTS = [   # (palabras clave, plataforma) en orden de prioridad
    (("nexus", "nx-os", "nxos", "n9k", "n7k", "n5k", "n3k"), "cisco_nxos"),
    (("ios-xe", "iosxe", "ios xe", "cisco_xe", "c9", "cat9", "9200", "9300", "9400", "9500",
      "9600", "3650", "3850"), "cisco_xe"),
    (("aos-cx", "aoscx", "aruba cx", "aruba_aoscx", "6100", "6200", "6300", "6400", "8320",
      "8325", "8360"), "aruba_aoscx"),
    (("cisco", "catalyst", "ios", "2960", "3560", "3750", "4500", "6500"), "cisco_ios"),
    (("aruba", "procurve", "aos-s", "aoss", "2530", "2930", "3810", "5400", "hpe", "hp "),
     "aruba_aoss"),
    (("alcatel", "omniswitch", "omni", "ale ", "os6", "os9", "aos6", "aos8"), "alcatel_aos"),
]


def platform_from_text(text) -> str | None:
    """Clave, etiqueta o texto aproximado (p. ej. 'Catalyst 9300', 'nexus', 'OS6860') -> plataforma."""
    t = str(text or "").strip().lower()
    if not t or t == "nan":
        return None
    if t in PLATFORMS:
        return t
    for key, p in PLATFORMS.items():
        if t == p.label.lower():
            return key
    padded = t + " "
    for words, key in _HINTS:
        if any(w in padded for w in words):
            return key
    return None
