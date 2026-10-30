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


PLATFORMS: dict[str, Platform] = {
    "cisco_ios": Platform(
        key="cisco_ios", label="Cisco IOS / IOS-XE", vendor="cisco",
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
        },
    ),
    "cisco_nxos": Platform(
        key="cisco_nxos", label="Cisco NX-OS", vendor="cisco",
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
        },
    ),
    "aruba_aoss": Platform(
        key="aruba_aoss", label="Aruba AOS-S (ProCurve)", vendor="aruba",
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
        },
    ),
    "aruba_aoscx": Platform(
        key="aruba_aoscx", label="Aruba AOS-CX", vendor="aruba",
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
        key="alcatel_aos", label="Alcatel-Lucent Enterprise AOS (6/8)", vendor="alcatel",
        netmiko_type="alcatel_aos", textfsm_platform="alcatel_aos",
        commands={
            "neighbors_lldp": ["show lldp remote-system"],
            "mac": ["show mac-address-table", "show mac-learning"],
            "arp": ["show arp"],
            "interfaces": ["show interfaces status"],
            "vlans": ["show vlan"],
            "vlan_ports": ["show vlan members", "show vlan port"],
            "svis": ["show ip interface"],
        },
    ),
}


def platform_choices() -> dict[str, str]:
    return {k: p.label for k, p in PLATFORMS.items()}
