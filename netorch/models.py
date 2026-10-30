"""Modelos de datos normalizados, comunes a todos los vendors."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class Interface:
    port: str
    status: str = "unknown"            # up | down | disabled | unknown
    mode: Optional[str] = None         # access | trunk | routed | None
    access_vlan: Optional[int] = None  # VLAN untagged / nativa
    tagged_vlans: list[int] = field(default_factory=list)
    allowed_raw: Optional[str] = None  # texto original de VLANs permitidas (ej. "1-4094")
    description: Optional[str] = None
    speed: Optional[str] = None


@dataclass
class Neighbor:
    local_port: str
    name: str
    protocol: str                      # CDP | LLDP
    remote_port: Optional[str] = None
    platform: Optional[str] = None     # modelo / system description
    capabilities: list[str] = field(default_factory=list)  # Switch, Router, Phone, AP...
    mgmt_ip: Optional[str] = None
    chassis_mac: Optional[str] = None


@dataclass
class MacEntry:
    mac: str
    port: str
    vlan: Optional[int] = None


@dataclass
class ArpEntry:
    ip: str
    mac: str
    interface: Optional[str] = None


@dataclass
class Vlan:
    vlan_id: int
    name: Optional[str] = None
    svi_ip: Optional[str] = None


@dataclass
class ParsedData:
    """Todo lo que se pudo extraer de un switch en una ejecución."""
    interfaces: dict[str, Interface] = field(default_factory=dict)
    neighbors: list[Neighbor] = field(default_factory=list)
    macs: list[MacEntry] = field(default_factory=list)
    arp: list[ArpEntry] = field(default_factory=list)
    vlans: dict[int, Vlan] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


# Categorías del mapeo final
CAT_INFRA = "Vecino Directo de Infraestructura"
CAT_HOST = "Dispositivo Final (Host)"
CAT_UNMANAGED = "Uplink No Administrado / Hub / Switch no compatible"
CAT_TRUNK_EMPTY = "Trunk sin vecinos ni MACs"
CAT_ROUTED = "Puerto L3 (routed)"
CAT_UP_NO_MAC = "Activo sin MAC aprendida"
CAT_DOWN = "Inactivo"


@dataclass
class PortRow:
    """Una fila de la Tabla Consolidada de Mapeo."""
    port: str
    status: str
    vlan: str
    device_type: str
    category: str
    name: Optional[str] = None
    mac: Optional[str] = None
    ip: Optional[str] = None
    method: Optional[str] = None       # CDP | LLDP | CDP+LLDP | Access MAC | ...
    mac_count: int = 0
    remote_port: Optional[str] = None
    platform: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)
