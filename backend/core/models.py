from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class Connection:
    """Una fila = una MAC vista en un puerto de un switch."""
    switch: str
    port: str
    mac: str = ""
    vlan: Optional[int] = None
    kind: str = "PC"                 # PC | SW | FW (lo definen las reglas JSON)
    name: str = ""                   # System Name (LLDP)
    description: str = ""            # System Description (LLDP)
    capabilities: list[str] = field(default_factory=list)
    vendor: str = ""                 # fabricante por OUI (opcional)
    neighbor: bool = False           # True si viene de LLDP (equipo directo)
    via_uplink: bool = False         # True si está detrás de un puerto con otro SW/FW

    def to_dict(self) -> dict:
        return asdict(self)
