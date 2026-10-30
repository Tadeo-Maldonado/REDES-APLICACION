"""Modelo de datos simple: todo se reduce a 'qué MAC hay en qué puerto'."""
from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class Connection:
    switch: str                   # nombre del switch donde se vio
    port: str                     # puerto del switch (ej. Gi1/0/5, 1/1/3, 1/1)
    mac: str                      # MAC normalizada: aa:bb:cc:dd:ee:ff
    vlan: Optional[int] = None
    kind: str = "PC"              # PC | SW | FW  (lo decide classifier.py)
    name: Optional[str] = None    # hostname si LLDP/CDP lo informa
    description: Optional[str] = None  # system description de LLDP/CDP
    ip: Optional[str] = None      # opcional (tabla ARP)

    def to_dict(self):
        return asdict(self)
