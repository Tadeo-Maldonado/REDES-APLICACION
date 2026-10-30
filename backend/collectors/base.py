"""Clase base: cada fabricante solo implementa 3 cosas (comandos + parseo)."""
from abc import ABC, abstractmethod
from netmiko import ConnectHandler

from models import Connection
from classifier import classify


class BaseCollector(ABC):
    netmiko_type: str = ""  # tipo de dispositivo para netmiko

    def __init__(self, sw: dict):
        self.sw = sw

    # --- Lo que cambia por fabricante -------------------------------------
    @abstractmethod
    def get_mac_table(self, conn) -> list[Connection]:
        """Ejecuta el comando de tabla MAC y devuelve (puerto, mac, vlan)."""

    @abstractmethod
    def get_lldp(self, conn) -> dict[str, dict]:
        """Devuelve {puerto: {'name':..., 'description':..., 'caps': 'B,R'}}."""

    # --- Lo común ---------------------------------------------------------
    def collect(self) -> list[Connection]:
        params = {
            "device_type": self.netmiko_type,
            "host": self.sw["host"],
            "username": self.sw["username"],
            "password": self.sw["password"],
        }
        with ConnectHandler(**params) as conn:     # SSH solo a este switch
            entries = self.get_mac_table(conn)
            lldp = self.get_lldp(conn)

        result = []
        for e in entries:
            e.switch = self.sw["name"]
            info = lldp.get(e.port, {})
            e.name = info.get("name")
            e.description = info.get("description")
            result.append(classify(e, info.get("caps", "")))
        return result
