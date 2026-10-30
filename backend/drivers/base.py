class BaseDriver:
    """Un driver por fabricante: qué comandos correr y cómo leer la salida."""
    name = ""            # id corto: "cisco"
    label = ""           # nombre para mostrar
    netmiko_type = ""    # device_type de netmiko
    commands = {"mac_table": "", "lldp": ""}

    def parse_mac_table(self, text: str) -> list[dict]:
        """-> [{'mac': str, 'port': str, 'vlan': int|None}]"""
        raise NotImplementedError

    def parse_lldp(self, text: str) -> list[dict]:
        """-> [{'port', 'chassis', 'name', 'description', 'capabilities': [..]}]"""
        raise NotImplementedError
