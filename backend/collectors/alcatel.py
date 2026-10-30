from .base import BaseCollector


class AlcatelCollector(BaseCollector):
    netmiko_type = "alcatel_aos"

    def get_mac_table(self, conn):
        out = conn.send_command("show mac-learning")
        # TODO: parsear (VLAN, MAC, puerto)
        return []

    def get_lldp(self, conn):
        out = conn.send_command("show lldp remote-system")
        # TODO: parsear por puerto -> name, description, capabilities
        return {}
