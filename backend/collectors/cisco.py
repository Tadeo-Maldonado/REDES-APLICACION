from .base import BaseCollector


class CiscoCollector(BaseCollector):
    netmiko_type = "cisco_ios"

    def get_mac_table(self, conn):
        out = conn.send_command("show mac address-table")
        # TODO: parsear (VLAN, MAC, tipo, puerto). Se recomienda use_textfsm=True
        return []

    def get_lldp(self, conn):
        out = conn.send_command("show lldp neighbors detail")
        # TODO: parsear por puerto -> name, description, capabilities
        return {}
