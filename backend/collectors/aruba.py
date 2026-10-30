from .base import BaseCollector


class ArubaCollector(BaseCollector):
    # ArubaOS-Switch (ProCurve): "hp_procurve". Si son AOS-CX, revisar el tipo
    # soportado por la versión de netmiko instalada.
    netmiko_type = "hp_procurve"

    def get_mac_table(self, conn):
        out = conn.send_command("show mac-address")
        # TODO: parsear (MAC, puerto, VLAN)
        return []

    def get_lldp(self, conn):
        out = conn.send_command("show lldp info remote-device")
        # TODO: parsear por puerto -> name, description, capabilities
        return {}
