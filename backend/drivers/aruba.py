import re
from . import register
from .base import BaseDriver

MAC_RE = re.compile(r"^\s*([0-9a-f]{6}-[0-9a-f]{6})\s+(\S+)\s+(\d+)\s*$", re.I | re.M)
LLDP_RE = re.compile(
    r"^\s*(\S+)\s*\|\s*((?:[0-9a-f]{2}[ -]){5}[0-9a-f]{2})\s+(\S+)\s+(\S+)\s+(.*?)\s*$", re.I | re.M)


@register
class ArubaDriver(BaseDriver):
    """ArubaOS-Switch (ProCurve). Para AOS-CX se crea otro driver con sus comandos."""
    name = "aruba"
    label = "Aruba (ArubaOS-Switch)"
    netmiko_type = "hp_procurve"
    commands = {"mac_table": "show mac-address", "lldp": "show lldp info remote-device"}

    def parse_mac_table(self, text):
        return [{"mac": m, "port": p, "vlan": int(v)} for m, p, v in MAC_RE.findall(text)]

    def parse_lldp(self, text):
        # La tabla resumida no trae descripción ni capacidades; se clasifica por nombre.
        return [{"port": p, "chassis": c, "name": n, "description": "", "capabilities": []}
                for p, c, _pid, _pd, n in LLDP_RE.findall(text)]
