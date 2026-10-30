import re
from . import register
from .base import BaseDriver
from core.utils import normalize_caps

MAC_RE = re.compile(
    r"^\s*VLAN\s+(\d+)\s+((?:[0-9a-f]{2}:){5}[0-9a-f]{2})\s+\S+\s+\S+\s+(\S+)\s*$", re.I | re.M)


@register
class AlcatelDriver(BaseDriver):
    name = "alcatel"
    label = "Alcatel-Lucent Enterprise (AOS)"
    netmiko_type = "alcatel_aos"
    commands = {"mac_table": "show mac-learning", "lldp": "show lldp remote-system"}

    def parse_mac_table(self, text):
        return [{"vlan": int(v), "mac": m, "port": p} for v, m, p in MAC_RE.findall(text)]

    def parse_lldp(self, text):
        out = []
        parts = re.split(r"Remote LLDP nearest-bridge Agents on Local Port\s+(\S+?):", text)
        for port, block in zip(parts[1::2], parts[2::2]):
            g = lambda rx: (re.search(rx, block, re.M) or [None, ""])[1].strip()
            out.append({
                "port": port,
                "chassis": g(r"Chassis\s+(\S+?),"),
                "name": g(r"System Name\s*=\s*(.*?)[,;]?\s*$"),
                "description": g(r"System Description\s*=\s*(.*?)[,;]?\s*$"),
                "capabilities": normalize_caps(g(r"System Capabilities\s*=\s*(.*?)[,;]?\s*$")),
            })
        return out
