import re
from . import register
from .base import BaseDriver
from core.utils import normalize_caps

MAC_RE = re.compile(
    r"^\s*(\d+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+\S+\s+(\S+)\s*$", re.I | re.M)


@register
class CiscoDriver(BaseDriver):
    name = "cisco"
    label = "Cisco IOS / IOS-XE"
    netmiko_type = "cisco_ios"
    commands = {"mac_table": "show mac address-table", "lldp": "show lldp neighbors detail"}

    def parse_mac_table(self, text):
        return [{"vlan": int(v), "mac": m, "port": p}
                for v, m, p in MAC_RE.findall(text) if p.upper() != "CPU"]

    def parse_lldp(self, text):
        out = []
        for block in re.split(r"^-{10,}\s*$", text, flags=re.M):
            port = re.search(r"Local Intf:\s*(\S+)", block)
            if not port:
                continue
            g = lambda rx, fl=re.M: (re.search(rx, block, fl) or [None, ""])[1].strip()
            out.append({
                "port": port.group(1),
                "chassis": g(r"Chassis id:\s*(\S+)"),
                "name": g(r"System Name:\s*(.*)$"),
                "description": " ".join(g(
                    r"System Description:\s*(.*?)\s*(?=Time remaining:|System Capabilities:|Enabled Capabilities:|$)",
                    re.S).split()),
                "capabilities": normalize_caps(g(r"Enabled Capabilities:\s*([A-Za-z,]+)")),
            })
        return out
