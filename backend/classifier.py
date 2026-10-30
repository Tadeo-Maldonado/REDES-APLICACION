"""Decide si una MAC es PC, SW o FW. Reglas simples y fáciles de ajustar."""
from models import Connection

FW_KEYWORDS = ("fortigate", "palo alto", "pan-os", "asa", "firepower", "sophos", "checkpoint")
SW_KEYWORDS = ("switch", "aos", "arubaos", "ios", "catalyst", "omniswitch")


def classify(conn: Connection, lldp_caps: str = "") -> Connection:
    """lldp_caps: capacidades anunciadas por LLDP, ej. 'B,R' (Bridge, Router)."""
    text = (conn.description or "").lower()

    if any(k in text for k in FW_KEYWORDS):
        conn.kind = "FW"
    elif "B" in lldp_caps.upper() or any(k in text for k in SW_KEYWORDS):
        conn.kind = "SW"
    else:
        conn.kind = "PC"
    return conn
