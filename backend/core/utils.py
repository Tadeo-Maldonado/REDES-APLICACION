import re
from typing import Optional

_CAP_WORDS = {
    "bridge": "B", "router": "R", "wlan": "W", "station": "S",
    "telephone": "T", "repeater": "P", "docsis": "D", "other": "O",
}


def try_mac(value: str) -> Optional[str]:
    """Devuelve la MAC como aa:bb:cc:dd:ee:ff, o None si no es una MAC."""
    hex_only = re.sub(r"[^0-9a-fA-F]", "", value or "")
    if len(hex_only) != 12:
        return None
    return ":".join(hex_only[i:i + 2] for i in range(0, 12, 2)).lower()


def normalize_caps(value: str) -> list[str]:
    """'B,R' o 'bridge router' -> ['B', 'R']."""
    caps = set()
    for tok in re.split(r"[,\s]+", (value or "").strip()):
        if not tok:
            continue
        caps.add(tok.upper() if len(tok) == 1 else _CAP_WORDS.get(tok.lower(), tok[0].upper()))
    return sorted(caps)
