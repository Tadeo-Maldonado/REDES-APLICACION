import re


def normalize_mac(mac: str) -> str:
    """Convierte cualquier formato (aabb.ccdd.eeff, AA-BB-..., etc.) a aa:bb:cc:dd:ee:ff."""
    hex_only = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    if len(hex_only) != 12:
        raise ValueError(f"MAC inválida: {mac}")
    return ":".join(hex_only[i:i + 2] for i in range(0, 12, 2))
