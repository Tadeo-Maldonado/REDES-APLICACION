"""Despacha la salida cruda de cada comando al parser del vendor correspondiente."""
from __future__ import annotations

from ..commands import PLATFORMS
from ..models import ParsedData
from . import alcatel, aruba, cisco

_BY_VENDOR = {"cisco": cisco.parse, "aruba": aruba.parse, "alcatel": alcatel.parse}


def parse_outputs(platform_key: str, outputs: dict[str, str]) -> ParsedData:
    """outputs: {clave_lógica: salida_cruda}, p. ej. {'mac': '...', 'arp': '...'}."""
    platform = PLATFORMS[platform_key]
    return _BY_VENDOR[platform.vendor](outputs, platform_key)
