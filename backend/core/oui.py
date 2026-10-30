"""Fabricante por MAC. Opcional: solo si OUI_LOOKUP=1 y está instalado mac-vendor-lookup."""
import os

_lookup = None


def vendor_of(mac: str) -> str:
    global _lookup
    if os.environ.get("OUI_LOOKUP") != "1" or not mac:
        return ""
    try:
        if _lookup is None:
            from mac_vendor_lookup import MacLookup
            _lookup = MacLookup()
        return _lookup.lookup(mac)
    except Exception:
        return ""
