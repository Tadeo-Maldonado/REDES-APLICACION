"""Clasifica PC / SW / FW con reglas del archivo config/classification.json.
El archivo se relee si cambia, así se ajustan reglas sin reiniciar el servidor."""
import json
import re
from pathlib import Path

CONFIG = Path(__file__).resolve().parent.parent / "config" / "classification.json"
_cache = {"mtime": None, "data": {"default": "PC", "rules": []}}


def _load() -> dict:
    mtime = CONFIG.stat().st_mtime
    if _cache["mtime"] != mtime:
        _cache["data"] = json.loads(CONFIG.read_text(encoding="utf-8"))
        _cache["mtime"] = mtime
    return _cache["data"]


def classify(name: str = "", description: str = "", capabilities=None, vendor: str = "") -> str:
    cfg = _load()
    capabilities = set(capabilities or [])
    text = f"{description} {vendor}".lower()
    for rule in cfg["rules"]:
        if any(k.lower() in text for k in rule.get("keywords", [])):
            return rule["type"]
        if any(re.search(rx, name or "", re.I) for rx in rule.get("name_regex", [])):
            return rule["type"]
        if capabilities & set(rule.get("capabilities", [])):
            return rule["type"]
    return cfg.get("default", "PC")
