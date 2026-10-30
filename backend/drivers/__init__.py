"""Registro de drivers. Para soportar un fabricante nuevo basta crear un archivo
en esta carpeta con una clase decorada con @register; se detecta solo."""
import importlib
import pkgutil

REGISTRY: dict = {}


def register(cls):
    REGISTRY[cls.name] = cls
    return cls


def get_driver(name: str):
    if name not in REGISTRY:
        raise ValueError(f"Fabricante no soportado: {name}")
    return REGISTRY[name]


def list_drivers() -> list[dict]:
    return [{"id": c.name, "label": c.label} for c in REGISTRY.values()]


for _m in pkgutil.iter_modules(__path__):
    if _m.name != "base":
        importlib.import_module(f"{__name__}.{_m.name}")
