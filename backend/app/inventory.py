"""Carga el inventario predefinido de switches (switches.yaml)."""
import os
from pathlib import Path
import yaml
from dotenv import load_dotenv

BASE = Path(__file__).resolve().parent.parent
load_dotenv(BASE / ".env")


def load_switches() -> list[dict]:
    path = BASE / "switches.yaml"
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    switches = data["switches"]
    for sw in switches:
        sw["username"] = os.environ[sw["username_env"]]
        sw["password"] = os.environ[sw["password_env"]]
    return switches
