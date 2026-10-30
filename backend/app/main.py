"""API: consulta los switches predefinidos por SSH. No hace escaneos."""
from fastapi import FastAPI

from .inventory import load_switches
from .collectors import COLLECTORS

app = FastAPI(title="REDES-APLICACION")


@app.get("/api/switches")
def list_switches():
    return [{"name": s["name"], "host": s["host"], "vendor": s["vendor"]}
            for s in load_switches()]


@app.get("/api/connections")
def connections(switch: str | None = None):
    """Qué hay conectado (PC / SW / FW) y su MAC, por puerto."""
    result = []
    for sw in load_switches():
        if switch and sw["name"] != switch:
            continue
        collector = COLLECTORS[sw["vendor"]](sw)
        result += [c.to_dict() for c in collector.collect()]
    return result
