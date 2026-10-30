"""API REDES-APLICACION. Lee switches por SSH (o datos demo). No escanea la red
y no guarda datos de los switches: las credenciales llegan en cada petición y se descartan.

Ejecutar desde esta carpeta:  uvicorn main:app --reload   ->  http://localhost:8000
"""
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from core.collector import collect_all
from drivers import list_drivers

app = FastAPI(title="REDES-APLICACION")


class SwitchSpec(BaseModel):
    name: str
    vendor: str                 # id de un driver: ver GET /api/vendors
    host: str = ""
    username: str = ""
    password: str = ""
    port: int = 22
    demo: bool = False          # True = usa datos de muestra, sin conectarse


class CollectRequest(BaseModel):
    switches: list[SwitchSpec]


@app.get("/api/vendors")
def vendors():
    return list_drivers()


@app.post("/api/collect")
def collect(req: CollectRequest):
    """Qué hay conectado en cada switch: PC / SW / FW por MAC y puerto."""
    return {"results": collect_all(req.switches)}


FRONTEND = Path(__file__).resolve().parent.parent / "frontend"
if FRONTEND.exists():
    app.mount("/", StaticFiles(directory=FRONTEND, html=True), name="frontend")
