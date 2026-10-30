"""API: consulta un switch por SSH. No hace escaneos y NO guarda datos de los switches.

Los datos de conexión (host, usuario, contraseña) llegan en cada petición,
se usan solo en memoria y se descartan.

Ejecutar desde la carpeta backend:  uvicorn main:app --reload
"""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from collectors import COLLECTORS

app = FastAPI(title="REDES-APLICACION")


class SwitchRequest(BaseModel):
    name: str
    host: str
    vendor: str      # cisco | aruba | alcatel
    username: str
    password: str


@app.post("/api/connections")
def connections(sw: SwitchRequest):
    """Qué hay conectado (PC / SW / FW) y su MAC, por puerto."""
    if sw.vendor not in COLLECTORS:
        raise HTTPException(400, f"Vendor no soportado: {sw.vendor}")
    collector = COLLECTORS[sw.vendor](sw.model_dump())
    return [c.to_dict() for c in collector.collect()]
