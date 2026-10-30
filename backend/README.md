# Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
```

Abrir http://localhost:8000 (frontend) o http://localhost:8000/docs (API).

## Cómo extender

| Quiero… | Qué hago |
|---|---|
| Soportar otro fabricante | Crear `drivers/<nombre>.py` con una clase `@register` (comandos + 2 parsers). Se detecta solo. |
| Cambiar qué es PC / SW / FW | Editar `config/classification.json` (no requiere reiniciar). |
| Agregar un dato nuevo (IP, ARP…) | Agregar un comando en el driver y un campo en `core/models.py`. |
| Probar un parser | Poner la salida real en `drivers/samples/<driver>_<comando>.txt` y usar el modo demo. |
