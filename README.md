# NetOrch · Orquestador de Red (REDES-APLICACION)

Aplicación en Python con interfaz gráfica que se conecta **por SSH a un solo switch**
(sin escaneos masivos), extrae vecinos CDP/LLDP, tabla MAC, ARP, puertos y VLANs, y
entrega un **mapeo limpio de lo que está conectado directamente**, sin el ruido de las
tablas MAC/ARP globales. Todo se guarda **localmente** y organizado por **proyectos**.

Vendors: **Cisco IOS/IOS-XE, Cisco NX-OS, Aruba AOS-S (ProCurve), Aruba AOS-CX y
Alcatel-Lucent Enterprise AOS 6/8.**

## Inicio rápido

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate      Linux/Mac: source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

Se abre en el navegador (`http://localhost:8501`). En Windows también puedes dar doble
clic a `iniciar.bat`.

**¿Sin switch a la mano?** En la barra lateral usa **🎬 Cargar proyecto demo**: crea un
proyecto con un core Cisco y tres switches de acceso (Aruba AOS-S, Aruba CX y Alcatel)
usando salidas de ejemplo, para explorar todas las vistas. También puedes marcar
**Modo demo** en el formulario de ejecución.

## Qué hace

| Sección | Contenido |
|---|---|
| **Proyectos** (barra lateral) | Crear, alternar y borrar proyectos. Cada proyecto acumula sus ejecuciones de forma aislada. |
| **🚀 Nueva ejecución** | IP, vendor/OS, puerto SSH, usuario, contraseña, enable, llave privada opcional y **Custom CLI** (comandos extra, uno por línea). |
| **📋 Resultados** | Las 4 capas: **Resumen ejecutivo** (switch + acumulado del proyecto), **Tabla consolidada de mapeo**, **Topología** interactiva y **Raw logs** (auditoría, descargables). Además VLANs/SVIs. |
| **🗺️ Topología del proyecto** | Une la última ejecución de cada switch en un solo diagrama: si un switch escaneado aparece como vecino de otro, se "cosen" por IP de gestión o hostname. |
| **🔍 Comparar** | Diferencias entre dos ejecuciones: equipos nuevos/desaparecidos, puertos que cambiaron de estado y hosts que se movieron de puerto. |
| **📜 Historial** | Todas las ejecuciones del proyecto, con errores y notas. |

### Tabla consolidada de mapeo

`Puerto | Estado | VLAN Native/Tagged | Tipo de Dispositivo | Vecino / Host Name |
Dirección MAC | Dirección IP | Método de Detección` (+ categoría, MACs en el puerto,
puerto remoto). Exportable a CSV.

## Lógica de filtrado (cero "info basura")

Implementada en `netorch/classifier.py`, por puerto:

1. **Hay CDP/LLDP** → *Vecino Directo de Infraestructura*, tipificado como Switch,
   Router, Firewall, Phone, AP… por capacidades y plataforma. Si el vecino es un
   **IP Phone** y queda **exactamente una MAC más**, se reporta la **PC detrás del teléfono**.
   Un servidor que habla LLDP (capacidad *Station*) se reporta como host.
2. **Sin CDP/LLDP y exactamente 1 MAC** → *Dispositivo Final (Host)*; la IP se resuelve
   cruzando esa MAC con la ARP del switch (si tiene la SVI/gateway).
3. **Sin CDP/LLDP y 2+ MACs** → *Uplink No Administrado / Hub / Switch no compatible*.
   Solo se muestra el **conteo**, no las docenas de MACs/IPs.
4. **0 MACs** → activo sin MAC, trunk vacío o inactivo, según el estado.

Las MACs aprendidas en los uplinks (las de toda la red) nunca aparecen como hosts.

Detalles por vendor:
- Aruba AOS-S y Alcatel no tienen "modo trunk" explícito: un puerto con VLAN untagged y
  **una sola** VLAN tagged (típicamente voz) se trata como acceso; con 2+ tagged es trunk.
- Alcatel AOS no muestra el estado operativo en `show interfaces status`; se deduce de la
  velocidad detectada.
- Cada comando tiene alternativas (p. ej. `show mac-address-table` → `show mac-learning`
  en AOS 8); si una falla por sintaxis se intenta la siguiente y ambas quedan en los Raw logs.

## Estructura

```
app.py                     Interfaz gráfica (Streamlit)
netorch/
  commands.py              Plataformas y comandos por vendor (con alternativas)
  engine.py                SSH con Netmiko (o sesión demo), ejecución y guardado
  parsers/
    cisco.py aruba.py alcatel.py   Parsers RegEx propios por vendor
    common.py              Utilidades + fallback a NTC-Templates (TextFSM)
  classifier.py            Algoritmo de filtrado L1/L2 y métricas
  storage.py               SQLite local por proyectos
  analysis.py              Acumulado del proyecto y comparación de ejecuciones
  topology.py              Diagrama interactivo (Pyvis / vis.js)
  demo_data/               Salidas de ejemplo por plataforma (demo y pruebas)
tests/                     Pruebas (pytest) con las salidas de ejemplo
data/netorch.db            Base local (se crea sola; está en .gitignore)
```

### Esquema SQLite

```
projects (id, name UNIQUE, description, created_at)
  └─ runs (id, project_id, switch_ip, platform, hostname, username, started_at,
           finished_at, status ok|error|running, error, summary JSON, warnings JSON, notes)
       ├─ raw_outputs (run_id, seq, key, command, output, is_custom, ok)
       ├─ port_rows   (run_id, port, status, vlan, device_type, category, name, mac, ip,
       │               method, mac_count, remote_port, platform)
       └─ vlans       (run_id, vlan_id, name, svi_ip)
```

Borrar un proyecto borra en cascada sus ejecuciones. Para usar otra base:
`NETORCH_DB=/ruta/otra.db streamlit run app.py`.

## Seguridad

- **Las contraseñas y passphrases nunca se guardan**; solo el usuario SSH. La llave privada
  se escribe a un archivo temporal con permisos 600 y se borra al terminar.
- Ojo: lo que pidas por **Custom CLI** (p. ej. `show running-config`) se guarda tal cual en la
  base local. Trata `data/netorch.db` como información sensible.
- Los nombres que anuncian los equipos por CDP/LLDP se neutralizan antes de dibujarlos.

## Pruebas

```bash
pytest -q
```

## Agregar o ajustar un vendor

1. Agrega/ajusta la plataforma y sus comandos en `netorch/commands.py`.
2. Implementa o corrige el parser en `netorch/parsers/<vendor>.py` (devuelve un `ParsedData`).
3. Guarda salidas reales en `netorch/demo_data/<plataforma>/` (el nombre del archivo es el
   comando con `_`, p. ej. `show_mac_address_table.txt`) y agrega una prueba.

Los parsers se probaron con salidas de ejemplo; si un equipo real devuelve un formato
distinto, la ejecución no se pierde: los **Raw logs** quedan guardados para ajustar el parser.
