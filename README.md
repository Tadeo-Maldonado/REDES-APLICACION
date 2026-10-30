# NetOrch · Orquestador de Red (REDES-APLICACION)

Aplicación en Python con interfaz gráfica que se conecta **por SSH a un solo switch**
(sin escaneos masivos), extrae vecinos CDP/LLDP, tabla MAC, ARP, puertos y VLANs, y
entrega un **mapeo limpio de lo que está conectado directamente**, sin el ruido de las
tablas MAC/ARP globales. Todo se guarda **localmente** y organizado por **proyectos**.

Vendors: **Cisco Catalyst IOS (2960, 3560, 3750, 4500…), Cisco Catalyst IOS-XE (3650, 3850,
9200, 9300, 9400, 9500…), Cisco Nexus NX-OS, Aruba AOS-S / ProCurve, Aruba AOS-CX y
Alcatel-Lucent Enterprise AOS 6/8 (OS6860, OS6900…).** Al importar un CSV, el vendor puede
escribirse como modelo ("Catalyst 9300", "2960X", "Nexus 9k", "OS6860", "Aruba 6300"…).

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
| **🚀 Nueva ejecución** | Tabla de **varios switches** (con casilla **«Sin usuario»** para equipos que solo piden contraseña) (nombre, IP, vendor/OS, puerto, usuario opcional) que se ejecutan **en paralelo**, con progreso por equipo. Credenciales **comunes o distintas por switch**, enable, llave privada opcional y **Custom CLI** (se ejecuta en todos). Importa el inventario desde CSV (sin contraseñas). Si un switch falla, los demás siguen. |
| **📑 Reporte** | Aparece solo al terminar cada ejecución y en su propia pestaña (proyecto completo, última tanda o una ejecución): métricas, **hallazgos con severidad y recomendación**, **diagrama de red** y **exportación**. |
| **📋 Resultados por switch** | Las 4 capas: **Resumen ejecutivo** (switch + acumulado del proyecto), **Tabla consolidada de mapeo**, **Topología** interactiva y **Raw logs** (auditoría, descargables). Además VLANs/SVIs. |
| **🗺️ Topología del proyecto** | Une la última ejecución de cada switch en un solo diagrama: si un switch escaneado aparece como vecino de otro, se "cosen" por IP de gestión o hostname. |
| **🔍 Comparar** | Diferencias entre dos ejecuciones: equipos nuevos/desaparecidos, puertos que cambiaron de estado y hosts que se movieron de puerto. |
| **📜 Historial** | Todas las ejecuciones del proyecto, con errores y notas. |

### Tabla consolidada de mapeo

`Puerto | Estado | VLAN Native/Tagged | Tipo de Dispositivo | Vecino / Host Name |
Dirección MAC | Dirección IP | Método de Detección` (+ categoría, MACs en el puerto,
puerto remoto). Exportable a CSV.

## Hallazgos automáticos

`netorch/findings.py` revisa cada switch y el conjunto del proyecto:

| Severidad | Ejemplos |
|---|---|
| 🔴 Alta | Hubs/switches no administrados (acceso o trunk sin CDP/LLDP), puertos *err-disabled*, **VLAN nativa o modo distinto entre dos switches**, switches que no se pudieron recolectar |
| 🟠 Media | Hosts sin IP (el gateway está en otro equipo), sin CDP/LLDP, la misma MAC como host en dos puertos |
| 🟡 Baja | Hosts en puertos trunk, puertos con enlace pero sin tráfico |
| 🔵 Info | Inventario por switch, puertos apagados, capacidad libre, equipos de infraestructura vistos pero no recolectados |

En la vista de proyecto las **IPs se cruzan entre switches**: si un host del switch de acceso
no tiene IP local, se toma de la ARP del core (se indica «IP vía ARP de …»).

## Diagrama de red

Íconos propios por tipo de equipo (switch recolectado con insignia ✓, switch vecino, router,
firewall, AP, teléfono, host, servidor, no administrado) y **acomodo jerárquico sin cruces**:
firewalls/routers arriba, core, acceso, y cada switch con sus equipos debajo. Botones para
cambiar a acomodo libre, encuadrar y **descargar PNG** en alta resolución. Funciona sin internet.

## Exportación

Desde el reporte: **Reporte HTML** (autocontenido, con el diagrama interactivo), **Excel**
(Resumen, Hallazgos, Mapeo, VLANs, Ejecuciones), **Diagrama HTML** y **ZIP** con todo
(+ CSV y raw logs). O **💾 Guardar en una carpeta** de tu equipo (por defecto
`Documentos/NetOrch/<proyecto>/<fecha-hora>/`) con botón para abrirla.

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

**LAG / Port-channel / linkagg:** las MACs de un uplink agregado se aprenden en el puerto
lógico (`Po1`, `Trk1`, `lag1`, `0/1` en Alcatel) y CDP/LLDP se ve en los físicos. Si un
miembro tiene vecino, las MACs del LAG se le asignan a ese uplink (no aparecen como hub ni
como hosts) y los demás miembros se marcan como *Miembro de LAG*.

Detalles por vendor:
- Aruba AOS-S y Alcatel no tienen "modo trunk" explícito: un puerto con VLAN untagged y
  **una sola** VLAN tagged (típicamente voz) se trata como acceso; con 2+ tagged es trunk.
- Alcatel AOS 8 (OS6860, OS6900, OS6560…) no muestra el estado del enlace en
  `show interfaces status`; se toma de `show interfaces alias` (que también trae la
  descripción) y, si no está, se deduce de la velocidad detectada.
- Cada comando tiene alternativas (p. ej. `show mac-address-table` → `show mac-learning`
  en AOS 8); si una falla por sintaxis se intenta la siguiente y ambas quedan en los Raw logs.

### Comandos por plataforma

| Dato | Cisco Catalyst IOS / IOS-XE | Cisco Nexus NX-OS | Aruba AOS-S | Aruba AOS-CX | Alcatel AOS 6/8 (OS6860) |
|---|---|---|---|---|---|
| Vecinos | `show cdp neighbors detail`, `show lldp neighbors detail` | igual | `show lldp info remote-device detail` | `show lldp neighbor-info detail` | `show lldp remote-system` |
| MAC | `show mac address-table` | `show mac address-table` | `show mac-address` | `show mac-address-table` | `show mac-address-table` → `show mac-learning` (AOS 8) |
| ARP | `show ip arp` | `show ip arp vrf all` | `show arp` | `show arp all-vrfs` | `show arp` |
| Puertos | `show interfaces status`, `show interfaces trunk` | `show interface status`, `show interface trunk` | `show interfaces brief` | `show interface brief`, `show running-config interface` | `show interfaces status`, `show interfaces alias` |
| VLANs / SVIs | `show vlan brief`, `show ip interface brief` | ídem + `vrf all` | `show vlans`, `show vlans <id>`, `show ip` | `show vlan`, `show ip interface brief` | `show vlan`, `show vlan members` → `show vlan port` (AOS 6), `show ip interface` |
| LAG | `show etherchannel summary` | `show port-channel summary` | `show trunks` | (de la configuración `lag N`) | `show linkagg port` |

## Estructura

```
app.py                     Interfaz gráfica (Streamlit)
netorch/
  commands.py              Plataformas y comandos por vendor (con alternativas)
  engine.py                SSH con Netmiko (o sesión demo), ejecución en paralelo y guardado
  parsers/
    cisco.py aruba.py alcatel.py   Parsers RegEx propios por vendor
    common.py              Utilidades + fallback a NTC-Templates (TextFSM)
  classifier.py            Algoritmo de filtrado L1/L2 y métricas
  storage.py               SQLite local por proyectos
  analysis.py              Acumulado del proyecto y comparación de ejecuciones
  topology.py              Diagrama interactivo (vis-network) con layout de árbol propio
  icons.py                 Íconos SVG de los equipos
  findings.py              Hallazgos automáticos con severidad
  report.py                Reporte HTML, Excel, ZIP y guardado en carpeta
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
       ├─ arp_entries (run_id, ip, mac, interface)   ← para cruzar IPs entre switches
       ├─ port_rows   (run_id, port, status, vlan, device_type, category, name, mac, ip,
       │               method, mac_count, remote_port, platform)
       └─ vlans       (run_id, vlan_id, name, svi_ip)
```

Borrar un proyecto borra en cascada sus ejecuciones. Para usar otra base:
`NETORCH_DB=/ruta/otra.db streamlit run app.py`.

## Equipos sin usuario (solo contraseña)

Marca **«Sin usuario»** en la tabla, en las credenciales comunes o por switch. La app se
conecta por SSH con usuario vacío y la contraseña; si el servidor SSH del equipo no acepta un
usuario vacío, reintenta una vez con un usuario genérico (los equipos que solo validan la
contraseña lo ignoran).

## Robustez

- Cada comando se ejecuta aislado: si uno tarda demasiado o falla, se registra en Raw logs y
  la recolección sigue. Los comandos pesados (MAC, ARP, vecinos) tienen más tiempo de espera.
- Si la sesión SSH se cae a la mitad, se guarda lo que alcanzó a recolectarse (resultado
  parcial con aviso) en lugar de perder toda la ejecución.
- Cada sección del parseo está aislada: una salida inesperada genera una advertencia, no un
  error. Las pruebas incluyen salidas aleatorias/basura para todas las plataformas.
- En ejecución múltiple, un switch con problemas nunca detiene a los demás.
- Si la sesión queda en modo usuario (`>`) en Cisco, se avisa para agregar el enable.

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
