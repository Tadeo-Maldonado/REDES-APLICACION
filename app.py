"""NetOrch · Orquestador de Red — interfaz gráfica (Streamlit).

Ejecutar:  streamlit run app.py
"""
from __future__ import annotations

import ipaddress
import os
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from netorch.analysis import diff_runs, enrich_with_project_arp, project_summary
from netorch.findings import SEVERITY_ICON, severity_counts
from netorch.report import (build_report_data, default_export_dir, export_files, open_folder,
                            save_to_folder, slug)
from netorch.commands import platform_choices, platform_from_text, platform_label
from netorch.engine import DemoSession, NetmikoSession, Target, run_many
from netorch.netdiag import AUTO, local_interfaces, probe_many
from netorch.models import CAT_DOWN
from netorch.storage import DEFAULT_DB, Storage
from netorch.topology import build_graph, render_html

st.set_page_config(page_title="NetOrch · Orquestador de Red", page_icon="🛰️", layout="wide")

STATUS_LABEL = {"up": "🟢 Activo", "down": "🔴 Inactivo", "disabled": "⚫ Deshabilitado", "err-disabled": "🟥 Err-disabled",
                "unknown": "⚪ Desconocido"}
RUN_STATUS = {"ok": "✅", "error": "❌", "running": "⏳"}
TABLE_COLUMNS = {
    "port": "Puerto", "status": "Estado", "vlan": "VLAN Native/Tagged",
    "device_type": "Tipo de Dispositivo", "name": "Vecino / Host Name", "mac": "Dirección MAC",
    "ip": "Dirección IP", "method": "Método de Detección", "category": "Categoría",
    "mac_count": "MACs en puerto", "remote_port": "Puerto remoto", "platform": "Plataforma / Descr.",
}
DEMO_SET = [("cisco_ios", "10.0.0.1"), ("aruba_aoss", "10.0.0.11"),
            ("aruba_aoscx", "10.0.0.12"), ("alcatel_aos", "10.0.0.13")]


@st.cache_resource
def get_storage() -> Storage:
    return Storage(os.environ.get("NETORCH_DB", DEFAULT_DB))


db = get_storage()


def is_dark() -> bool:
    try:
        return st.context.theme.type == "dark"
    except Exception:
        return False


def run_label(r: dict) -> str:
    when = r["started_at"].replace("T", " ")[:16]
    name = r.get("hostname") or "?"
    return f"#{r['id']} · {RUN_STATUS.get(r['status'], '')} {name} ({r['switch_ip']}) · {when}"


def rows_df(rows: list[dict], with_switch: bool = False) -> pd.DataFrame:
    if not rows:
        return pd.DataFrame(columns=list(TABLE_COLUMNS.values()))
    df = pd.DataFrame(rows)
    cols = (["switch"] if with_switch else []) + list(TABLE_COLUMNS)
    df = df[[c for c in cols if c in df.columns]].copy()
    df["status"] = df["status"].map(lambda s: STATUS_LABEL.get(s, s))
    df = df.astype(object).where(df.notna(), "—")
    return df.rename(columns={**TABLE_COLUMNS, "switch": "Switch"})


def show_html(html: str, height: int):
    if hasattr(st, "iframe"):
        st.iframe(html, height=height)
    else:                                   # Streamlit < 1.50
        components.html(html, height=height, scrolling=False)


def show_topology(runs_with_rows, key: str, title: str = "", hosts_default: bool = True):
    c1, c2, _ = st.columns([1, 1, 3])
    hosts = c1.toggle("Mostrar hosts finales", value=hosts_default, key=f"{key}_hosts")
    unm = c2.toggle("Mostrar no administrados", value=True, key=f"{key}_unm")
    graph = build_graph(runs_with_rows, show_hosts=hosts, show_unmanaged=unm)
    if not graph.nodes:
        st.info("No hay datos para dibujar.")
        return
    show_html(render_html(graph, height=640, dark=is_dark(), title=title), height=650)
    st.caption("Arrastra, haz zoom y pasa el cursor sobre equipos y enlaces. «⇄ Libre / ⇅ Jerárquico» "
               "cambia el acomodo y «⬇ PNG» descarga la imagen.")


@st.cache_data(show_spinner="Preparando archivos del reporte…", max_entries=8)
def cached_export(run_ids: tuple[int, ...], title: str, scope: str) -> dict[str, bytes]:
    runs = [db.get_run(i) for i in run_ids]
    return export_files(db, build_report_data(db, [r for r in runs if r], title, scope))


SEV_STYLE = {"Alta": "red", "Media": "orange", "Baja": "yellow", "Info": "blue"}


def report_panel(runs: list[dict], title: str, scope: str, key: str):
    """Reporte con hallazgos + diagrama + exportación (descarga o carpeta local)."""
    if not runs:
        st.info("No hay ejecuciones para reportar.")
        return
    rd = build_report_data(db, runs, title, scope)
    st.caption(f"{scope} · {len(rd.runs_with_rows)} switch(es) recolectado(s)"
               + (f" · {len(rd.failed)} con error" if rd.failed else ""))
    m = rd.metrics
    cols = st.columns(6)
    for col, k in zip(cols, ["Switches recolectados", "Puertos activos", "Hosts", "Hosts con IP",
                             "Vecinos de infraestructura", "No administrados"]):
        col.metric(k, m[k])

    st.markdown("#### 🔎 Hallazgos")
    counts = severity_counts(rd.findings)
    st.markdown("  ".join(f":{SEV_STYLE[k]}-badge[{SEVERITY_ICON[k]} {k}: {v}]" for k, v in counts.items()))
    important = [f for f in rd.findings if f.severity in ("Alta", "Media")]
    minor = [f for f in rd.findings if f.severity not in ("Alta", "Media")]
    if not rd.findings:
        st.success("Sin hallazgos.")

    def finding_card(f):
        with st.container(border=True):
            st.markdown(f":{SEV_STYLE[f.severity]}-badge[{f.severity}] "
                        f":gray-badge[{f.category}] **{f.title}**")
            meta = []
            if f.switch:
                meta.append(f"Switch: **{f.switch}**")
            if f.ports:
                meta.append(f"Puertos: {f.ports}")
            if meta:
                st.caption(" · ".join(meta))
            st.write(f.detail)
            if f.recommendation:
                st.info(f.recommendation, icon="💡")

    for f in important:
        finding_card(f)
    if minor:
        with st.expander(f"Hallazgos de baja prioridad e informativos ({len(minor)})"):
            for f in minor:
                finding_card(f)

    st.markdown("#### 🕸️ Diagrama de red")
    # Con varios switches se abre en vista de infraestructura (más legible); los hosts se activan
    show_topology(rd.runs_with_rows, key=f"{key}_topo", title=title,
                  hosts_default=len(rd.runs_with_rows) <= 1)

    st.markdown("#### 💾 Exportar")
    files = cached_export(tuple(r["id"] for r in runs), title, scope)
    base = f"{slug(title)}_{datetime.now():%Y%m%d-%H%M}"
    c1, c2, c3, c4 = st.columns(4)
    c1.download_button("📄 Reporte HTML", files["reporte.html"], file_name=f"{base}_reporte.html",
                       mime="text/html", width="stretch", on_click="ignore", key=f"{key}_dl_html")
    c2.download_button("📊 Excel", files["reporte.xlsx"], file_name=f"{base}.xlsx", width="stretch",
                       mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                       on_click="ignore", key=f"{key}_dl_xlsx")
    c3.download_button("🕸️ Diagrama (HTML)", files["topologia.html"], file_name=f"{base}_topologia.html",
                       mime="text/html", width="stretch", on_click="ignore", key=f"{key}_dl_topo")
    from netorch.report import to_zip
    c4.download_button("🗜️ Todo (.zip)", to_zip(files), file_name=f"{base}.zip", mime="application/zip",
                       width="stretch", on_click="ignore", key=f"{key}_dl_zip")
    st.caption("El reporte HTML se abre en cualquier navegador sin internet: incluye hallazgos, el diagrama "
               "interactivo (con botón PNG) y el detalle por switch. El ZIP agrega Excel, CSV y raw logs.")
    with st.container(border=True):
        st.markdown("**Guardar en una carpeta de este equipo**")
        c5, c6 = st.columns([4, 1])
        folder = c5.text_input("Carpeta destino", value=str(default_export_dir(title)),
                               key=f"{key}_folder", label_visibility="collapsed")
        if c6.button("💾 Guardar", key=f"{key}_save", width="stretch", type="primary"):
            try:
                st.session_state[f"{key}_saved"] = str(save_to_folder(files, folder))
            except Exception as exc:
                st.error(f"No se pudo guardar en «{folder}»: {exc}")
        saved = st.session_state.get(f"{key}_saved")
        if saved:
            st.success(f"Guardado en `{saved}` (reporte.html, reporte.xlsx, diagramas, CSV y raw logs).")
            if st.button("📂 Abrir carpeta", key=f"{key}_open"):
                if not open_folder(Path(saved)):
                    st.warning("No se pudo abrir el explorador; la ruta está arriba.")
        st.caption("Se crea una subcarpeta con fecha y hora por cada exportación. Si usas la app desde "
                   "otra computadora, usa los botones de descarga de arriba.")


# =============================================================== Sidebar =====
with st.sidebar:
    st.title("🛰️ NetOrch")
    st.caption("Orquestador de red · mapeo L1/L2 por SSH")

    projects = db.list_projects()
    with st.expander("➕ Nuevo proyecto", expanded=not projects):
        with st.form("new_project", clear_on_submit=True):
            pname = st.text_input("Nombre", placeholder="Proyecto 1: Sede Monterrey")
            pdesc = st.text_area("Descripción (opcional)", height=70)
            if st.form_submit_button("Crear proyecto", width="stretch") and pname.strip():
                try:
                    st.session_state.project_id = db.create_project(pname, pdesc)
                    st.rerun()
                except Exception:
                    st.error("Ya existe un proyecto con ese nombre.")

    if not projects:
        st.info("Crea tu primer proyecto, o carga el demo para explorar la app.")
        if st.button("🎬 Cargar proyecto demo", width="stretch"):
            pid = db.create_project(f"Demo · Sede Monterrey ({datetime.now():%H:%M})",
                                    "Datos de ejemplo: core Cisco + accesos Aruba y Alcatel")
            run_many(db, pid, [Target(host=ip, platform=plat, username="demo", name=f"SW{i + 1}")
                               for i, (plat, ip) in enumerate(DEMO_SET)],
                     ["show version"], session_factory=DemoSession, notes="demo")
            st.session_state.project_id = pid
            st.rerun()
        st.stop()

    ids = [p["id"] for p in projects]
    current = st.session_state.get("project_id")
    idx = ids.index(current) if current in ids else 0
    project = st.selectbox("Proyecto activo", projects, index=idx,
                           format_func=lambda p: f"{p['name']}  ({p['runs']} ejec.)")
    st.session_state.project_id = project["id"]
    if project.get("description"):
        st.caption(project["description"])

    with st.expander("🗑️ Eliminar proyecto"):
        st.warning("Se borran todas sus ejecuciones.")
        if st.checkbox(f"Confirmo borrar «{project['name']}»", key="confirm_del_proj"):
            if st.button("Eliminar definitivamente", type="primary"):
                db.delete_project(project["id"])
                st.session_state.pop("project_id", None)
                st.rerun()

    st.divider()
    st.caption(f"💾 Base local: `{db.path}`")

pid = project["id"]
runs = db.list_runs(pid)
ok_runs = [r for r in runs if r["status"] == "ok"]

st.header(project["name"])
tab_run, tab_rep, tab_res, tab_proj, tab_cmp, tab_hist = st.tabs(
    ["🚀 Nueva ejecución", "📑 Reporte", "📋 Resultados por switch", "🗺️ Topología del proyecto",
     "🔍 Comparar", "📜 Historial"])

# ======================================================= Nueva ejecución =====
CHOICES = platform_choices()
LABEL_TO_KEY = {v: k for k, v in CHOICES.items()}
A_FULL, A_PASS, A_NONE = "Usuario y contraseña", "Solo contraseña", "Sin credenciales"
ACCESS_MODES = [A_FULL, A_PASS, A_NONE]
COLS = ["Nombre", "IP", "Vendor / OS", "Puerto SSH", "Acceso", "Usuario (opcional)"]


def access_from_text(value) -> str:
    """CSV/tabla -> modo de acceso. Acepta 'solo contraseña', 'sin credenciales', 'ninguno'..."""
    t = clean_str(value).lower() if not isinstance(value, bool) else ""
    if t in (m.lower() for m in ACCESS_MODES):
        return next(m for m in ACCESS_MODES if m.lower() == t)
    if any(k in t for k in ("sin cred", "ninguno", "none", "nada", "abierto", "sin auth")):
        return A_NONE
    if any(k in t for k in ("solo", "password", "contraseña", "pass")):
        return A_PASS
    return A_FULL


def clean_str(value) -> str:
    """Celdas vacías del editor llegan como None o NaN: siempre devolver texto limpio."""
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except (TypeError, ValueError):
        pass
    text = str(value).strip()
    return "" if text.lower() == "nan" else text


def safe_int(value, default: int, lo: int = 1, hi: int = 65535) -> int:
    try:
        n = int(float(value))
    except (TypeError, ValueError):
        return default
    return n if lo <= n <= hi else default


def truthy(value) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in ("1", "si", "sí", "true", "yes", "x")
    try:
        return bool(value) and not pd.isna(value)
    except (TypeError, ValueError):
        return bool(value)


def vendor_from_text(text) -> str | None:
    return platform_from_text(text)


def table_from_records(records: list[dict]) -> pd.DataFrame:
    return pd.DataFrame(records, columns=COLS)


def new_table(df: pd.DataFrame):
    st.session_state.switch_table = df
    st.session_state.editor_ver = st.session_state.get("editor_ver", 0) + 1


if "switch_table" not in st.session_state:
    new_table(table_from_records([{"Nombre": "SW1", "IP": "", "Vendor / OS": CHOICES["cisco_xe"],
                                   "Puerto SSH": 22, "Acceso": A_FULL, "Usuario (opcional)": ""}]))

with tab_run:
    st.subheader("1 · Switches a ejecutar")
    st.caption("Agrega una fila por switch (botón ➕ al pie de la tabla). La app abre SSH solo contra "
               "estos equipos, en paralelo: no hace escaneos de red.")
    c1, c2, c3 = st.columns([1, 1, 2])
    if c1.button("🎬 Llenar con ejemplo demo", width="stretch"):
        new_table(table_from_records([
            {"Nombre": f"SW{i + 1}", "IP": ip, "Vendor / OS": CHOICES[plat], "Puerto SSH": 22,
             "Acceso": A_FULL, "Usuario (opcional)": ""}
            for i, (plat, ip) in enumerate(DEMO_SET)]))
        st.rerun()
    c2.download_button("⬇️ Plantilla CSV", "nombre,ip,vendor,puerto,usuario,acceso\n"
                       "SW1,10.0.0.1,Catalyst 9300,22,,usuario y contraseña\n"
                       "SW2,10.0.0.2,Catalyst 2960,22,,solo contraseña\n"
                       "SW3,10.0.0.3,Aruba 2530,22,,sin credenciales\n"
                       "SW4,10.0.0.13,OS6860,22,,\n",
                       file_name="inventario_switches.csv", width="stretch")
    csv_file = c3.file_uploader("Importar inventario CSV (sin contraseñas)", type=["csv"],
                                label_visibility="collapsed")
    if csv_file is not None and st.session_state.get("csv_loaded") != csv_file.file_id:
        try:
            inv = pd.read_csv(csv_file, dtype=str).fillna("")
            inv.columns = [c.strip().lower() for c in inv.columns]
            recs, bad = [], []
            for _, r in inv.iterrows():
                key = vendor_from_text(r.get("vendor", ""))
                if not key:
                    bad.append(r.get("ip", "?"))
                recs.append({"Nombre": clean_str(r.get("nombre", "") or r.get("name", "")),
                             "IP": clean_str(r.get("ip", "")),
                             "Vendor / OS": CHOICES.get(key or "cisco_xe"),
                             "Puerto SSH": safe_int(r.get("puerto", ""), 22),
                             "Usuario (opcional)": clean_str(r.get("usuario", "") or r.get("user", "")),
                             "Acceso": (A_PASS if truthy(r.get("sin_usuario", ""))
                                        else access_from_text(r.get("acceso", "")))})
            st.session_state.csv_loaded = csv_file.file_id
            new_table(table_from_records(recs))
            if bad:
                st.session_state.csv_warning = ("Vendor no reconocido (se puso Cisco Catalyst IOS-XE, revísalo) en: "
                                                + ", ".join(bad))
            st.rerun()
        except Exception as exc:
            st.error(f"No se pudo leer el CSV: {exc}")
    if st.session_state.get("csv_warning"):
        st.warning(st.session_state.pop("csv_warning"))

    edited = st.data_editor(
        st.session_state.switch_table, key=f"sw_editor_{st.session_state.editor_ver}",
        num_rows="dynamic", width="stretch", hide_index=True,
        column_config={
            "Nombre": st.column_config.TextColumn(help="Cómo quieres identificarlo (SW1, Core MTY…)"),
            "IP": st.column_config.TextColumn(help="IP de gestión del switch", required=True),
            "Vendor / OS": st.column_config.SelectboxColumn(options=list(CHOICES.values()),
                                                            required=True, width="large",
                                                            default=CHOICES["cisco_xe"]),
            "Puerto SSH": st.column_config.NumberColumn(min_value=1, max_value=65535, step=1,
                                                        default=22),
            "Usuario (opcional)": st.column_config.TextColumn(
                help="Solo si este switch usa un usuario distinto al común"),
            "Acceso": st.column_config.SelectboxColumn(
                options=ACCESS_MODES, default=A_FULL, required=True,
                help="Cómo entra el switch: usuario y contraseña, solo contraseña, o sin "
                     "credenciales (no pide nada)"),
        })
    rows_in = []
    for r in edited.to_dict("records"):
        row = {"Nombre": clean_str(r.get("Nombre")), "IP": clean_str(r.get("IP")),
               "Vendor / OS": clean_str(r.get("Vendor / OS")),
               "Puerto SSH": safe_int(r.get("Puerto SSH"), 22),
               "Usuario (opcional)": clean_str(r.get("Usuario (opcional)")),
               "Acceso": access_from_text(r.get("Acceso"))}
        if row["IP"] or row["Nombre"]:
            rows_in.append(row)

    st.subheader("2 · Credenciales")
    st.caption("Las contraseñas no se guardan en ningún lado.")
    cred_mode = st.radio("Credenciales", ["Las mismas para todos", "Distintas por switch"],
                         horizontal=True, label_visibility="collapsed")
    common = {}
    per_switch: dict[int, dict] = {}
    if cred_mode == "Las mismas para todos":
        override = st.selectbox(
            "Tipo de acceso", ["Según la columna «Acceso» de la tabla"] + ACCESS_MODES,
            key="common_access",
            help="Aplica un tipo de acceso a todos los switches, o respeta lo que diga cada fila.")
        common["access"] = None if override.startswith("Según") else override
        modes = {common["access"] or r["Acceso"] for r in rows_in} or {A_FULL}
        need_user, need_pass = A_FULL in modes, bool(modes & {A_FULL, A_PASS})
        if modes == {A_NONE}:
            st.info("Sin credenciales: la app se conecta por SSH sin usuario ni contraseña.")
        c4, c5, c6 = st.columns(3)
        common["user"] = c4.text_input("Usuario", disabled=not need_user,
                                       placeholder="" if need_user else "(no se usa)")
        common["password"] = c5.text_input("Contraseña", type="password", disabled=not need_pass,
                                           placeholder="" if need_pass else "(no se usa)")
        common["secret"] = c6.text_input("Enable password (si aplica)", type="password")
    else:
        if not rows_in:
            st.info("Primero agrega switches en la tabla.")
        for i, r in enumerate(rows_in):
            label = r["Nombre"] or f"Switch {i + 1}"
            c4, c5, c6, c7, c8 = st.columns([1.1, 1.1, 1.1, 1.1, 1.1])
            c4.markdown(f"**{label}**  \n`{r['IP'] or 'sin IP'}`")
            uid = f"{i}_{r['IP']}"
            access = c5.selectbox("Acceso", ACCESS_MODES, index=ACCESS_MODES.index(r["Acceso"]),
                                  key=f"ac_{uid}")
            per_switch[i] = {
                "access": access,
                "user": c6.text_input("Usuario", value=r["Usuario (opcional)"], key=f"u_{uid}",
                                      disabled=access != A_FULL),
                "password": c7.text_input("Contraseña", type="password", key=f"p_{uid}",
                                          disabled=access == A_NONE),
                "secret": c8.text_input("Enable", type="password", key=f"e_{uid}"),
            }
    with st.expander("🔑 Llave SSH privada (opcional, aplica a todos)"):
        key_upload = st.file_uploader("Archivo de llave (id_rsa, id_ed25519…)", key="key_up")
        key_pass = st.text_input("Passphrase de la llave", type="password")

    st.subheader("3 · Opciones")
    custom = st.text_area("Comandos adicionales / Custom CLI (uno por línea, se ejecutan en todos)",
                          placeholder="show log\nshow power inline\nshow running-config", height=100)
    c8, c9, c10 = st.columns([3, 1, 1])
    notes = c8.text_input("Nota de la ejecución (opcional)", placeholder="Ej. antes de la ventana de cambio")
    timeout = c9.number_input("Timeout SSH (s)", min_value=5, max_value=120, value=20)
    workers = c10.number_input("Switches en paralelo", min_value=1, max_value=10, value=4,
                               help="Cuántas sesiones SSH simultáneas abrir")
    ifaces = local_interfaces()
    src_options = [AUTO] + [ip for _, ip in ifaces]
    src_names = {AUTO: "Automática (según la tabla de rutas de este equipo)"}
    src_names.update({ip: f"{name} — {ip}" for name, ip in ifaces})
    source_ip = st.selectbox(
        "IP / tarjeta de red de origen", src_options, format_func=lambda x: src_names.get(x, x),
        key="source_ip",
        help="Por dónde sale la conexión SSH. Si llegas al switch por VPN y la app no, elige la "
             "tarjeta de la VPN. Usa «Probar conectividad» para ver qué IP usa la app.")
    demo = st.checkbox("Modo demo: usar salidas de ejemplo de cada plataforma (sin conectarse)")

    n = len(rows_in)
    cprobe, cgo = st.columns([1, 3])
    probe_btn = cprobe.button("🩺 Probar conectividad", width="stretch", disabled=n == 0,
                              help="Prueba TCP y banner SSH a cada switch, sin iniciar sesión")
    go = cgo.button(f"▶️ Ejecutar recolección en {n} switch{'es' if n != 1 else ''}", type="primary",
                    width="stretch", disabled=n == 0)

    if probe_btn:
        valid, bad_ips = [], []
        for r in rows_in:
            try:
                ipaddress.ip_address(r["IP"])
                valid.append(r)
            except ValueError:
                bad_ips.append(r["Nombre"] or r["IP"] or "?")
        if bad_ips:
            st.warning("Se omiten filas sin IP válida: " + ", ".join(bad_ips))
        with st.spinner("Probando conectividad…"):
            results = probe_many([(r["IP"], r["Puerto SSH"]) for r in valid],
                                 timeout=min(float(timeout), 8.0), source_ip=source_ip)
        st.session_state.probe_results = [
            {"Switch": r["Nombre"] or r["IP"], "IP": p.host, "Puerto": p.port,
             "Origen (IP local)": p.source_ip or "sin ruta",
             "Tarjeta": p.source_iface or "—",
             "TCP": {"ok": "✅ abre", "timeout": "⏱️ sin respuesta", "rechazado": "⛔ rechazado"}
             .get(p.tcp, "❌ error"),
             "ms": p.ms, "Banner": p.banner or "—", "Diagnóstico": p.diagnosis}
            for r, p in zip(valid, results)]
    if st.session_state.get("probe_results"):
        st.markdown("##### 🩺 Conectividad")
        st.dataframe(pd.DataFrame(st.session_state.probe_results), hide_index=True, width="stretch",
                     column_config={"Diagnóstico": st.column_config.TextColumn(width="large")})
        st.caption("«Origen» es la IP con la que la app sale hacia cada switch. Compárala con la que "
                   "usa PuTTY: en PowerShell, `Find-NetRoute -RemoteIPAddress <ip_del_switch>`.")

    if go:
        errors, targets, seen = [], [], set()
        for i, r in enumerate(rows_in):
            label = r["Nombre"] or f"Switch {i + 1}"
            ip = r["IP"]
            plat = LABEL_TO_KEY.get(r["Vendor / OS"])
            if cred_mode == "Las mismas para todos":
                creds = common
                access = common.get("access") or r["Acceso"]
                user = r["Usuario (opcional)"] or common.get("user", "")
            else:
                creds = per_switch.get(i, {})
                access = creds.get("access", A_FULL)
                user = creds.get("user", "")
            no_user = access in (A_PASS, A_NONE)
            no_password = access == A_NONE
            user = "" if no_user else user.strip()
            password = "" if no_password else creds.get("password", "")
            if not plat:
                errors.append(f"{label}: elige el vendor / OS.")
            if not demo:
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    errors.append(f"{label}: la IP «{ip}» no es válida.")
                if ip in seen:
                    errors.append(f"{label}: la IP {ip} está repetida.")
                if access == A_FULL and not user:
                    errors.append(f"{label}: falta el usuario SSH (o cambia el acceso a "
                                  "«Solo contraseña» / «Sin credenciales»).")
                if access != A_NONE and not password and not key_upload:
                    errors.append(f"{label}: falta contraseña (o una llave SSH, o acceso "
                                  "«Sin credenciales»).")
            seen.add(ip)
            targets.append(Target(host=ip or f"demo-{i + 1}", platform=plat or "cisco_xe",
                                  username=user, password=password,
                                  secret=creds.get("secret", ""), port=r["Puerto SSH"],
                                  key_passphrase=key_pass or None, timeout=int(timeout),
                                  name=r["Nombre"] or None, no_user=no_user,
                                  no_password=no_password,
                                  source_ip="" if demo else source_ip))
        if errors:
            for e in errors:
                st.error(e)
        else:
            key_path = None
            if key_upload is not None:
                fd, key_path = tempfile.mkstemp(prefix="netorch_key_")
                with os.fdopen(fd, "wb") as f:
                    f.write(key_upload.getvalue())
                os.chmod(key_path, 0o600)
                for t in targets:
                    t.key_file = key_path

            # Progreso: los hilos solo escriben en este dict; la UI se actualiza desde aquí
            state = {i: ("En cola", 0.0) for i in range(len(targets))}
            lock = threading.Lock()

            def on_progress(i, msg, frac):
                with lock:
                    state[i] = (msg, frac)

            outcome: dict = {}

            def worker():
                try:
                    outcome["ids"] = run_many(
                        db, pid, targets, custom.splitlines(), progress=on_progress,
                        session_factory=DemoSession if demo else NetmikoSession,
                        max_workers=int(workers), notes=("[demo] " if demo else "") + notes)
                except Exception as exc:          # no debería pasar: cada switch captura lo suyo
                    outcome["error"] = exc

            board = st.empty()

            def draw():
                with lock:
                    snap = dict(state)
                board.dataframe(pd.DataFrame([{
                    "Switch": t.label, "IP": t.host, "Progreso": snap[i][1], "Estado": snap[i][0],
                } for i, t in enumerate(targets)]), hide_index=True, width="stretch",
                    column_config={"Progreso": st.column_config.ProgressColumn(
                        min_value=0.0, max_value=1.0, format="percent")})

            th = threading.Thread(target=worker, daemon=True)
            th.start()
            while th.is_alive():
                draw()
                time.sleep(0.4)
            th.join()
            draw()
            if key_path and os.path.exists(key_path):
                os.remove(key_path)

            if "error" in outcome:
                st.error(f"Error inesperado: {outcome['error']}")
            else:
                st.session_state.last_batch = {"pid": pid, "ids": outcome["ids"],
                                               "when": datetime.now().strftime("%d/%m/%Y %H:%M")}
                ok_ids = [i for i in outcome["ids"] if db.get_run(i)["status"] == "ok"]
                if ok_ids:
                    st.session_state.selected_run = ok_ids[0]
                board.empty()

    # Resultado de la última tanda: queda visible aunque la página se recargue
    batch = st.session_state.get("last_batch")
    if batch and batch["pid"] == pid:
        done = [r for r in (db.get_run(i) for i in batch["ids"]) if r]
        if done:
            ok = [r for r in done if r["status"] == "ok"]
            st.divider()
            (st.success if len(ok) == len(done) else st.warning)(
                f"Ejecución del {batch['when']}: {len(ok)} de {len(done)} switches recolectados y "
                "guardados en el proyecto.")
            st.dataframe(pd.DataFrame([{
                "Ejecución": f"#{r['id']}", "Switch": r.get("hostname") or "-", "IP": r["switch_ip"],
                "Estado": RUN_STATUS.get(r["status"], r["status"]),
                "Puertos activos": f"{r['summary'].get('puertos_activos', '-')}/{r['summary'].get('puertos_total', '-')}",
                "Hosts": r["summary"].get("hosts", "-"), "Vecinos": r["summary"].get("vecinos_infra", "-"),
                "Error": r.get("error") or "",
            } for r in done]), hide_index=True, width="stretch")
            st.subheader("📑 Reporte de esta ejecución")
            report_panel(done, project["name"], f"Ejecución del {batch['when']}", key="post")

# ================================================================ Reporte =====
with tab_rep:
    if not runs:
        st.info("Este proyecto aún no tiene ejecuciones. Ejecuta uno o varios switches para generar el reporte.")
    else:
        options = ["Proyecto completo (última ejecución de cada switch)"]
        if batch and batch["pid"] == pid:
            options.append(f"Última tanda ejecutada ({batch['when']})")
        options.append("Una ejecución en particular")
        scope = st.radio("Alcance del reporte", options, horizontal=True, key="rep_scope")
        if scope.startswith("Proyecto completo"):
            latest_ok = db.latest_runs_per_switch(pid)
            names = {(r.get("hostname") or r["switch_ip"]).lower() for r in latest_ok}
            # Switches cuyo último intento falló y nunca se recolectaron bien
            failed_only = []
            for r in runs:
                k = (r.get("hostname") or r["switch_ip"]).lower()
                if r["status"] == "error" and k not in names:
                    failed_only.append(r)
                    names.add(k)
            report_panel(latest_ok + failed_only, project["name"], "Proyecto completo", key="rep_proj")
        elif scope.startswith("Última tanda"):
            report_panel([r for r in (db.get_run(i) for i in batch["ids"]) if r], project["name"],
                         f"Ejecución del {batch['when']}", key="rep_batch")
        else:
            one = st.selectbox("Ejecución", runs, format_func=run_label, key="rep_one")
            report_panel([one], f"{project['name']} · {one.get('hostname') or one['switch_ip']}",
                         f"Ejecución #{one['id']}", key=f"rep_one_{one['id']}")

# ============================================================ Resultados =====
with tab_res:
    if not runs:
        st.info("Este proyecto aún no tiene ejecuciones.")
    else:
        ids = [r["id"] for r in runs]
        sel = st.session_state.get("selected_run")
        run = st.selectbox("Ejecución", runs, index=ids.index(sel) if sel in ids else 0,
                           format_func=run_label, key="res_run")
        st.caption(f"Plataforma: {platform_label(run['platform'])} · Usuario: {run['username'] or '-'}"
                   + (f" · Nota: {run['notes']}" if run.get("notes") else ""))
        if run["status"] == "error":
            st.error(run["error"])
        rows = db.get_port_rows(run["id"])
        t_sum, t_tab, t_topo, t_raw, t_vlan = st.tabs(
            ["📊 Resumen ejecutivo", "🧾 Tabla de mapeo", "🕸️ Topología", "📄 Raw logs", "🏷️ VLANs"])

        with t_sum:
            s = run["summary"]
            if s:
                st.markdown(f"#### Switch: {run['hostname'] or run['switch_ip']}")
                m = st.columns(6)
                m[0].metric("Puertos activos", f"{s['puertos_activos']}/{s['puertos_total']}")
                m[1].metric("Puertos inactivos", s["puertos_inactivos"])
                m[2].metric("VLANs", s["vlans"])
                m[3].metric("SVIs", s["svis"])
                m[4].metric("Dispositivos finales", s["hosts"])
                m[5].metric("Vecinos infraestructura", s["vecinos_infra"])
                m = st.columns(6)
                m[0].metric("Switches", s["switches"])
                m[1].metric("Routers", s["routers"])
                m[2].metric("Firewalls", s["firewalls"])
                m[3].metric("APs", s["aps"])
                m[4].metric("Teléfonos IP", s["phones"])
                m[5].metric("Uplinks no administrados", s["uplinks_no_admin"])
                st.caption(f"Ruido descartado: la tabla MAC tenía {s['macs_en_tabla']} entradas y la ARP "
                           f"{s['arp_en_tabla']}; solo se muestran las conexiones directas.")
            ps = project_summary(db, pid)
            st.markdown("#### Acumulado del proyecto")
            m = st.columns(6)
            m[0].metric("Switches escaneados", ps["switches_escaneados"])
            m[1].metric("Ejecuciones", f"{ps['ejecuciones_ok']}/{ps['ejecuciones']} ok")
            m[2].metric("Puertos activos", f"{ps['puertos_activos']}/{ps['puertos_total']}")
            m[3].metric("Hosts únicos", ps["hosts_unicos"])
            m[4].metric("Enlaces de infraestructura", ps["enlaces_infra"])
            m[5].metric("VLANs únicas", ps["vlans_unicas"])
            for w in run["warnings"]:
                st.warning(w)

        with t_tab:
            df = rows_df(rows)
            c1, c2 = st.columns([3, 1])
            cats = sorted(df["Categoría"].dropna().unique()) if not df.empty else []
            chosen = c1.multiselect("Filtrar por categoría", cats, default=[c for c in cats if c != CAT_DOWN])
            text = c2.text_input("Buscar (MAC, IP, nombre, puerto)")
            view = df[df["Categoría"].isin(chosen)] if chosen else df
            if text:
                mask = view.astype(str).apply(lambda col: col.str.contains(text, case=False, na=False))
                view = view[mask.any(axis=1)]
            st.dataframe(view, width="stretch", hide_index=True, height=520)
            st.download_button("⬇️ Descargar CSV", df.to_csv(index=False).encode("utf-8-sig"),
                               file_name=f"mapeo_{run['hostname'] or run['switch_ip']}_{run['id']}.csv",
                               mime="text/csv")

        with t_topo:
            if rows:
                show_topology([(run, rows)], key=f"run{run['id']}",
                              title=run.get("hostname") or run["switch_ip"])
            else:
                st.info("Sin datos de topología en esta ejecución.")

        with t_raw:
            raws = db.get_raw(run["id"])
            only_custom = st.toggle("Solo comandos adicionales (Custom CLI)")
            blob = []
            for r in raws:
                if only_custom and not r["is_custom"]:
                    continue
                badge = "🛠️ " if r["is_custom"] else ""
                badge += "" if r["ok"] else "⚠️ "
                with st.expander(f"{badge}{r['command']}"):
                    st.code(r["output"] or "(sin salida)", language=None)
                blob.append(f"### {r['command']}\n{r['output']}\n")
            if raws:
                st.download_button("⬇️ Descargar todos los logs (.txt)", "\n".join(blob).encode("utf-8"),
                                   file_name=f"raw_{run['hostname'] or run['switch_ip']}_{run['id']}.txt")

        with t_vlan:
            vl = db.get_vlans(run["id"])
            if vl:
                st.dataframe(pd.DataFrame(vl)[["vlan_id", "name", "svi_ip"]]
                             .rename(columns={"vlan_id": "VLAN", "name": "Nombre", "svi_ip": "SVI / IP"}),
                             width="stretch", hide_index=True)
            else:
                st.info("No se obtuvieron VLANs.")

# ======================================================= Proyecto ============
with tab_proj:
    latest = db.latest_runs_per_switch(pid)
    if not latest:
        st.info("Aún no hay ejecuciones exitosas en este proyecto.")
    else:
        ps = project_summary(db, pid)
        m = st.columns(6)
        m[0].metric("Switches escaneados", ps["switches_escaneados"])
        m[1].metric("Puertos activos", f"{ps['puertos_activos']}/{ps['puertos_total']}")
        m[2].metric("Hosts únicos", ps["hosts_unicos"])
        m[3].metric("Enlaces de infraestructura", ps["enlaces_infra"])
        m[4].metric("Uplinks no administrados", ps["uplinks_no_admin"])
        m[5].metric("VLANs / SVIs", f"{ps['vlans_unicas']} / {ps['svis']}")
        st.caption("Topología consolidada: se usa la ejecución exitosa más reciente de cada switch, "
                   "y se unen entre sí cuando un switch aparece como vecino CDP/LLDP de otro.")
        data = enrich_with_project_arp(db, [(r, db.get_port_rows(r["id"])) for r in latest])
        show_topology(data, key="project", title=project["name"], hosts_default=False)
        st.markdown("#### Tabla consolidada del proyecto")
        all_rows = [{**row, "switch": r.get("hostname") or r["switch_ip"]} for r, rr in data for row in rr]
        dfp = rows_df(all_rows, with_switch=True)
        hide_down = st.toggle("Ocultar puertos inactivos", value=True)
        st.dataframe(dfp[dfp["Categoría"] != CAT_DOWN] if hide_down else dfp,
                     width="stretch", hide_index=True, height=420)
        st.download_button("⬇️ Descargar CSV consolidado", dfp.to_csv(index=False).encode("utf-8-sig"),
                           file_name=f"proyecto_{pid}_consolidado.csv", mime="text/csv")

# ======================================================== Comparar ===========
with tab_cmp:
    if len(ok_runs) < 2:
        st.info("Se necesitan al menos dos ejecuciones exitosas para comparar.")
    else:
        st.caption("Ideal para comparar el mismo switch antes y después de un cambio.")
        c1, c2 = st.columns(2)
        old = c1.selectbox("Ejecución anterior", ok_runs, index=1, format_func=run_label, key="cmp_old")
        new = c2.selectbox("Ejecución nueva", ok_runs, index=0, format_func=run_label, key="cmp_new")
        if old["id"] == new["id"]:
            st.warning("Elige dos ejecuciones distintas.")
        else:
            if (old.get("hostname") or old["switch_ip"]) != (new.get("hostname") or new["switch_ip"]):
                st.info("Estás comparando switches distintos: la comparación es por nombre de puerto.")
            d = diff_runs(db.get_port_rows(old["id"]), db.get_port_rows(new["id"]))
            m = st.columns(4)
            m[0].metric("Nuevos", len(d["nuevos"]))
            m[1].metric("Desaparecidos", len(d["desaparecidos"]))
            m[2].metric("Puertos con cambio de estado", len(d["cambios_estado"]))
            m[3].metric("Hosts que cambiaron de puerto", len(d["hosts_movidos"]))
            for title, key in (("🆕 Nuevos", "nuevos"), ("👻 Desaparecidos", "desaparecidos")):
                st.markdown(f"##### {title}")
                if d[key]:
                    st.dataframe(rows_df(d[key]), width="stretch", hide_index=True)
                else:
                    st.caption("Ninguno.")
            st.markdown("##### 🔁 Cambios de estado de puerto")
            if d["cambios_estado"]:
                st.dataframe(pd.DataFrame(d["cambios_estado"]).rename(
                    columns={"port": "Puerto", "antes": "Antes", "ahora": "Ahora"}),
                    width="stretch", hide_index=True)
            else:
                st.caption("Ninguno.")
            st.markdown("##### 🚚 Hosts que cambiaron de puerto")
            if d["hosts_movidos"]:
                st.dataframe(pd.DataFrame(d["hosts_movidos"]), width="stretch", hide_index=True)
            else:
                st.caption("Ninguno.")

# ======================================================== Historial ==========
with tab_hist:
    if not runs:
        st.info("Sin ejecuciones todavía.")
    else:
        hist = pd.DataFrame([{
            "ID": r["id"], "Estado": RUN_STATUS.get(r["status"], r["status"]),
            "Switch": r.get("hostname") or "-", "IP": r["switch_ip"],
            "Plataforma": platform_label(r["platform"]),
            "Inicio": r["started_at"].replace("T", " "),
            "Puertos activos": r["summary"].get("puertos_activos"),
            "Hosts": r["summary"].get("hosts"), "Vecinos": r["summary"].get("vecinos_infra"),
            "Nota": r.get("notes") or "", "Error": r.get("error") or "",
        } for r in runs])
        st.dataframe(hist, width="stretch", hide_index=True)
        with st.expander("🗑️ Eliminar una ejecución"):
            victim = st.selectbox("Ejecución", runs, format_func=run_label, key="del_run")
            if st.button("Eliminar ejecución"):
                db.delete_run(victim["id"])
                st.session_state.pop("selected_run", None)
                st.rerun()
