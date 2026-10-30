"""NetOrch · Orquestador de Red — interfaz gráfica (Streamlit).

Ejecutar:  streamlit run app.py
"""
from __future__ import annotations

import ipaddress
import os
import tempfile
from datetime import datetime

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from netorch.analysis import diff_runs, project_summary
from netorch.commands import PLATFORMS, platform_choices
from netorch.engine import DemoSession, NetmikoSession, Target, run_collection
from netorch.models import CAT_DOWN
from netorch.storage import DEFAULT_DB, Storage
from netorch.topology import build_graph, render_html

st.set_page_config(page_title="NetOrch · Orquestador de Red", page_icon="🛰️", layout="wide")

STATUS_LABEL = {"up": "🟢 Activo", "down": "🔴 Inactivo", "disabled": "⚫ Deshabilitado",
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


def show_topology(runs_with_rows, key: str):
    c1, c2, _ = st.columns([1, 1, 3])
    hosts = c1.toggle("Mostrar hosts finales", value=True, key=f"{key}_hosts")
    unm = c2.toggle("Mostrar no administrados", value=True, key=f"{key}_unm")
    graph = build_graph(runs_with_rows, show_hosts=hosts, show_unmanaged=unm)
    if not graph.nodes:
        st.info("No hay datos para dibujar.")
        return
    html = render_html(graph, height="640px", dark=is_dark())
    if hasattr(st, "iframe"):
        st.iframe(html, height=660)
    else:                                   # Streamlit < 1.50
        components.html(html, height=660, scrolling=False)
    st.caption("🟦 Switch escaneado · 🟦 Switch vecino · 🟪 Router · 🟥 Firewall · 🟩 AP · "
               "🟨 Teléfono · ⚪ Host · 🟧 No administrado — arrastra, haz zoom y pasa el "
               "cursor sobre nodos y enlaces para ver detalles.")


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
            for plat, ip in DEMO_SET:
                run_collection(db, pid, Target(host=ip, platform=plat, username="demo"),
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
tab_run, tab_res, tab_proj, tab_cmp, tab_hist = st.tabs(
    ["🚀 Nueva ejecución", "📋 Resultados", "🗺️ Topología del proyecto", "🔍 Comparar", "📜 Historial"])

# ======================================================= Nueva ejecución =====
with tab_run:
    st.subheader("Conectar a un switch")
    st.caption("La app abre SSH únicamente contra el equipo indicado: no hace escaneos de red. "
               "Las contraseñas no se guardan.")
    with st.form("run_form"):
        c1, c2, c3 = st.columns([2, 2, 1])
        host = c1.text_input("IP del switch", placeholder="10.0.0.1")
        choices = platform_choices()
        platform = c2.selectbox("Vendor / OS", list(choices), format_func=choices.get)
        port = c3.number_input("Puerto SSH", min_value=1, max_value=65535, value=22)
        c4, c5, c6 = st.columns(3)
        user = c4.text_input("Usuario")
        password = c5.text_input("Contraseña", type="password")
        secret = c6.text_input("Enable password (si aplica)", type="password")
        with st.expander("🔑 Llave SSH privada (opcional)"):
            key_upload = st.file_uploader("Archivo de llave (id_rsa, id_ed25519…)", type=None)
            key_pass = st.text_input("Passphrase de la llave", type="password")
        custom = st.text_area("Comandos adicionales / Custom CLI (uno por línea)",
                              placeholder="show log\nshow power inline\nshow running-config",
                              height=110)
        c7, c8 = st.columns([3, 1])
        notes = c7.text_input("Nota de la ejecución (opcional)", placeholder="Ej. antes de la ventana de cambio")
        timeout = c8.number_input("Timeout (s)", min_value=5, max_value=120, value=20)
        demo = st.checkbox("Modo demo: usar salidas de ejemplo de esta plataforma (sin conectarse)")
        submitted = st.form_submit_button("▶️ Ejecutar recolección", type="primary",
                                          width="stretch")

    if submitted:
        errors = []
        if not demo:
            try:
                ipaddress.ip_address(host.strip())
            except ValueError:
                errors.append("La IP del switch no es válida.")
            if not user.strip():
                errors.append("Falta el usuario SSH.")
            if not password and not key_upload:
                errors.append("Ingresa una contraseña o una llave SSH.")
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
            target = Target(host=host.strip() or "demo", platform=platform, username=user.strip(),
                            password=password, secret=secret, port=int(port), key_file=key_path,
                            key_passphrase=key_pass or None, timeout=int(timeout))
            bar = st.progress(0.0, text="Iniciando…")
            try:
                run_id = run_collection(
                    db, pid, target, custom.splitlines(),
                    progress=lambda msg, frac: bar.progress(min(frac, 1.0), text=msg),
                    session_factory=DemoSession if demo else NetmikoSession,
                    notes=("[demo] " if demo else "") + notes)
            finally:
                if key_path and os.path.exists(key_path):
                    os.remove(key_path)
            run = db.get_run(run_id)
            st.session_state.selected_run = run_id
            if run["status"] == "ok":
                s = run["summary"]
                bar.progress(1.0, text="Completado")
                st.success(f"Ejecución #{run_id} guardada en el proyecto · **{run['hostname'] or host}** · "
                           f"{s['puertos_activos']}/{s['puertos_total']} puertos activos · "
                           f"{s['hosts']} hosts · {s['vecinos_infra']} vecinos de infraestructura. "
                           "Ve a la pestaña **📋 Resultados**.")
            else:
                bar.empty()
                st.error(f"La ejecución #{run_id} falló: {run['error']}")
                st.caption("Las salidas obtenidas antes del error quedan en Resultados → Raw logs.")

# ============================================================ Resultados =====
with tab_res:
    if not runs:
        st.info("Este proyecto aún no tiene ejecuciones.")
    else:
        ids = [r["id"] for r in runs]
        sel = st.session_state.get("selected_run")
        run = st.selectbox("Ejecución", runs, index=ids.index(sel) if sel in ids else 0,
                           format_func=run_label, key="res_run")
        st.caption(f"Plataforma: {PLATFORMS[run['platform']].label} · Usuario: {run['username'] or '-'}"
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
                show_topology([(run, rows)], key=f"run{run['id']}")
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
        data = [(r, db.get_port_rows(r["id"])) for r in latest]
        show_topology(data, key="project")
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
            "Plataforma": PLATFORMS[r["platform"]].label,
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
