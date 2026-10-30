"""Reporte final: HTML autocontenido, Excel, ZIP y guardado en carpeta local."""
from __future__ import annotations

import html
import io
import re
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import pandas as pd

from .analysis import enrich_with_project_arp
from .commands import platform_label
from .findings import SEVERITY_ICON, Finding, project_findings, severity_counts
from .icons import icon_data_uri
from .models import CAT_DOWN, CAT_HOST, CAT_INFRA, CAT_UNMANAGED
from .storage import Storage
from .topology import build_graph, render_html

COLUMNS = {
    "switch": "Switch", "port": "Puerto", "status": "Estado", "vlan": "VLAN Native/Tagged",
    "device_type": "Tipo de Dispositivo", "name": "Vecino / Host Name", "mac": "Dirección MAC",
    "ip": "Dirección IP", "method": "Método de Detección", "category": "Categoría",
    "mac_count": "MACs en puerto", "remote_port": "Puerto remoto", "platform": "Plataforma / Descr.",
}
STATUS_TXT = {"up": "Activo", "down": "Inactivo", "disabled": "Deshabilitado",
              "err-disabled": "Err-disabled", "unknown": "Desconocido"}


@dataclass
class ReportData:
    title: str
    scope: str
    generated: datetime
    runs_with_rows: list[tuple[dict, list[dict]]]
    failed: list[dict]
    findings: list[Finding]
    vlans: dict[int, list[dict]] = field(default_factory=dict)   # run_id -> vlans

    @property
    def metrics(self) -> dict:
        rows = [r for _, rr in self.runs_with_rows for r in rr]
        ports = {(run["id"], r["port"]): r["status"] for run, rr in self.runs_with_rows for r in rr}
        sev = severity_counts(self.findings)
        return {
            "Switches recolectados": len(self.runs_with_rows),
            "Fallidos": len(self.failed),
            "Puertos activos": f"{sum(1 for s in ports.values() if s == 'up')}/{len(ports)}",
            "Hosts": len({r['mac'] for r in rows if r['category'] == CAT_HOST and r['mac']}),
            "Hosts con IP": sum(1 for r in rows if r['category'] == CAT_HOST and r['ip']),
            "Vecinos de infraestructura": sum(1 for r in rows if r['category'] == CAT_INFRA),
            "No administrados": sum(1 for r in rows if r['category'] == CAT_UNMANAGED),
            "Hallazgos altos": sev["Alta"], "Hallazgos medios": sev["Media"],
        }


def build_report_data(storage: Storage, runs: list[dict], title: str, scope: str) -> ReportData:
    """runs: ejecuciones a incluir (ok y fallidas)."""
    ok = [r for r in runs if r["status"] == "ok"]
    failed = [r for r in runs if r["status"] == "error"]
    data = enrich_with_project_arp(storage, [(r, storage.get_port_rows(r["id"])) for r in ok])
    return ReportData(title=title, scope=scope, generated=datetime.now(), runs_with_rows=data,
                      failed=failed, findings=project_findings(data, failed),
                      vlans={r["id"]: storage.get_vlans(r["id"]) for r in ok})


def sw_name(run: dict) -> str:
    return run.get("hostname") or run["switch_ip"]


def mapping_df(rd: ReportData, include_down: bool = True) -> pd.DataFrame:
    recs = []
    for run, rows in rd.runs_with_rows:
        for r in rows:
            if not include_down and r["category"] == CAT_DOWN:
                continue
            recs.append({**{k: r.get(k) for k in COLUMNS if k != "switch"}, "switch": sw_name(run)})
    df = pd.DataFrame(recs, columns=list(COLUMNS))
    df["status"] = df["status"].map(lambda s: STATUS_TXT.get(s, s))
    return df.rename(columns=COLUMNS)


def findings_df(rd: ReportData) -> pd.DataFrame:
    return pd.DataFrame([{
        "Severidad": f.severity, "Categoría": f.category, "Hallazgo": f.title, "Switch": f.switch,
        "Puertos": f.ports, "Detalle": f.detail, "Recomendación": f.recommendation,
    } for f in rd.findings])


def topology_html(rd: ReportData, show_hosts: bool = True, height: int = 640,
                  dark: bool = False) -> str:
    return render_html(build_graph(rd.runs_with_rows, show_hosts=show_hosts), height=height,
                       dark=dark, title=rd.title)


# ------------------------------------------------------------------ Excel ---
_XL_ILLEGAL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _xl_safe(value):
    """Excel rechaza caracteres de control (pueden venir en descripciones LLDP) y >32k chars."""
    if isinstance(value, str):
        value = _XL_ILLEGAL.sub(" ", value)
        return value[:32000]
    return value

def to_excel(rd: ReportData) -> bytes:
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    buf = io.BytesIO()
    summary = pd.DataFrame([{"Dato": "Reporte", "Valor": rd.title},
                            {"Dato": "Alcance", "Valor": rd.scope},
                            {"Dato": "Generado", "Valor": rd.generated.strftime("%Y-%m-%d %H:%M")}]
                           + [{"Dato": k, "Valor": v} for k, v in rd.metrics.items()])
    runs = pd.DataFrame([{
        "Ejecución": r["id"], "Switch": sw_name(r), "IP": r["switch_ip"],
        "Plataforma": platform_label(r["platform"]), "Fecha": r["started_at"].replace("T", " "),
        "Estado": r["status"], "Error": r.get("error") or "",
    } for r in [x for x, _ in rd.runs_with_rows] + rd.failed])
    vlans = pd.DataFrame([{"Switch": sw_name(run), "VLAN": v["vlan_id"], "Nombre": v["name"],
                           "SVI / IP": v["svi_ip"]}
                          for run, _ in rd.runs_with_rows for v in rd.vlans.get(run["id"], [])])
    sheets = {"Resumen": summary, "Hallazgos": findings_df(rd), "Mapeo": mapping_df(rd),
              "VLANs": vlans, "Ejecuciones": runs}
    sev_fill = {"Alta": "FEE2E2", "Media": "FFEDD5", "Baja": "FEF9C3", "Info": "DBEAFE"}
    with pd.ExcelWriter(buf, engine="openpyxl") as xw:
        for name, df in sheets.items():
            if df.empty and not len(df.columns):
                df = pd.DataFrame({"Info": ["Sin datos"]})
            df = df.map(_xl_safe) if hasattr(df, "map") else df.applymap(_xl_safe)
            df.to_excel(xw, sheet_name=name, index=False)
            ws = xw.sheets[name]
            for cell in ws[1]:
                cell.font = Font(bold=True, color="FFFFFF")
                cell.fill = PatternFill("solid", fgColor="1E3A8A")
                cell.alignment = Alignment(vertical="center")
            ws.freeze_panes = "A2"
            if ws.max_row > 1:
                ws.auto_filter.ref = ws.dimensions
            for i, col in enumerate(df.columns, start=1):
                width = max([len(str(col))] + [len(str(v)) for v in df[col].head(500)]) + 2
                ws.column_dimensions[get_column_letter(i)].width = min(max(width, 8), 60)
            if name == "Hallazgos":
                for row in ws.iter_rows(min_row=2):
                    color = sev_fill.get(row[0].value)
                    if color:
                        for cell in row:
                            cell.fill = PatternFill("solid", fgColor=color)
                            cell.alignment = Alignment(wrap_text=True, vertical="top")
    return buf.getvalue()


# ------------------------------------------------------------------- HTML ---
def _e(x) -> str:
    return html.escape("" if x is None else str(x))


SEV_COLORS = {"Alta": ("#dc2626", "#fef2f2"), "Media": ("#ea580c", "#fff7ed"),
              "Baja": ("#ca8a04", "#fefce8"), "Info": ("#2563eb", "#eff6ff")}


def to_html(rd: ReportData) -> str:
    m = rd.metrics
    kpis = "".join(f'<div class="kpi"><div class="v">{_e(v)}</div><div class="l">{_e(k)}</div></div>'
                   for k, v in m.items())
    sev = severity_counts(rd.findings)
    chips = "".join(f'<span class="chip" style="background:{SEV_COLORS[k][1]};color:{SEV_COLORS[k][0]}">'
                    f'{SEVERITY_ICON[k]} {k}: {v}</span>' for k, v in sev.items())
    fnd = "".join(_finding_html(f) for f in rd.findings) or "<p>Sin hallazgos.</p>"

    topo = topology_html(rd, show_hosts=True, height=680)
    topo_frame = (f'<iframe class="topo" srcdoc="{html.escape(topo, quote=True)}" '
                  f'title="Topología" loading="lazy"></iframe>')

    switches = []
    for run, rows in rd.runs_with_rows:
        s = run.get("summary") or {}
        active = [r for r in rows if r["category"] != CAT_DOWN]
        body = "".join(_row_html(r) for r in active)
        vl = rd.vlans.get(run["id"], [])
        vlan_txt = ", ".join(f"{v['vlan_id']}{' ' + v['name'] if v['name'] else ''}"
                             f"{' (SVI ' + v['svi_ip'] + ')' if v['svi_ip'] else ''}" for v in vl)
        switches.append(f"""
        <section class="sw">
          <h3><img src="{icon_data_uri('Escaneado')}"/> {_e(sw_name(run))}
            <small>{_e(run['switch_ip'])} · {_e(platform_label(run['platform']))} ·
            {_e(run['started_at'].replace('T', ' '))}</small></h3>
          <div class="mini">
            <span>Puertos activos <b>{s.get('puertos_activos', 0)}/{s.get('puertos_total', 0)}</b></span>
            <span>Hosts <b>{s.get('hosts', 0)}</b></span>
            <span>Vecinos <b>{s.get('vecinos_infra', 0)}</b></span>
            <span>No administrados <b>{s.get('uplinks_no_admin', 0)}</b></span>
            <span>VLANs <b>{s.get('vlans', 0)}</b> · SVIs <b>{s.get('svis', 0)}</b></span>
          </div>
          <table><thead><tr><th>Puerto</th><th>Estado</th><th>VLAN</th><th>Tipo</th>
            <th>Vecino / Host</th><th>MAC</th><th>IP</th><th>Detección</th></tr></thead>
            <tbody>{body}</tbody></table>
          <p class="note">{len(rows) - len(active)} puerto(s) inactivo(s) omitidos ·
            VLANs: {_e(vlan_txt) or '—'}</p>
        </section>""")

    failed = "".join(f"<li><b>{_e(sw_name(r))}</b> ({_e(r['switch_ip'])}): {_e(r.get('error'))}</li>"
                     for r in rd.failed)

    failed_html = ('<h2>Switches que no se pudieron recolectar</h2><ul class="failed">'
                   + failed + "</ul>") if failed else ""
    switches_html = "".join(switches)
    generated = rd.generated.strftime("%d/%m/%Y %H:%M")
    return f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(rd.title)} · Reporte de red</title>
<style>
  :root{{--fg:#0f172a;--muted:#64748b;--line:#e2e8f0;--bg:#f8fafc;--card:#fff;--brand:#1d4ed8}}
  *{{box-sizing:border-box}}
  body{{margin:0;font-family:Inter,"Segoe UI",system-ui,sans-serif;color:var(--fg);background:var(--bg)}}
  header{{background:linear-gradient(135deg,#1e3a8a,#1d4ed8 60%,#0e7490);color:#fff;padding:32px 40px}}
  header h1{{margin:0 0 6px;font-size:26px}} header p{{margin:0;opacity:.85;font-size:13px}}
  main{{max-width:1240px;margin:0 auto;padding:24px 28px 60px}}
  h2{{font-size:18px;margin:34px 0 12px;padding-bottom:8px;border-bottom:2px solid var(--line)}}
  .kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:-44px}}
  .kpi{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px;
        box-shadow:0 4px 14px rgba(15,23,42,.06)}}
  .kpi .v{{font-size:24px;font-weight:700}} .kpi .l{{font-size:12px;color:var(--muted);margin-top:2px}}
  .chips{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}}
  .chip{{padding:4px 10px;border-radius:999px;font-size:12px;font-weight:600}}
  .fd{{background:var(--card);border:1px solid var(--line);border-left:5px solid;border-radius:10px;
       padding:12px 16px;margin-bottom:10px;break-inside:avoid}}
  .fh{{display:flex;gap:8px;align-items:center;flex-wrap:wrap}}
  .sev{{font-size:11px;font-weight:700;padding:2px 8px;border-radius:6px}}
  .cat{{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}}
  .meta{{font-size:12px;color:var(--muted);margin-top:6px}} .det{{font-size:13px;margin-top:6px}}
  .rec{{font-size:13px;margin-top:6px;background:#f1f5f9;border-radius:8px;padding:7px 10px}}
  .topo{{width:100%;height:700px;border:1px solid var(--line);border-radius:12px;background:#fff}}
  .sw{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin-bottom:18px}}
  .sw h3{{margin:0;display:flex;align-items:center;gap:10px;font-size:17px;flex-wrap:wrap}}
  .sw h3 img{{width:30px;height:30px}} .sw h3 small{{font-weight:400;color:var(--muted);font-size:12px}}
  .mini{{display:flex;gap:18px;flex-wrap:wrap;font-size:12px;color:var(--muted);margin:10px 0 12px}}
  .mini b{{color:var(--fg)}}
  table{{width:100%;border-collapse:collapse;font-size:12.5px}}
  th{{text-align:left;background:#f1f5f9;color:#334155;font-weight:600;padding:7px 8px;
      border-bottom:1px solid var(--line);position:sticky;top:0}}
  td{{padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:middle}}
  tr:hover td{{background:#f8fafc}}
  .mono{{font-family:ui-monospace,Consolas,monospace;font-size:12px}}
  .ic{{width:18px;height:18px;vertical-align:middle;margin-right:6px}}
  .dot{{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;background:#94a3b8}}
  .st-up .dot{{background:#16a34a}} .st-err-disabled .dot{{background:#dc2626}}
  .note{{font-size:12px;color:var(--muted);margin:8px 0 0}}
  .failed{{background:#fef2f2;border:1px solid #fecaca;border-radius:10px;padding:10px 18px}}
  footer{{text-align:center;color:var(--muted);font-size:12px;padding:20px}}
  @media print{{ header{{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
    .kpis{{margin-top:12px}} .topo{{height:640px}} body{{background:#fff}} }}
</style></head><body>
<header><h1>{_e(rd.title)}</h1>
  <p>Reporte de red · {_e(rd.scope)} · Generado {generated} con NetOrch</p></header>
<main>
  <div class="kpis">{kpis}</div>
  {failed_html}
  <h2>Hallazgos</h2><div class="chips">{chips}</div>{fnd}
  <h2>Diagrama de red</h2>
  <p class="note">Interactivo: arrastra, haz zoom, pasa el cursor sobre equipos y enlaces. Botón «PNG» para exportar la imagen.</p>
  {topo_frame}
  <h2>Detalle por switch</h2>{switches_html}
</main>
<footer>NetOrch · Orquestador de red · mapeo L1/L2 por SSH</footer>
</body></html>"""


def _row_html(r: dict) -> str:
    cells = [_e(r["port"]),
             '<span class="dot"></span>' + _e(STATUS_TXT.get(r["status"], r["status"])),
             _e(r["vlan"]),
             f'<img class="ic" src="{icon_data_uri(_kind_for(r))}"/>' + _e(r["device_type"]),
             _e(r["name"] or ""),
             '<span class="mono">' + _e(r["mac"] or "") + "</span>",
             '<span class="mono">' + _e(r["ip"] or "") + "</span>",
             _e(r["method"] or "")]
    return f'<tr class="st-{_e(r["status"])}">' + "".join(f"<td>{c}</td>" for c in cells) + "</tr>"


def _finding_html(f: Finding) -> str:
    color, soft = SEV_COLORS[f.severity]
    meta = ""
    if f.switch or f.ports:
        meta = '<div class="meta">Switch: <b>' + _e(f.switch) + "</b>"
        if f.ports:
            meta += " · Puertos: " + _e(f.ports)
        meta += "</div>"
    rec = '<div class="rec">💡 ' + _e(f.recommendation) + "</div>" if f.recommendation else ""
    return (f'<div class="fd" style="border-left-color:{color}"><div class="fh">'
            f'<span class="sev" style="background:{soft};color:{color}">{_e(f.severity)}</span>'
            f'<span class="cat">{_e(f.category)}</span><b>{_e(f.title)}</b></div>'
            f'{meta}<div class="det">{_e(f.detail)}</div>{rec}</div>')


def _kind_for(r: dict) -> str:
    from .icons import PALETTE
    if r["category"] == CAT_UNMANAGED:
        return "No administrado"
    return r["device_type"] if r["device_type"] in PALETTE else "Otro (CDP/LLDP)"


# ---------------------------------------------------------- paquete / disco ---
def slug(text: str) -> str:
    s = re.sub(r"[^\w\-]+", "_", text.strip(), flags=re.UNICODE).strip("_")
    return s[:60] or "reporte"


def export_files(storage: Storage, rd: ReportData) -> dict[str, bytes]:
    """Todos los archivos del reporte: {nombre_relativo: contenido}."""
    files = {
        "reporte.html": to_html(rd).encode("utf-8"),
        "topologia.html": topology_html(rd, height=820).encode("utf-8"),
        "topologia_infraestructura.html": topology_html(rd, show_hosts=False, height=820).encode("utf-8"),
        "reporte.xlsx": to_excel(rd),
        "mapeo.csv": mapping_df(rd).to_csv(index=False).encode("utf-8-sig"),
        "hallazgos.csv": findings_df(rd).to_csv(index=False).encode("utf-8-sig"),
    }
    for run in [r for r, _ in rd.runs_with_rows] + rd.failed:
        raws = storage.get_raw(run["id"])
        if raws:
            text = "\n".join(f"### {x['command']}\n{x['output'] or ''}\n" for x in raws)
            files[f"raw_logs/{slug(sw_name(run))}_{run['id']}.txt"] = text.encode("utf-8")
    return files


def to_zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


def default_export_dir(project_name: str) -> Path:
    home = Path.home()
    docs = next((home / d for d in ("Documents", "Documentos") if (home / d).is_dir()), home)
    return docs / "NetOrch" / slug(project_name)


def save_to_folder(files: dict[str, bytes], base_dir: Path | str) -> Path:
    """Guarda el paquete en <base_dir>/<AAAAMMDD-HHMM>/ y devuelve esa carpeta."""
    dest = Path(base_dir).expanduser() / datetime.now().strftime("%Y%m%d-%H%M%S")
    for name, data in files.items():
        path = dest / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return dest


def open_folder(path: Path) -> bool:
    """Abre la carpeta en el explorador del sistema (solo si la app corre en tu equipo)."""
    import os
    import subprocess
    import sys
    try:
        if sys.platform.startswith("win"):
            os.startfile(str(path))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)])
        return True
    except Exception:
        return False
