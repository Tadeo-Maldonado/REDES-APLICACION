"""Diagrama topológico interactivo (Pyvis / vis.js).

Sirve tanto para una ejecución como para la topología consolidada del proyecto:
los switches escaneados se empatan con los vecinos CDP/LLDP de otros switches por
IP de gestión o por hostname, así que las ejecuciones se "cosen" en un solo grafo.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .models import CAT_HOST, CAT_INFRA, CAT_UNMANAGED
from .utils import short_hostname

COLORS = {
    "Escaneado": "#2563eb", "Switch": "#0891b2", "Router": "#7c3aed", "Firewall": "#dc2626",
    "AP": "#16a34a", "Phone": "#ca8a04", "Servidor / Host (LLDP)": "#475569",
    "PC / Host": "#64748b", "No administrado": "#f97316", "Otro (CDP/LLDP)": "#94a3b8",
}
SHAPES = {
    "Escaneado": "box", "Switch": "box", "Router": "ellipse", "Firewall": "diamond",
    "AP": "triangle", "Phone": "dot", "PC / Host": "dot", "Servidor / Host (LLDP)": "square",
    "No administrado": "star",
}


@dataclass
class Graph:
    nodes: dict[str, dict] = field(default_factory=dict)
    edges: dict[tuple, dict] = field(default_factory=dict)
    aliases: dict[str, str] = field(default_factory=dict)  # ip / hostname corto -> node id

    def node(self, nid: str, label: str, kind: str, title: str = "", size: int = 18):
        if nid not in self.nodes:
            self.nodes[nid] = {"label": label, "kind": kind, "title": title, "size": size}
        elif kind == "Escaneado":                  # un vecino que luego se escaneó
            self.nodes[nid].update(kind=kind, label=label, size=size,
                                   title=title or self.nodes[nid]["title"])
        return nid

    def edge(self, a: str, b: str, label: str):
        key = tuple(sorted((a, b)))
        if key in self.edges:
            if label and label not in self.edges[key]["labels"]:
                self.edges[key]["labels"].append(label)
        else:
            self.edges[key] = {"labels": [label] if label else []}

    def resolve(self, name: Optional[str], ip: Optional[str], mac: Optional[str]) -> Optional[str]:
        for key in (ip, short_hostname(name), mac):
            if key and key in self.aliases:
                return self.aliases[key]
        return None


def build_graph(runs_with_rows: list[tuple[dict, list[dict]]], show_hosts: bool = True,
                show_unmanaged: bool = True) -> Graph:
    g = Graph()
    # 1) Registrar primero los switches escaneados para poder empatar vecinos con ellos
    for run, _ in runs_with_rows:
        sw_name = run.get("hostname") or run["switch_ip"]
        nid = "sw:" + short_hostname(sw_name)
        s = run.get("summary") or {}
        g.node(nid, sw_name, "Escaneado", size=30, title=(
            f"{sw_name}\n{run['switch_ip']} · {run['platform']}\n"
            f"Puertos activos: {s.get('puertos_activos', '?')}/{s.get('puertos_total', '?')}\n"
            f"Hosts: {s.get('hosts', 0)} · Vecinos: {s.get('vecinos_infra', 0)}\n"
            f"Escaneado: {run['started_at']}"))
        g.aliases[run["switch_ip"]] = nid
        g.aliases[short_hostname(sw_name)] = nid

    # 2) Conexiones de cada switch
    for run, rows in runs_with_rows:
        sw_id = "sw:" + short_hostname(run.get("hostname") or run["switch_ip"])
        for r in rows:
            if r["category"] == CAT_INFRA:
                target = g.resolve(r["name"], r["ip"], r["mac"])
                if not target:
                    target = "nb:" + (short_hostname(r["name"]) or r["mac"] or r["port"])
                    g.node(target, r["name"] or r["mac"] or "?", r["device_type"], title=(
                        f"{r['name']}\n{r['device_type']}\nIP: {r['ip'] or '-'}\n"
                        f"MAC: {r['mac'] or '-'}\n{(r['platform'] or '')[:120]}"))
                    for key in (r["ip"], short_hostname(r["name"]), r["mac"]):
                        if key:
                            g.aliases.setdefault(key, target)
                label = f"{r['port']} ↔ {r['remote_port']}" if r["remote_port"] else r["port"]
                g.edge(sw_id, target, label)
            elif r["category"] == CAT_HOST and show_hosts:
                nid = "host:" + (r["mac"] or f"{sw_id}:{r['port']}")
                kind = r["device_type"] if r["device_type"] in COLORS else "PC / Host"
                g.node(nid, r["ip"] or r["name"] or r["mac"], kind, size=10, title=(
                    f"{r['name'] or 'Host'}\nIP: {r['ip'] or 'sin ARP'}\nMAC: {r['mac']}\n"
                    f"Puerto: {r['port']} · VLAN {r['vlan']}\nDetección: {r['method']}"))
                g.edge(sw_id, nid, r["port"])
            elif r["category"] == CAT_UNMANAGED and show_unmanaged:
                nid = f"unm:{sw_id}:{r['port']}"
                g.node(nid, f"No administrado\n({r['mac_count']} MACs)", "No administrado",
                       size=16, title=f"Hub / switch no administrado en {r['port']}\n"
                                      f"{r['mac_count']} MACs sin CDP/LLDP")
                g.edge(sw_id, nid, r["port"])
    return g


def _safe(text) -> str:
    """Los nombres vienen de los equipos (CDP/LLDP): se neutraliza cualquier HTML."""
    return str(text or "").replace("<", "‹").replace(">", "›").replace("&", "＆")


def render_html(g: Graph, height: str = "650px", dark: bool = False) -> str:
    import json
    from pyvis.network import Network

    fg = "#e2e8f0" if dark else "#0f172a"
    net = Network(height=height, width="100%", directed=False, cdn_resources="in_line",
                  bgcolor="#0f172a" if dark else "#ffffff", font_color=fg)
    for nid, n in g.nodes.items():
        net.add_node(nid, label=_safe(n["label"]), title=_safe(n["title"]), size=n["size"],
                     color=COLORS.get(n["kind"], "#94a3b8"), shape=SHAPES.get(n["kind"], "dot"))
    for (a, b), e in g.edges.items():
        backbone = not a.startswith(("host:", "unm:")) and not b.startswith(("host:", "unm:"))
        local_ports = sorted({lbl.split(" ↔ ")[0] for lbl in e["labels"]})
        net.add_edge(a, b, title=_safe(" | ".join(e["labels"])),
                     label=_safe(" / ".join(local_ports)), width=3 if backbone else 1.2)
    options = {
        "physics": {"barnesHut": {"gravitationalConstant": -12000, "springLength": 130,
                                  "springConstant": 0.04, "avoidOverlap": 0.3},
                    "minVelocity": 0.75, "stabilization": {"iterations": 300, "fit": True}},
        "edges": {"font": {"size": 10, "align": "top", "color": fg,
                           "strokeWidth": 3, "strokeColor": "#0f172a" if dark else "#ffffff"},
                  "smooth": {"type": "continuous"},
                  "color": {"inherit": False, "color": "#94a3b8"}},
        "nodes": {"font": {"size": 13, "color": fg}, "borderWidth": 1},
        "interaction": {"hover": True, "navigationButtons": True, "keyboard": True},
    }
    net.set_options(json.dumps(options))
    html = net.generate_html(notebook=False)
    # Tooltips multilínea, sin bordes extra y encuadre automático al terminar de acomodarse
    css = ("<style>div.vis-tooltip{white-space:pre-line;font-family:system-ui,sans-serif;"
           "font-size:12px} body{margin:0} .card{border:none!important}"
           "#mynetwork{border:none!important}</style>")
    # En Streamlit las pestañas ocultas tienen tamaño 0: al hacerse visible el diagrama
    # se vuelve a dibujar y encuadrar.
    js = ("<script>if (typeof network !== 'undefined') {"
          "var refit=function(){network.setSize('100%','" + height + "');network.redraw();"
          "network.fit({animation:false});};"
          "network.once('stabilizationIterationsDone', refit);"
          "var el=document.getElementById('mynetwork');var last=0;"
          "new ResizeObserver(function(){var w=el.clientWidth;"
          "if(w>0&&Math.abs(w-last)>20){last=w;setTimeout(refit,50);}}).observe(el);"
          "window.addEventListener('resize', refit);}</script>")
    html = html.replace("</head>", css + "</head>", 1)
    return html.replace("</body>", js + "</body>", 1)
