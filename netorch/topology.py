"""Diagrama topológico interactivo (vis-network, sin dependencias de internet).

- Íconos SVG propios por tipo de equipo (netorch/icons.py).
- Layout jerárquico: firewalls/routers arriba, core, distribución/acceso, y hosts abajo.
  Se puede cambiar a layout libre (física) desde la barra del diagrama.
- Sirve para una ejecución o para la topología consolidada del proyecto: los switches
  escaneados se empatan con los vecinos CDP/LLDP de otros switches por IP o hostname.
"""
from __future__ import annotations

import json
from collections import defaultdict, deque
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Optional

from .icons import LEGEND, icon_data_uri
from .models import CAT_HOST, CAT_INFRA, CAT_UNMANAGED
from .utils import short_hostname

INFRA_KINDS = {"Escaneado", "Switch", "Router", "Firewall"}
EDGE_KINDS = {"Router", "Firewall"}            # equipos de borde: se dibujan arriba del core
SIZES = {"Escaneado": 34, "Switch": 28, "Router": 28, "Firewall": 28, "AP": 22, "Phone": 20,
         "PC / Host": 16, "Servidor / Host (LLDP)": 18, "No administrado": 22,
         "Otro (CDP/LLDP)": 20}


@dataclass
class Graph:
    nodes: dict[str, dict] = field(default_factory=dict)
    edges: dict[tuple, dict] = field(default_factory=dict)
    aliases: dict[str, str] = field(default_factory=dict)  # ip / hostname corto / mac -> node id

    def node(self, nid: str, label: str, kind: str, title: str = "", sub: str = "",
             size: Optional[int] = None):
        if nid not in self.nodes:
            self.nodes[nid] = {"label": label, "kind": kind, "title": title, "sub": sub,
                               "size": size or SIZES.get(kind, 20)}
        elif kind == "Escaneado":                  # un vecino que también se escaneó
            self.nodes[nid].update(kind=kind, label=label, sub=sub or self.nodes[nid]["sub"],
                                   size=SIZES["Escaneado"], title=title or self.nodes[nid]["title"])
        return nid

    def edge(self, a: str, b: str, label: str, kind: str = "backbone"):
        key = tuple(sorted((a, b)))
        # Si 'a' no es el primero de la llave, la etiqueta "local ↔ remoto" se voltea para que
        # los dos extremos reporten el mismo enlace igual (y no salga duplicado)
        if kind == "backbone" and label and " ↔ " in label and a != key[0]:
            left, right = label.split(" ↔ ", 1)
            label = f"{right} ↔ {left}"
        if key in self.edges:
            if label and label not in self.edges[key]["labels"]:
                # "Gi1/0/47 ↔ 49" y "Gi1/0/47" son el mismo enlace: se queda el más completo
                same = [x for x in self.edges[key]["labels"]
                        if x.split(" ↔ ")[0] == label.split(" ↔ ")[0]]
                if same and " ↔ " in label:
                    self.edges[key]["labels"].remove(same[0])
                    self.edges[key]["labels"].append(label)
                elif not same:
                    self.edges[key]["labels"].append(label)
        else:
            self.edges[key] = {"labels": [label] if label else [], "kind": kind}

    def resolve(self, name: Optional[str], ip: Optional[str], mac: Optional[str]) -> Optional[str]:
        for key in (ip, short_hostname(name), mac):
            if key and key in self.aliases:
                return self.aliases[key]
        return None


def display_name(name: Optional[str], limit: int = 22) -> str:
    """'RTR-WAN-MTY.lab.local' -> 'RTR-WAN-MTY' (las IPs y MACs se dejan igual)."""
    n = (name or "").strip()
    if n and not any(c == ":" for c in n) and not n.replace(".", "").isdigit():
        n = n.split(".")[0]
    return n if len(n) <= limit else n[:limit - 1] + "…"


def build_graph(runs_with_rows: list[tuple[dict, list[dict]]], show_hosts: bool = True,
                show_unmanaged: bool = True) -> Graph:
    g = Graph()
    # 1) Switches escaneados primero, para empatar los vecinos con ellos
    for run, _ in runs_with_rows:
        sw_name = run.get("hostname") or run["switch_ip"]
        nid = "sw:" + short_hostname(sw_name)
        s = run.get("summary") or {}
        g.node(nid, display_name(sw_name), "Escaneado", sub=run["switch_ip"], title=(
            f"{sw_name}  (recolectado)\nIP: {run['switch_ip']} · {run['platform']}\n"
            f"Puertos activos: {s.get('puertos_activos', '?')}/{s.get('puertos_total', '?')}\n"
            f"Hosts: {s.get('hosts', 0)} · Vecinos: {s.get('vecinos_infra', 0)}\n"
            f"Fecha: {run['started_at'].replace('T', ' ')}"))
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
                    g.node(target, display_name(r["name"]) or r["mac"] or "?", r["device_type"],
                           sub=r["ip"] or "",
                           title=(f"{r['name']}\n{r['device_type']}\nIP: {r['ip'] or '-'}\n"
                                  f"MAC: {r['mac'] or '-'}\n{(r['platform'] or '')[:140]}"))
                    for key in (r["ip"], short_hostname(r["name"]), r["mac"]):
                        if key:
                            g.aliases.setdefault(key, target)
                label = f"{r['port']} ↔ {r['remote_port']}" if r["remote_port"] else r["port"]
                kind = "backbone" if g.nodes[target]["kind"] in INFRA_KINDS else "leaf"
                g.edge(sw_id, target, label, kind)
            elif r["category"] == CAT_HOST and show_hosts:
                nid = "host:" + (r["mac"] or f"{sw_id}:{r['port']}")
                kind = r["device_type"] if r["device_type"] in SIZES else "PC / Host"
                main = display_name(r["name"]) if r["name"] and kind != "PC / Host" \
                    else (r["ip"] or r["mac"])
                sub = r["mac"] if main == r["ip"] else (r["ip"] or "")
                g.node(nid, main, kind, sub=sub, title=(
                    f"{r['name'] or 'Host'}\nIP: {r['ip'] or 'sin ARP'}\nMAC: {r['mac']}\n"
                    f"Puerto: {r['port']} · VLAN {r['vlan']}\nDetección: {r['method']}"))
                g.edge(sw_id, nid, r["port"], "leaf")
            elif r["category"] == CAT_UNMANAGED and show_unmanaged:
                nid = f"unm:{sw_id}:{r['port']}"
                g.node(nid, "No administrado", "No administrado",
                       sub=f"{r['mac_count']} MACs",
                       title=f"Hub / switch no administrado en {r['port']}\n"
                             f"{r['mac_count']} MACs sin CDP/LLDP · VLAN {r['vlan']}")
                g.edge(sw_id, nid, r["port"], "unmanaged")
    return g


def compute_levels(g: Graph) -> dict[str, int]:
    """Niveles para el layout jerárquico: borde (FW/router) → core → acceso → hosts."""
    adj: dict[str, set[str]] = defaultdict(set)
    for a, b in g.edges:
        adj[a].add(b)
        adj[b].add(a)
    infra = [n for n, d in g.nodes.items() if d["kind"] in INFRA_KINDS]
    if not infra:
        return {n: 0 for n in g.nodes}
    scanned = [n for n in infra if g.nodes[n]["kind"] == "Escaneado"] or infra
    root = max(scanned, key=lambda n: sum(1 for m in adj[n] if g.nodes[m]["kind"] in INFRA_KINDS))
    level = {root: 1}
    q = deque([root])
    while q:
        n = q.popleft()
        for m in adj[n]:
            if m in level or g.nodes[m]["kind"] not in INFRA_KINDS:
                continue
            # Firewalls/routers colgados del core van arriba (salida a WAN/Internet)
            if g.nodes[m]["kind"] in EDGE_KINDS and level[n] == 1:
                level[m] = 0
            else:
                level[m] = level[n] + 1
            q.append(m)
    for n in infra:
        level.setdefault(n, 1)
    deepest = max(level.values())
    for n, d in g.nodes.items():
        if n in level:
            continue
        parents = [level[m] for m in adj[n] if m in level]
        level[n] = (max(parents) + 1) if parents else deepest + 1
    return level


def compute_layout(g: Graph, unit: float = 118, level_gap: float = 170, row_gap: float = 88,
                   max_cols: int = 4) -> dict[str, tuple[float, float]]:
    """Layout de árbol propio (sin cruces): cada switch con sus equipos justo debajo.

    - Los hosts/APs/teléfonos de un switch se acomodan en una rejilla de `max_cols` columnas.
    - Los firewalls/routers conectados al core van en una fila arriba de él.
    - Enlaces redundantes (anillos) se dibujan igual, pero no alteran el árbol.
    """
    levels = compute_levels(g)
    adj: dict[str, list[str]] = defaultdict(list)
    for a, b in g.edges:
        adj[a].append(b)
        adj[b].append(a)
    kind = {n: d["kind"] for n, d in g.nodes.items()}
    infra = [n for n in g.nodes if kind[n] in INFRA_KINDS]
    if not g.nodes:
        return {}
    top = {n for n in infra if levels.get(n) == 0}
    order = sorted(g.nodes, key=lambda n: (levels.get(n, 0), g.nodes[n]["label"]))
    infra_children: dict[str, list[str]] = defaultdict(list)
    leaf_children: dict[str, list[str]] = defaultdict(list)
    parent: dict[str, str] = {}
    roots: list[str] = []

    def bfs(root: str):
        q = deque([root])
        parent[root] = ""
        while q:
            n = q.popleft()
            for m in sorted(adj[n], key=lambda x: g.nodes[x]["label"]):
                if m in parent or kind[m] not in INFRA_KINDS or m in top:
                    continue
                parent[m] = n
                infra_children[n].append(m)
                q.append(m)

    for n in order:
        if kind[n] in INFRA_KINDS and n not in top and n not in parent:
            roots.append(n)
            bfs(n)
    for n in order:                                # hojas -> su switch
        if n in parent or n in top:
            continue
        ups = [m for m in adj[n] if m in parent]
        if ups:
            p = min(ups, key=lambda m: levels.get(m, 0))
            parent[n] = p
            leaf_children[p].append(n)
        else:
            roots.append(n)
            parent[n] = ""

    width: dict[str, float] = {}

    def w(n: str) -> float:
        if n not in width:
            leaves = len(leaf_children[n])
            width[n] = max(1.0, sum(w(c) for c in infra_children[n]) + min(max_cols, leaves))
        return width[n]

    pos: dict[str, tuple[float, float]] = {}

    def place(n: str, x0: float, depth: int):
        pos[n] = ((x0 + w(n) / 2) * unit, depth * level_gap)
        cursor = x0
        for c in infra_children[n]:
            place(c, cursor, depth + 1)
            cursor += w(c)
        leaves = leaf_children[n]
        if leaves and not infra_children[n]:
            cursor = x0 + (w(n) - min(max_cols, len(leaves))) / 2
        for i, leaf in enumerate(leaves):
            col, row = i % max_cols, i // max_cols
            stagger = 0.5 if row % 2 else 0.0      # filas intercaladas: los enlaces pasan entre nodos
            pos[leaf] = ((cursor + col + 0.5 + stagger) * unit, (depth + 1) * level_gap + row * row_gap)

    x = 0.0
    for r in roots:
        place(r, x, 1)
        x += w(r) + 0.8
    # Fila superior: firewalls/routers centrados sobre el switch al que se conectan
    by_anchor: dict[str, list[str]] = defaultdict(list)
    for t in sorted(top, key=lambda n: g.nodes[n]["label"]):
        anchors = [m for m in adj[t] if m in pos]
        by_anchor[anchors[0] if anchors else ""].append(t)
    for anchor, tops in by_anchor.items():
        cx = pos[anchor][0] if anchor in pos else x * unit
        for i, t in enumerate(tops):
            pos[t] = (cx + (i - (len(tops) - 1) / 2) * unit * 1.2, 0.0)
    return pos


@lru_cache(maxsize=1)
def _vis_assets() -> tuple[str, str]:
    import pyvis
    base = Path(pyvis.__file__).parent / "lib" / "vis-9.1.2"
    return ((base / "vis-network.min.js").read_text(encoding="utf-8"),
            (base / "vis-network.css").read_text(encoding="utf-8"))


def _safe(text) -> str:
    """Los nombres vienen de los equipos (CDP/LLDP): se neutraliza cualquier HTML."""
    return str(text or "").replace("&", "＆").replace("<", "‹").replace(">", "›")


def _js(obj) -> str:
    """JSON seguro para incrustar dentro de <script>."""
    return json.dumps(obj).replace("</", "<\\/")


def render_html(g: Graph, height: int = 650, dark: bool = False, title: str = "",
                hierarchical: bool = True) -> str:
    """HTML autocontenido (funciona sin internet) con el diagrama interactivo."""
    js, css = _vis_assets()
    fg, bg = ("#e2e8f0", "#0b1220") if dark else ("#0f172a", "#f8fafc")
    grid = "#1e293b" if dark else "#e2e8f0"
    muted = "#94a3b8" if dark else "#64748b"
    levels = compute_levels(g)
    positions = compute_layout(g)

    nodes = []
    for nid, n in g.nodes.items():
        label = f"<b>{_safe(n['label'])}</b>"
        if n["sub"]:
            label += f"\n<i>{_safe(n['sub'])}</i>"
        node = {"id": nid, "label": label, "title": _safe(n["title"]),
                "image": icon_data_uri(n["kind"]), "shape": "image",
                "size": n["size"]}
        if nid in positions:
            node["x"], node["y"] = positions[nid]
        if n["kind"] not in INFRA_KINDS:
            node["font"] = {"size": 11, "bold": {"size": 11}, "ital": {"size": 10}}
        nodes.append(node)
    edge_style = {
        "backbone": {"width": 3.2, "color": "#64748b" if not dark else "#94a3b8"},
        "leaf": {"width": 1.3, "color": "#cbd5e1" if not dark else "#475569"},
        "unmanaged": {"width": 1.6, "color": "#fb923c", "dashes": [6, 4]},
    }
    edges = []
    for (a, b), e in g.edges.items():
        st = edge_style[e["kind"]]
        flip = levels.get(a, 0) > levels.get(b, 0)   # se dibuja de arriba hacia abajo
        if e["kind"] == "backbone":
            labels = [" ↔ ".join(reversed(x.split(" ↔ "))) if flip else x for x in e["labels"]]
            label = " / ".join(labels[:2])
        else:
            label = " / ".join(sorted({x.split(" ↔ ")[0] for x in e["labels"]}))
        if flip:
            a, b = b, a
        edges.append({"from": a, "to": b, "label": _safe(label),
                      "title": _safe(" | ".join(e["labels"])), "width": st["width"],
                      "color": {"color": st["color"], "highlight": "#2563eb", "hover": "#2563eb"},
                      "dashes": st.get("dashes", False)})

    present = {n["kind"] for n in g.nodes.values()}
    legend = "".join(
        f'<div class="lg"><img src="{icon_data_uri(k)}"/><span>{lbl}</span></div>'
        for k, lbl in LEGEND if k in present)

    options = {
        "nodes": {"font": {"multi": "html", "face": "Inter, Segoe UI, system-ui, sans-serif",
                           "size": 13, "color": fg, "strokeWidth": 4, "strokeColor": bg,
                           "bold": {"size": 13, "color": fg}, "ital": {"size": 11, "color": muted}},
                  "shapeProperties": {"useImageSize": False, "interpolation": True},
                  "shadow": {"enabled": True, "color": "rgba(15,23,42,.18)", "size": 8, "x": 0, "y": 3}},
        "edges": {"font": {"size": 10, "color": muted, "strokeWidth": 3, "strokeColor": bg,
                           "face": "Inter, Segoe UI, system-ui, sans-serif", "align": "middle"},
                  "smooth": {"type": "cubicBezier", "forceDirection": "vertical", "roundness": 0.45}},
        "interaction": {"hover": True, "navigationButtons": True, "keyboard": True,
                        "tooltipDelay": 120},
    }
    free_physics = {"enabled": True, "solver": "barnesHut",
                    "barnesHut": {"gravitationalConstant": -14000, "springLength": 130,
                                  "springConstant": 0.04, "avoidOverlap": 0.4},
                    "stabilization": {"iterations": 300}}

    title_html = (f'<div class="ttl">{_safe(title)}<small>{len(g.nodes)} nodos · '
                  f'{len(g.edges)} enlaces</small></div>') if title else ""
    layout_btn = "⇄ Libre" if hierarchical else "⇅ Jerárquico"
    btn_bg = "#111827" if dark else "#ffffff"
    legend_bg = "rgba(17,24,39,.88)" if dark else "rgba(255,255,255,.92)"
    tip_bg = "#111827" if dark else "#fff"
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_safe(title) or "Topología de red"}</title>
<style>{css}</style>
<style>
  html,body{{margin:0;padding:0;background:{bg};font-family:Inter,"Segoe UI",system-ui,sans-serif}}
  #wrap{{position:relative;width:100%;height:{height}px;border-radius:12px;overflow:hidden;
        background:{bg};background-image:radial-gradient({grid} 1px,transparent 1px);
        background-size:22px 22px}}
  #net{{position:absolute;inset:0}}
  .bar{{position:absolute;top:12px;right:12px;display:flex;gap:6px;z-index:5}}
  .bar button{{font:600 12px Inter,system-ui,sans-serif;border:1px solid {grid};
        background:{btn_bg};color:{fg};padding:7px 11px;border-radius:8px;
        cursor:pointer;box-shadow:0 1px 2px rgba(0,0,0,.06)}}
  .bar button:hover{{border-color:#2563eb;color:#2563eb}}
  .ttl{{position:absolute;top:14px;left:16px;z-index:5;color:{fg};font-weight:700;font-size:15px}}
  .ttl small{{display:block;color:{muted};font-weight:500;font-size:11px;margin-top:2px}}
  .legend{{position:absolute;left:12px;bottom:12px;z-index:5;display:flex;flex-wrap:wrap;gap:4px 12px;
        max-width:70%;padding:8px 12px;border-radius:10px;border:1px solid {grid};
        background:{legend_bg}}}
  .lg{{display:flex;align-items:center;gap:6px;font-size:11px;color:{fg}}}
  .lg img{{width:18px;height:18px}}
  div.vis-tooltip{{white-space:pre-line;font:12px Inter,system-ui,sans-serif;padding:8px 10px;
        border-radius:8px;border:1px solid {grid};background:{tip_bg};
        color:{fg};box-shadow:0 6px 18px rgba(0,0,0,.15);max-width:340px}}
  div.vis-network div.vis-navigation div.vis-button{{opacity:.55}}
  div.vis-network div.vis-navigation div.vis-button:hover{{opacity:1;box-shadow:none}}
  div.vis-network div.vis-navigation div.vis-button.vis-up,
  div.vis-network div.vis-navigation div.vis-button.vis-down,
  div.vis-network div.vis-navigation div.vis-button.vis-left,
  div.vis-network div.vis-navigation div.vis-button.vis-right{{display:none}}
</style></head><body>
<div id="wrap">
  {title_html}
  <div class="bar">
    <button id="bLayout" title="Cambiar acomodo">{layout_btn}</button>
    <button id="bFit" title="Encuadrar todo">⤢ Encuadrar</button>
    <button id="bPng" title="Descargar imagen PNG">⬇ PNG</button>
  </div>
  <div id="net"></div>
  <div class="legend">{legend}</div>
</div>
<script>{js}</script>
<script>
(function(){{
  var nodes = new vis.DataSet({_js(nodes)});
  var edges = new vis.DataSet({_js(edges)});
  var opts = {json.dumps(options)};
  var FREE = {json.dumps(free_physics)};
  var hierarchical = {str(hierarchical).lower()};
  var TREE = {{}};
  nodes.forEach(function(n){{ TREE[n.id] = {{x:n.x, y:n.y}}; }});
  opts.layout = {{hierarchical:{{enabled:false}}}};
  opts.physics = hierarchical ? {{enabled:false}} : FREE;
  var el = document.getElementById('net');
  var network = new vis.Network(el, {{nodes:nodes, edges:edges}}, opts);
  window.network = network;
  function fit(){{
    if (!el.clientWidth || !el.clientHeight) return;      // pestaña oculta: se hará al mostrarse
    network.setSize('100%', '100%');                       // el canvas toma el tamaño real
    network.redraw(); network.fit({{animation:false}});
    // margen para que la leyenda y la barra no tapen equipos
    var c = network.getViewPosition();
    network.moveTo({{position:{{x:c.x, y:c.y + 25 / network.getScale()}}, scale:network.getScale() * 0.93}});
  }}
  network.once('afterDrawing', fit);
  network.on('stabilizationIterationsDone', function(){{ network.setOptions({{physics:{{enabled:false}}}}); fit(); }});
  document.getElementById('bFit').onclick = fit;
  document.getElementById('bLayout').onclick = function(){{
    hierarchical = !hierarchical;
    this.textContent = hierarchical ? '⇄ Libre' : '⇅ Jerárquico';
    if (hierarchical) {{
      network.setOptions({{physics:{{enabled:false}}}});
      Object.keys(TREE).forEach(function(id){{ network.moveNode(id, TREE[id].x, TREE[id].y); }});
      setTimeout(fit, 30);
    }} else {{
      network.setOptions({{physics:FREE}});
      network.stabilize(300);
    }}
  }};
  document.getElementById('bPng').onclick = function(){{
    // Se dibuja al doble de tamaño para que la imagen salga nítida
    var w = el.clientWidth, h = el.clientHeight, scale = 2;
    network.setSize((w * scale) + 'px', (h * scale) + 'px');
    network.fit({{animation:false}});
    network.once('afterDrawing', function(ctxDraw){{
      var src = el.querySelector('canvas');
      var out = document.createElement('canvas');
      out.width = src.width; out.height = src.height;
      var ctx = out.getContext('2d');
      ctx.fillStyle = '{bg}'; ctx.fillRect(0, 0, out.width, out.height);
      ctx.drawImage(src, 0, 0);
      var a = document.createElement('a');
      a.download = 'topologia.png'; a.href = out.toDataURL('image/png');
      document.body.appendChild(a); a.click(); a.remove();
      network.setSize('100%', '100%'); fit();
    }});
    network.redraw();
  }};
  // En Streamlit las pestañas ocultas miden 0: al hacerse visible se vuelve a encuadrar
  var last = 0;
  new ResizeObserver(function(){{
    var w = el.clientWidth;
    if (w > 0 && Math.abs(w - last) > 20) {{ last = w; setTimeout(fit, 60); }}
  }}).observe(el);
}})();
</script></body></html>"""
