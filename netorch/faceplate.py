"""'Frente de switch': un cuadro por puerto, coloreado por lo que tiene conectado."""
from __future__ import annotations

import html
import re

from .oui import vendor_for_row
from .models import (CAT_DOWN, CAT_HOST, CAT_INFRA, CAT_LAG_MEMBER, CAT_ROUTED, CAT_TRUNK_EMPTY,
                     CAT_UNMANAGED, CAT_UP_NO_MAC)

# Prioridad cuando un puerto tiene varias filas (p. ej. teléfono + PC)
PRIORITY = [CAT_INFRA, CAT_UNMANAGED, CAT_HOST, CAT_ROUTED, CAT_LAG_MEMBER, CAT_TRUNK_EMPTY,
            CAT_UP_NO_MAC, CAT_DOWN]

# (fondo, texto, etiqueta de leyenda)
STYLE = {
    "Switch": ("#0e7490", "#fff", "Switch"),
    "Router": ("#6d28d9", "#fff", "Router"),
    "Firewall": ("#b91c1c", "#fff", "Firewall"),
    "AP": ("#15803d", "#fff", "AP"),
    "Phone": ("#b45309", "#fff", "Teléfono"),
    "infra_other": ("#475569", "#fff", "Otro vecino"),
    CAT_HOST: ("#22c55e", "#052e16", "Host"),
    CAT_UNMANAGED: ("#f97316", "#fff", "No administrado"),
    CAT_ROUTED: ("#8b5cf6", "#fff", "L3"),
    CAT_LAG_MEMBER: ("#38bdf8", "#082f49", "Miembro LAG"),
    CAT_TRUNK_EMPTY: ("#94a3b8", "#0f172a", "Activo sin tráfico"),
    CAT_UP_NO_MAC: ("#94a3b8", "#0f172a", "Activo sin tráfico"),
    "err-disabled": ("#dc2626", "#fff", "Err-disabled"),
    "disabled": ("#1f2937", "#9ca3af", "Apagado"),
    CAT_DOWN: ("#e5e7eb", "#6b7280", "Sin enlace"),
}


def _sort_key(port: str):
    return [int(t) if t.isdigit() else t.lower() for t in re.split(r"(\d+)", port)]


def _style_for(row: dict) -> str:
    if row["status"] == "err-disabled":
        return "err-disabled"
    if row["category"] == CAT_DOWN:
        return "disabled" if row["status"] == "disabled" else CAT_DOWN
    if row["category"] == CAT_INFRA:
        return row["device_type"] if row["device_type"] in STYLE else "infra_other"
    return row["category"] if row["category"] in STYLE else CAT_UP_NO_MAC


def port_cells(rows: list[dict]) -> list[dict]:
    """Un elemento por puerto físico con su estilo y texto de ayuda."""
    by_port: dict[str, list[dict]] = {}
    for r in rows:
        by_port.setdefault(r["port"], []).append(r)
    cells = []
    for port in sorted(by_port, key=_sort_key):
        if port.lower().startswith(("po", "trk", "lag", "0/")):     # lógicos: no van al frente
            continue
        items = sorted(by_port[port], key=lambda r: PRIORITY.index(r["category"])
                       if r["category"] in PRIORITY else 99)
        main = items[0]
        lines = [f"{port} · {main['status']} · VLAN {main['vlan'] or '-'}"]
        for r in items:
            if r["category"] in (CAT_INFRA, CAT_HOST):
                lines.append(" · ".join(x for x in (r["device_type"], r["name"], r["ip"], r["mac"],
                                                    vendor_for_row(r)) if x))
            elif r["category"] == CAT_UNMANAGED:
                lines.append(f"No administrado: {r['mac_count']} MACs"
                             + (f" ({vendor_for_row(r)})" if r.get("mac_list") else ""))
            elif r["category"] != CAT_DOWN:
                lines.append(r["category"])
        short = port.split("/")[-1] if "/" in port else re.sub(r"^[A-Za-z]+", "", port) or port
        cells.append({"port": port, "short": short, "style": _style_for(main),
                      "tip": "\n".join(lines)})
    return cells


def render_faceplate(rows: list[dict], max_per_row: int = 24, show_legend: bool = True) -> str:
    """HTML (sin scripts) con el frente del switch; los puertos impares arriba como un switch real."""
    cells = port_cells(rows)
    if not cells:
        return '<div style="color:#94a3b8;font-size:12px">Sin puertos.</div>'
    blocks = [cells[i:i + max_per_row * 2] for i in range(0, len(cells), max_per_row * 2)]
    out = ['<div class="fp">']
    for block in blocks:
        top, bottom = block[0::2], block[1::2]
        for row in (top, bottom):
            out.append('<div class="fp-row">')
            for c in row:
                bg, fg, _ = STYLE[c["style"]]
                out.append(f'<span class="fp-p" style="background:{bg};color:{fg}" '
                           f'title="{html.escape(c["tip"], quote=True)}">{html.escape(c["short"])}</span>')
            out.append("</div>")
        out.append('<div class="fp-gap"></div>')
    out.append("</div>")
    if show_legend:
        used = []
        for c in cells:
            label = STYLE[c["style"]][2]
            if label not in [u[0] for u in used]:
                used.append((label, STYLE[c["style"]][0]))
        out.append('<div class="fp-lg">' + "".join(
            f'<span><i style="background:{color}"></i>{html.escape(label)}</span>'
            for label, color in used) + "</div>")
    css = """<style>
      .fp{display:inline-block;padding:8px 10px;border-radius:8px;background:#0f172a;
          box-shadow:inset 0 0 0 1px #334155}
      .fp-row{display:flex;gap:3px;margin:2px 0}
      .fp-gap{height:4px}
      .fp-p{display:inline-flex;align-items:center;justify-content:center;width:22px;height:18px;
            border-radius:3px;font:600 9px/1 Inter,system-ui,sans-serif;cursor:default;
            box-shadow:inset 0 -2px 0 rgba(0,0,0,.18)}
      .fp-lg{display:flex;flex-wrap:wrap;gap:4px 12px;margin-top:6px;font:11px Inter,system-ui,sans-serif;
             color:#64748b}
      .fp-lg span{display:inline-flex;align-items:center;gap:5px}
      .fp-lg i{width:10px;height:10px;border-radius:2px;display:inline-block}
    </style>"""
    return css + "".join(out)
