"""Íconos SVG propios para el diagrama (estilo plano, mosaico con degradado + glifo blanco).

Se entregan como data-URI para usarlos en vis.js (shape="image") y en el reporte HTML.
"""
from __future__ import annotations

import base64
from functools import lru_cache

# tipo -> (color base, color claro para el degradado)
PALETTE = {
    "Escaneado": ("#1d4ed8", "#3b82f6"),
    "Switch": ("#0e7490", "#06b6d4"),
    "Router": ("#6d28d9", "#8b5cf6"),
    "Firewall": ("#b91c1c", "#ef4444"),
    "AP": ("#15803d", "#22c55e"),
    "Phone": ("#b45309", "#f59e0b"),
    "PC / Host": ("#475569", "#94a3b8"),
    "Servidor / Host (LLDP)": ("#1e293b", "#64748b"),
    "No administrado": ("#c2410c", "#fb923c"),
    "Otro (CDP/LLDP)": ("#64748b", "#a8b4c6"),
}

W = 'stroke="#fff" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round" fill="none"'
F = 'fill="#fff"'


def _arrow(x1, y1, x2, y2, head=5.5) -> str:
    """Línea con punta de flecha en (x2, y2)."""
    import math
    ang = math.atan2(y2 - y1, x2 - x1)
    hx1 = x2 - head * math.cos(ang - 0.6)
    hy1 = y2 - head * math.sin(ang - 0.6)
    hx2 = x2 - head * math.cos(ang + 0.6)
    hy2 = y2 - head * math.sin(ang + 0.6)
    return (f'<path d="M{x1:.1f} {y1:.1f} L{x2:.1f} {y2:.1f} M{hx1:.1f} {hy1:.1f} '
            f'L{x2:.1f} {y2:.1f} L{hx2:.1f} {hy2:.1f}" {W}/>')


GLYPHS = {
    # Switch: flechas en ambos sentidos (conmutación)
    "switch": (_arrow(18, 22, 46, 22) + _arrow(46, 30, 18, 30)
               + _arrow(18, 38, 46, 38) + _arrow(46, 46, 18, 46)),
    # Router: flechas que entran y salen del centro
    "router": (_arrow(32, 12, 32, 26) + _arrow(32, 52, 32, 38)
               + _arrow(28, 32, 13, 32) + _arrow(36, 32, 51, 32)
               + '<circle cx="32" cy="32" r="3" fill="#fff"/>'),
    # Firewall: muro de ladrillos
    "firewall": ('<rect x="14" y="17" width="36" height="30" rx="2" ' + W + '/>'
                 '<path d="M14 27 H50 M14 37 H50 M26 17 V27 M40 17 V27 M20 27 V37 M33 27 V37 '
                 'M46 27 V37 M26 37 V47 M40 37 V47" stroke="#fff" stroke-width="2.6" fill="none"/>'),
    # AP: ondas Wi-Fi
    "ap": ('<path d="M14 28 Q32 12 50 28" ' + W + '/><path d="M20 35 Q32 24 44 35" ' + W + '/>'
           '<path d="M26 42 Q32 37 38 42" ' + W + '/><circle cx="32" cy="48" r="3.4" ' + F + '/>'),
    # Teléfono IP: auricular sobre base con teclado
    "phone": ('<path d="M16 24 Q32 12 48 24 L44 29 Q32 22 20 29 Z" ' + F + '/>'
              '<rect x="17" y="31" width="30" height="19" rx="4" ' + W + '/>'
              + "".join(f'<circle cx="{x}" cy="{y}" r="1.7" fill="#fff"/>'
                        for x in (25, 32, 39) for y in (37, 44))),
    # PC: monitor con base
    "pc": ('<rect x="13" y="15" width="38" height="26" rx="3" ' + W + '/>'
           '<path d="M32 41 V48 M23 49 H41" ' + W + '/>'),
    # Servidor: unidades de rack
    "server": ("".join(f'<rect x="16" y="{y}" width="32" height="10" rx="2" {W}/>'
                       f'<circle cx="22" cy="{y + 5}" r="1.8" fill="#fff"/>'
                       f'<path d="M30 {y + 5} H42" stroke="#fff" stroke-width="2" />'
                       for y in (13, 27, 41))),
    # No administrado: hub con signo de interrogación
    "unmanaged": ('<rect x="13" y="30" width="38" height="16" rx="3" ' + W + '/>'
                  + "".join(f'<circle cx="{x}" cy="38" r="1.8" fill="#fff"/>' for x in (21, 28, 35, 42))
                  + '<path d="M27.5 13 Q27.5 8 32 8 Q36.5 8 36.5 12.5 Q36.5 15.5 32 17 L32 19.5" '
                  'stroke="#fff" stroke-width="2.6" fill="none" stroke-linecap="round"/>'
                  '<circle cx="32" cy="24.5" r="1.9" fill="#fff"/>'),
    "other": ('<circle cx="22" cy="32" r="3.5" fill="#fff"/><circle cx="32" cy="32" r="3.5" fill="#fff"/>'
              '<circle cx="42" cy="32" r="3.5" fill="#fff"/>'),
}
KIND_GLYPH = {
    "Escaneado": "switch", "Switch": "switch", "Router": "router", "Firewall": "firewall",
    "AP": "ap", "Phone": "phone", "PC / Host": "pc", "Servidor / Host (LLDP)": "server",
    "No administrado": "unmanaged", "Otro (CDP/LLDP)": "other",
}


@lru_cache(maxsize=None)
def icon_svg(kind: str) -> str:
    base, light = PALETTE.get(kind, PALETTE["Otro (CDP/LLDP)"])
    glyph = GLYPHS[KIND_GLYPH.get(kind, "other")]
    gid = "g" + "".join(c for c in kind if c.isalnum())
    badge = ""
    if kind == "Escaneado":   # insignia de "recolectado"
        badge = ('<circle cx="52" cy="52" r="10" fill="#22c55e" stroke="#fff" stroke-width="2.5"/>'
                 '<path d="M47 52 L51 56 L57 48" stroke="#fff" stroke-width="2.8" fill="none" '
                 'stroke-linecap="round" stroke-linejoin="round"/>')
    dashed = ' stroke="#fff" stroke-opacity=".55" stroke-width="2" stroke-dasharray="4 3"' \
        if kind == "No administrado" else ""
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">'
        f'<defs><linearGradient id="{gid}" x1="0" y1="0" x2="0" y2="1">'
        f'<stop offset="0" stop-color="{light}"/><stop offset="1" stop-color="{base}"/>'
        f'</linearGradient></defs>'
        f'<rect x="3" y="3" width="58" height="58" rx="15" fill="url(#{gid})"{dashed}/>'
        f'<rect x="3" y="3" width="58" height="29" rx="15" fill="#fff" fill-opacity=".08"/>'
        f'{glyph}{badge}</svg>'
    )


def icon_data_uri(kind: str) -> str:
    return "data:image/svg+xml;base64," + base64.b64encode(icon_svg(kind).encode()).decode()


LEGEND = [
    ("Escaneado", "Switch recolectado"), ("Switch", "Switch vecino"), ("Router", "Router"),
    ("Firewall", "Firewall"), ("AP", "Access Point"), ("Phone", "Teléfono IP"),
    ("PC / Host", "Host / PC"), ("Servidor / Host (LLDP)", "Servidor (LLDP)"),
    ("No administrado", "No administrado / hub"),
]
