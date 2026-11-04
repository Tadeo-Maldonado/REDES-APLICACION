"""Fabricante de una MAC según el registro oficial del IEEE (OUI / MA-L, MA-M, MA-S, IAB).

Regla de oro: el **fabricante** sale únicamente de la asignación oficial del IEEE (quién compró
ese prefijo). No se adivina por patrones. Si el prefijo no está registrado, o la MAC es
"administrada localmente" (aleatoria por privacidad, virtual o cambiada a mano), se dice así.

Base incluida: netorch/oui_data/ieee_oui.tsv.gz (copia del registro IEEE). Se puede actualizar
desde la app (descarga los CSV oficiales de standards-oui.ieee.org) y se guarda en data/.
"""
from __future__ import annotations

import csv
import gzip
import io
import re
import urllib.request
from dataclasses import dataclass
from datetime import date
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Optional

from .utils import normalize_mac

ROOT = Path(__file__).resolve().parent
BUNDLED_DB = ROOT / "oui_data" / "ieee_oui.tsv.gz"
USER_DB = ROOT.parent / "data" / "ieee_oui.tsv.gz"      # versión actualizada por el usuario

IEEE_CSV_URLS = {
    "MA-L": "https://standards-oui.ieee.org/oui/oui.csv",
    "MA-M": "https://standards-oui.ieee.org/oui28/mam.csv",
    "MA-S": "https://standards-oui.ieee.org/oui36/oui36.csv",
    "IAB": "https://standards-oui.ieee.org/iab/iab.csv",
}

# ------------------------------------------------------------------ marcas ---
# Nombre corto de la marca y rubro del FABRICANTE (no del equipo). Solo empresas conocidas;
# el rubro describe a qué se dedica el fabricante, no adivina qué es el equipo concreto.
BRANDS: list[tuple[str, str, str]] = [
    # (regex sobre el nombre IEEE, marca, rubro del fabricante)
    (r"^alcatel-lucent enterprise|^ale usa|^alcatel-lucent", "Alcatel-Lucent Enterprise", "Red"),
    (r"^cisco meraki", "Cisco Meraki", "Red"),
    (r"^cisco-linksys", "Linksys", "Red (hogar / PyME)"),
    (r"^cisco", "Cisco", "Red"),
    (r"^aruba|^hewlett packard enterprise", "HPE / Aruba", "Red / Servidores"),
    (r"^juniper networks", "Juniper", "Red"),
    (r"^arista", "Arista", "Red"),
    (r"^extreme networks", "Extreme Networks", "Red"),
    (r"^ruckus|^ruckus wireless", "Ruckus", "Red inalámbrica"),
    (r"^ubiquiti", "Ubiquiti", "Red"),
    (r"^routerboard|^mikrotik", "MikroTik", "Red"),
    (r"^allied telesis", "Allied Telesis", "Red"),
    (r"^brocade", "Brocade", "Red"),
    (r"^dell emc networking|^force10", "Dell Networking", "Red"),
    (r"^netgear", "Netgear", "Red"),
    (r"^tp-link", "TP-Link", "Red"),
    (r"^d-link", "D-Link", "Red"),
    (r"^zyxel", "Zyxel", "Red"),
    (r"^cambium", "Cambium Networks", "Red inalámbrica"),
    (r"^huawei", "Huawei", "Red / Telecom / Móviles"),
    (r"^h3c|new h3c", "H3C", "Red"),
    (r"^ruijie", "Ruijie", "Red"),
    (r"^nokia", "Nokia", "Telecom"),
    (r"^fortinet", "Fortinet", "Seguridad de red"),
    (r"^palo alto networks", "Palo Alto Networks", "Seguridad de red"),
    (r"^check point", "Check Point", "Seguridad de red"),
    (r"^sonicwall", "SonicWall", "Seguridad de red"),
    (r"^watchguard technologies", "WatchGuard", "Seguridad de red"),
    (r"^sophos", "Sophos", "Seguridad de red"),
    (r"^barracuda", "Barracuda", "Seguridad de red"),
    (r"^f5,? |^f5 networks", "F5", "Balanceo / seguridad"),
    (r"hikvision", "Hikvision", "Videovigilancia"),
    (r"dahua", "Dahua", "Videovigilancia"),
    (r"^axis communications", "Axis", "Videovigilancia"),
    (r"hanwha (techwin|vision)|samsung techwin", "Hanwha Vision", "Videovigilancia"),
    (r"uniview|zhejiang uniview", "Uniview", "Videovigilancia"),
    (r"^vivotek", "Vivotek", "Videovigilancia"),
    (r"^avigilon", "Avigilon", "Videovigilancia"),
    (r"^mobotix", "Mobotix", "Videovigilancia"),
    (r"^bosch security", "Bosch Security", "Videovigilancia / seguridad"),
    (r"^pelco\b", "Pelco", "Videovigilancia"),
    (r"ezviz", "EZVIZ", "Videovigilancia"),
    (r"^polycom", "Polycom / Poly", "Telefonía IP"),
    (r"^yealink", "Yealink", "Telefonía IP"),
    (r"^grandstream", "Grandstream", "Telefonía IP"),
    (r"^mitel", "Mitel", "Telefonía IP"),
    (r"^avaya", "Avaya", "Telefonía / Red"),
    (r"^snom", "Snom", "Telefonía IP"),
    (r"^vmware", "VMware", "Virtualización"),
    (r"^dell( inc| emc| technologies|$)", "Dell", "Cómputo / Servidores"),
    (r"^hp inc", "HP", "Cómputo / Impresión"),
    (r"^hewlett[- ]packard", "Hewlett-Packard", "Cómputo / Impresión / Red (ProCurve)"),
    (r"^lenovo", "Lenovo", "Cómputo"),
    (r"^apple", "Apple", "Cómputo / Móviles"),
    (r"^microsoft", "Microsoft", "Cómputo"),
    (r"^asustek", "ASUS", "Cómputo"),
    (r"^acer", "Acer", "Cómputo"),
    (r"^intel corporat", "Intel", "Componentes (tarjetas de red)"),
    (r"^realtek", "Realtek", "Componentes (tarjetas de red)"),
    (r"^super micro", "Supermicro", "Servidores"),
    (r"^ibm", "IBM", "Servidores / Cómputo"),
    (r"^samsung electronics", "Samsung", "Electrónica / Móviles"),
    (r"^xiaomi", "Xiaomi", "Electrónica / Móviles"),
    (r"^lexmark", "Lexmark", "Impresión"),
    (r"^kyocera document", "Kyocera", "Impresión"),
    (r"^brother industries", "Brother", "Impresión"),
    (r"^xerox", "Xerox", "Impresión"),
    (r"^ricoh", "Ricoh", "Impresión"),
    (r"^canon", "Canon", "Impresión / Imagen"),
    (r"^epson|seiko epson", "Epson", "Impresión"),
    (r"^zebra technologies", "Zebra", "Impresión de etiquetas / lectores"),
    (r"^honeywell", "Honeywell", "Automatización / lectores"),
    (r"^american power conversion", "APC", "Energía / UPS"),
    (r"^schneider electric|^telemecanique", "Schneider Electric", "Energía / automatización"),
    (r"^eaton\b", "Eaton", "Energía / automatización"),
    (r"^vertiv|^liebert", "Vertiv", "Energía / UPS"),
    (r"^siemens", "Siemens", "Industrial / automatización"),
    (r"^rockwell automation|^allen-bradley", "Rockwell / Allen-Bradley", "Industrial / automatización"),
    (r"^phoenix contact", "Phoenix Contact", "Industrial / automatización"),
    (r"^moxa", "Moxa", "Industrial / redes"),
    (r"^hirschmann|^belden", "Hirschmann / Belden", "Industrial / redes"),
    (r"^raspberry pi", "Raspberry Pi", "Cómputo embebido"),
    (r"^espressif", "Espressif", "IoT (módulos Wi-Fi)"),
]
_BRAND_RE = [(re.compile(rx, re.IGNORECASE), brand, segment) for rx, brand, segment in BRANDS]


@dataclass(frozen=True)
class MacVendor:
    mac: str
    vendor: str        # nombre oficial IEEE, o explicación si no aplica
    brand: str         # nombre corto ("Hikvision")
    segment: str       # rubro del fabricante ("Videovigilancia"), "" si no se conoce
    status: str        # ieee | local | unregistered | invalid

    @property
    def label(self) -> str:
        return self.brand if self.status == "ieee" else self.vendor


# --------------------------------------------------------------- base local ---
def _write_db(path: Path, entries: dict[tuple[int, str], str], source: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    buf = io.StringIO()
    buf.write(f"# source={source} date={date.today().isoformat()} entries={len(entries)}\n")
    for (bits, prefix), org in sorted(entries.items(), key=lambda x: (x[0][1], x[0][0])):
        buf.write(f"{prefix}\t{bits}\t{org}\n")
    with gzip.open(path, "wt", encoding="utf-8") as f:
        f.write(buf.getvalue())


@lru_cache(maxsize=1)
def _load() -> tuple[dict[int, dict[str, str]], dict]:
    path = USER_DB if USER_DB.exists() else BUNDLED_DB
    tables: dict[int, dict[str, str]] = {24: {}, 28: {}, 36: {}}
    meta = {"path": str(path), "source": "?", "date": "?", "entries": 0}
    if not path.exists():
        return tables, meta
    try:
        with gzip.open(path, "rt", encoding="utf-8") as f:
            for line in f:
                if line.startswith("#"):
                    meta.update(re.findall(r"(\w+)=(.*?)(?=\s+\w+=|\s*$)", line[1:].strip()))
                    continue
                prefix, bits, org = line.rstrip("\n").split("\t", 2)
                tables.setdefault(int(bits), {})[prefix] = org
    except Exception as exc:      # base dañada: se trabaja sin fabricantes
        meta["error"] = str(exc)
    meta["entries"] = sum(len(t) for t in tables.values())
    meta["user_updated"] = path == USER_DB
    return tables, meta


def db_info() -> dict:
    return dict(_load()[1])


@lru_cache(maxsize=256)
def brand_of(org: str) -> tuple[str, str]:
    for rx, brand, segment in _BRAND_RE:
        if rx.search(org):
            return brand, segment
    short = re.sub(r"[,.]?\s*(co\.?,?\s*)?(ltd|inc|corp(oration)?|llc|gmbh|s\.?a\.?|limited|"
                   r"technologies|technology|company|co)\b\.?", "", org, flags=re.IGNORECASE)
    return (re.sub(r"\s+", " ", short).strip(" ,.") or org)[:40], ""


@lru_cache(maxsize=65536)
def lookup(mac: Optional[str]) -> MacVendor:
    norm = normalize_mac(mac or "")
    if not norm:
        return MacVendor(mac or "", "", "", "", "invalid")
    hexs = norm.replace(":", "").upper()
    first = int(hexs[:2], 16)
    if first & 0x02:
        return MacVendor(norm, "MAC local/aleatoria (privacidad o virtual): sin fabricante", "—",
                         "", "local")
    tables, _ = _load()
    for bits in (36, 28, 24):                      # el prefijo más largo gana
        org = tables.get(bits, {}).get(hexs[:bits // 4])
        if org:
            brand, segment = brand_of(org)
            return MacVendor(norm, org, brand, segment, "ieee")
    return MacVendor(norm, "Prefijo no registrado en el IEEE", "—", "", "unregistered")


def vendor_label(mac: Optional[str]) -> str:
    """Texto corto para tablas: 'Hikvision', '—' si no hay MAC."""
    if not mac:
        return ""
    v = lookup(mac)
    return v.label if v.status != "invalid" else ""


def summarize_vendors(macs: Iterable[str], limit: int = 4) -> str:
    """'3 Hikvision, 2 Dell, 1 MAC local' para resumir lo que hay detrás de un hub."""
    counts: dict[str, int] = {}
    for m in macs:
        v = lookup(m)
        key = v.brand if v.status == "ieee" else ("MAC local" if v.status == "local" else "desconocido")
        counts[key] = counts.get(key, 0) + 1
    items = sorted(counts.items(), key=lambda x: (-x[1], x[0]))
    text = ", ".join(f"{n} {k}" for k, n in items[:limit])
    return text + (f", +{len(items) - limit} más" if len(items) > limit else "")


# ------------------------------------------------- construir / actualizar ---
def parse_ieee_text(text: str, iab: bool = False) -> dict[tuple[int, str], str]:
    """Formato de texto del IEEE (oui.txt / iab.txt)."""
    out: dict[tuple[int, str], str] = {}
    hex_prefix = None
    for line in text.splitlines():
        if m := re.match(r"^([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){2})\s+\(hex\)\s+(.*)$", line):
            hex_prefix = m.group(1).replace("-", "").upper()
            if not iab:
                out[(24, hex_prefix)] = m.group(2).strip()
        elif iab and hex_prefix and (m := re.match(r"^([0-9A-Fa-f]{6})-[0-9A-Fa-f]{6}\s+\(base 16\)\s+(.*)$",
                                                     line)):
            out[(36, hex_prefix + m.group(1).upper()[:3])] = m.group(2).strip()
    return out


def parse_ieee_csv(text: str) -> dict[tuple[int, str], str]:
    """CSV oficial: Registry,Assignment,Organization Name,Organization Address."""
    out: dict[tuple[int, str], str] = {}
    for row in csv.DictReader(io.StringIO(text)):
        assignment = (row.get("Assignment") or "").strip().upper()
        org = (row.get("Organization Name") or "").strip()
        if re.fullmatch(r"[0-9A-F]{6}|[0-9A-F]{7}|[0-9A-F]{9}", assignment) and org:
            out[(len(assignment) * 4, assignment)] = org
    return out


def update_from_ieee(timeout: float = 60) -> dict:
    """Descarga los registros oficiales del IEEE y reemplaza la base local (data/)."""
    entries: dict[tuple[int, str], str] = {}
    report = {}
    for name, url in IEEE_CSV_URLS.items():
        req = urllib.request.Request(url, headers={"User-Agent": "NetOrch-OUI-updater/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            part = parse_ieee_csv(resp.read().decode("utf-8", "replace"))
        report[name] = len(part)
        entries.update(part)
    if report.get("MA-L", 0) < 10000:
        raise RuntimeError(f"Descarga incompleta del IEEE ({report}); no se reemplazó la base.")
    _write_db(USER_DB, entries, "IEEE standards-oui (MA-L, MA-M, MA-S, IAB)")
    _load.cache_clear()
    lookup.cache_clear()
    return {**report, "total": len(entries), "path": str(USER_DB)}


def vendor_for_row(row: dict) -> str:
    """Columna "Fabricante (IEEE)" de una fila del mapeo.

    - Host / vecino: fabricante de su MAC.
    - Uplink no administrado / con varias MACs sin vecino: resumen por fabricante.
    """
    mac_list = (row.get("mac_list") or "").split()
    if row.get("mac"):
        return vendor_label(row["mac"])
    if mac_list:
        return summarize_vendors(mac_list)
    return ""
