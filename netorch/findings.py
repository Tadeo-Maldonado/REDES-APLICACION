"""Hallazgos automáticos a partir del mapeo de uno o varios switches.

Severidades: Alta (atender), Media (revisar), Baja (higiene), Info (inventario/contexto).
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, asdict

from .models import CAT_HOST, CAT_INFRA, CAT_UNMANAGED, CAT_UP_NO_MAC
from .oui import summarize_vendors
from .utils import short_hostname

SEVERITY_ORDER = {"Alta": 0, "Media": 1, "Baja": 2, "Info": 3}
SEVERITY_ICON = {"Alta": "🔴", "Media": "🟠", "Baja": "🟡", "Info": "🔵"}


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    detail: str
    switch: str = ""
    ports: str = ""
    recommendation: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _sw_name(run: dict) -> str:
    return run.get("hostname") or run["switch_ip"]


def _native(vlan_text: str):
    """'N:1 T:10,20' -> ('trunk', 1) · '10 (U) +T:20' -> ('access', 10)."""
    vlan_text = vlan_text or ""
    if m := re.match(r"N:(\d+)", vlan_text):
        return "trunk", int(m.group(1))
    if m := re.match(r"(\d+) \(U\)", vlan_text):
        return "access", int(m.group(1))
    return None, None


def _ports_list(rows: list[dict], extra=None, limit: int = 12) -> str:
    items = [f"{r['port']}{f' ({extra(r)})' if extra else ''}" for r in rows]
    more = f" … y {len(items) - limit} más" if len(items) > limit else ""
    return ", ".join(items[:limit]) + more


def _macs_with_vendors(r: dict) -> str:
    vendors = summarize_vendors((r.get("mac_list") or "").split()) if r.get("mac_list") else ""
    return f"{r['mac_count']} MACs" + (f": {vendors}" if vendors else "")


def switch_findings(run: dict, rows: list[dict]) -> list[Finding]:
    sw = _sw_name(run)
    out: list[Finding] = []
    s = run.get("summary") or {}

    unm = [r for r in rows if r["category"] == CAT_UNMANAGED]
    unm_trunk = [r for r in unm if (r["vlan"] or "").startswith("N:")]
    unm_access = [r for r in unm if r not in unm_trunk]
    if unm_access:
        out.append(Finding(
            "Alta", "Equipos no administrados",
            f"{len(unm_access)} puerto(s) de acceso con varias MACs y sin CDP/LLDP",
            "Detrás de estos puertos hay un hub, un switch no administrado o un equipo que no "
            "anuncia CDP/LLDP. Son puntos ciegos: no se ve qué hay conectado y pueden causar loops.",
            sw, _ports_list(unm_access, _macs_with_vendors),
            "Identificar físicamente el equipo; reemplazarlo por uno administrado o habilitar LLDP. "
            "Activar BPDU Guard / loop-protect en puertos de acceso."))
    if unm_trunk:
        out.append(Finding(
            "Alta", "Equipos no administrados",
            f"{len(unm_trunk)} trunk(s) con tráfico pero sin vecino CDP/LLDP",
            "El puerto lleva varias VLANs y aprende MACs, pero el equipo del otro lado no se "
            "identifica. Suele ser un switch con LLDP apagado o de otro fabricante.",
            sw, _ports_list(unm_trunk, _macs_with_vendors),
            "Habilitar LLDP en ambos extremos y documentar el enlace."))

    errd = [r for r in rows if r["status"] == "err-disabled"]
    if errd:
        out.append(Finding(
            "Alta", "Puertos", f"{len(errd)} puerto(s) en err-disabled",
            "El switch apagó estos puertos por una violación (port-security, BPDU Guard, "
            "flapping, etc.).", sw, _ports_list(errd),
            "Revisar 'show interfaces status err-disabled' / logs, corregir la causa y reactivar."))

    no_ip = [r for r in rows if r["category"] == CAT_HOST and not r["ip"]]
    if no_ip:
        by_vlan: dict[str, list[dict]] = defaultdict(list)
        for r in no_ip:
            by_vlan[str(_native(r["vlan"])[1] or "?")].append(r)
        vl = ", ".join(f"VLAN {v} ({len(rr)})" for v, rr in sorted(by_vlan.items()))
        out.append(Finding(
            "Media", "Visibilidad", f"{len(no_ip)} host(s) sin IP resuelta",
            f"Este switch no tiene la ARP de esas VLANs ({vl}): el gateway está en otro equipo.",
            sw, _ports_list(no_ip),
            "Ejecutar también el switch/router que tiene la SVI o gateway de esas VLANs; "
            "en la vista del proyecto se cruzan las IPs automáticamente."))

    trunk_hosts = [r for r in rows if r["category"] == CAT_HOST and "trunk" in (r["method"] or "")]
    if trunk_hosts:
        out.append(Finding(
            "Baja", "Seguridad", f"{len(trunk_hosts)} host(s) conectado(s) en puerto trunk/tagged",
            "Un equipo final en un trunk puede alcanzar VLANs que no necesita.",
            sw, _ports_list(trunk_hosts),
            "Configurar el puerto como acceso con solo las VLANs necesarias (datos + voz)."))

    if s.get("vecinos_infra", 0) == 0:
        out.append(Finding(
            "Media", "Descubrimiento", "No se detectaron vecinos CDP/LLDP",
            "Sin protocolo de descubrimiento no se pueden identificar switches, APs ni teléfonos.",
            sw, "", "Habilitar LLDP (y CDP en Cisco) en el switch y en sus vecinos."))

    idle = [r for r in rows if r["category"] == CAT_UP_NO_MAC]
    if idle:
        out.append(Finding(
            "Baja", "Puertos", f"{len(idle)} puerto(s) activo(s) sin MAC aprendida",
            "Hay enlace pero ningún tráfico: equipo apagado/en reposo, o un puerto mal asignado.",
            sw, _ports_list(idle), "Validar qué hay conectado; documentar o apagar si no se usa."))

    total, down = s.get("puertos_total", 0), s.get("puertos_inactivos", 0)
    if total and down / total >= 0.5:
        out.append(Finding(
            "Info", "Capacidad", f"{down} de {total} puertos libres ({down * 100 // total}%)",
            "Capacidad disponible para crecimiento o consolidación de switches.", sw))
    disabled = [r for r in rows if r["status"] == "disabled"]
    if disabled:
        out.append(Finding("Info", "Puertos", f"{len(disabled)} puerto(s) apagado(s) administrativamente",
                           "Apagados con 'shutdown' (buena práctica para puertos sin uso).",
                           sw, _ports_list(disabled)))
    inv = {t: sum(1 for r in rows if r["category"] == CAT_INFRA and r["device_type"] == t)
           for t in ("Switch", "Router", "Firewall", "AP", "Phone")}
    if any(inv.values()):
        out.append(Finding(
            "Info", "Inventario", "Equipos conectados directamente",
            " · ".join(f"{k}: {v}" for k, v in inv.items() if v)
            + f" · Hosts: {s.get('hosts', 0)}", sw))
    return out


def project_findings(runs_with_rows: list[tuple[dict, list[dict]]],
                     failed_runs: list[dict] | None = None) -> list[Finding]:
    """Hallazgos que solo se ven cruzando varios switches (más los de cada switch)."""
    out: list[Finding] = []
    for run in failed_runs or []:
        out.append(Finding(
            "Alta", "Recolección", f"No se pudo recolectar {_sw_name(run)}",
            run.get("error") or "Error desconocido", _sw_name(run), "",
            "Verificar IP, credenciales, ACLs de gestión y que SSH esté habilitado; volver a ejecutar."))

    for run, rows in runs_with_rows:
        out += switch_findings(run, rows)

    # Identidad de los switches escaneados (por hostname corto e IP)
    scanned: dict[str, str] = {}
    for run, _ in runs_with_rows:
        name = _sw_name(run)
        scanned[short_hostname(name)] = name
        scanned[run["switch_ip"]] = name
    by_sw = {_sw_name(run): rows for run, rows in runs_with_rows}

    # VLAN nativa / modo distinto entre dos switches escaneados que se ven entre sí
    checked = set()
    for run, rows in runs_with_rows:
        a = _sw_name(run)
        for r in rows:
            if r["category"] != CAT_INFRA:
                continue
            b = scanned.get(r["ip"] or "") or scanned.get(short_hostname(r["name"]))
            if not b or b == a or (a, r["port"]) in checked:
                continue
            back = [x for x in by_sw[b] if x["category"] == CAT_INFRA
                    and (scanned.get(x["ip"] or "") == a or scanned.get(short_hostname(x["name"])) == a)
                    and (not r["remote_port"] or x["port"] == r["remote_port"]
                         or x["port"].endswith(r["remote_port"]))]
            if not back:
                continue
            x = back[0]
            checked.update({(a, r["port"]), (b, x["port"])})   # el enlace se revisa una vez
            mode_a, nat_a = _native(r["vlan"])
            mode_b, nat_b = _native(x["vlan"])
            if mode_a and mode_b and mode_a != mode_b:
                out.append(Finding(
                    "Alta", "VLANs", f"Modo distinto en el enlace {a} ↔ {b}",
                    f"{a} {r['port']} está en {mode_a} y {b} {x['port']} en {mode_b}.",
                    f"{a} / {b}", f"{r['port']} ↔ {x['port']}",
                    "Ambos extremos deben ser trunk (o ambos acceso) con las mismas VLANs."))
            elif nat_a is not None and nat_b is not None and nat_a != nat_b:
                out.append(Finding(
                    "Alta", "VLANs", f"VLAN nativa distinta en el enlace {a} ↔ {b}",
                    f"{a} {r['port']} usa VLAN {nat_a} y {b} {x['port']} usa VLAN {nat_b}: el "
                    "tráfico sin etiqueta se mezcla entre VLANs.",
                    f"{a} / {b}", f"{r['port']} ↔ {x['port']}",
                    "Igualar la VLAN nativa en ambos extremos (idealmente una VLAN sin uso)."))

    # Equipos de infraestructura vistos como vecinos pero no recolectados
    pending: dict[str, dict] = {}
    for run, rows in runs_with_rows:
        for r in rows:
            if r["category"] == CAT_INFRA and r["device_type"] in ("Switch", "Router", "Firewall") \
                    and not (scanned.get(r["ip"] or "") or scanned.get(short_hostname(r["name"]))):
                key = short_hostname(r["name"]) or r["ip"]
                pending.setdefault(key, {"name": r["name"], "ip": r["ip"], "type": r["device_type"],
                                         "seen": f"{_sw_name(run)} {r['port']}"})
    if pending:
        out.append(Finding(
            "Info", "Cobertura", f"{len(pending)} equipo(s) de infraestructura sin recolectar",
            "; ".join(f"{p['type']} {p['name']} ({p['ip'] or 'sin IP'}) visto en {p['seen']}"
                      for p in pending.values()), "", "",
            "Agregarlos al inventario para completar la topología (los firewalls/routers suelen "
            "tener la ARP de las VLANs)."))

    # La misma MAC vista como host en dos lugares distintos
    where: dict[str, set[str]] = defaultdict(set)
    for run, rows in runs_with_rows:
        for r in rows:
            if r["category"] == CAT_HOST and r["mac"]:
                where[r["mac"]].add(f"{_sw_name(run)} {r['port']}")
    dup = {m: w for m, w in where.items() if len(w) > 1}
    if dup:
        out.append(Finding(
            "Media", "Topología", f"{len(dup)} MAC(s) vista(s) como host en más de un puerto",
            "; ".join(f"{m}: {', '.join(sorted(w))}" for m, w in list(dup.items())[:10]),
            "", "", "Puede ser un equipo que se movió entre ejecuciones, un switch no administrado "
                    "entre ambos puertos o un loop. Comparar ejecuciones y revisar físicamente."))

    # Inventario de hosts por fabricante (registro IEEE)
    host_macs = {r["mac"] for _, rows in runs_with_rows for r in rows
                 if r["category"] == CAT_HOST and r["mac"]}
    if host_macs:
        out.append(Finding(
            "Info", "Inventario", f"Hosts por fabricante ({len(host_macs)} hosts)",
            summarize_vendors(host_macs, limit=12) + ". Fabricante según el registro oficial "
            "del IEEE; «MAC local» = MAC aleatoria o virtual (sin fabricante).", "", ""))
    out = _merge_info(out)
    out.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.category, f.switch))
    return out


def _merge_info(findings: list[Finding]) -> list[Finding]:
    """Une los hallazgos informativos repetidos por switch en uno solo por tema."""
    groups: dict[str, list[Finding]] = defaultdict(list)
    rest = []
    for f in findings:
        if f.severity == "Info" and f.switch and f.category in ("Inventario", "Puertos", "Capacidad"):
            groups[f.category].append(f)
        else:
            rest.append(f)
    for cat, items in groups.items():
        if len(items) == 1:
            rest += items
            continue
        if cat == "Inventario":
            title = f"Equipos conectados directamente ({len(items)} switches)"
        elif cat == "Puertos":
            title = f"Puertos apagados administrativamente en {len(items)} switches"
        else:
            title = f"Capacidad disponible en {len(items)} switches"
        def part(f: Finding) -> str:
            if cat == "Puertos":
                return f.ports or f.detail
            return f.title if cat == "Capacidad" else f.detail
        detail = "; ".join(f"{f.switch}: {part(f)}" for f in items)
        rest.append(Finding("Info", cat, title, detail, "", "", items[0].recommendation))
    return rest


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] += 1
    return counts
