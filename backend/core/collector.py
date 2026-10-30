"""Orquesta todo: transporte -> driver (parseo) -> unión MAC + LLDP -> clasificación."""
from concurrent.futures import ThreadPoolExecutor

from drivers import get_driver
from core.classifier import classify
from core.models import Connection
from core.oui import vendor_of
from core.transport import NetmikoTransport, SampleTransport
from core.utils import try_mac


def build_rows(switch: str, macs: list[dict], neighbors: list[dict]) -> list[Connection]:
    rows, neighbor_rows = [], {}
    neighbor_ports = {n["port"] for n in neighbors}

    for n in neighbors:                                # equipos vistos por LLDP
        mac = try_mac(n["chassis"]) or ""
        vendor = vendor_of(mac)
        row = Connection(
            switch=switch, port=n["port"], mac=mac, name=n["name"], description=n["description"],
            capabilities=n["capabilities"], vendor=vendor, neighbor=True,
            kind=classify(n["name"], n["description"], n["capabilities"], vendor))
        rows.append(row)
        neighbor_rows[(n["port"], mac)] = row

    for m in macs:                                     # el resto de la tabla MAC
        mac = try_mac(m["mac"])
        if not mac:
            continue
        existing = neighbor_rows.get((m["port"], mac))
        if existing:
            existing.vlan = m["vlan"]
            continue
        vendor = vendor_of(mac)
        rows.append(Connection(
            switch=switch, port=m["port"], mac=mac, vlan=m["vlan"], vendor=vendor,
            kind=classify(vendor=vendor), via_uplink=m["port"] in neighbor_ports))
    return rows


def collect_switch(sw) -> dict:
    try:
        driver = get_driver(sw.vendor)()
        transport = SampleTransport(driver) if sw.demo else NetmikoTransport(driver, sw)
        with transport as t:
            mac_text = t.run("mac_table")
            lldp_text = t.run("lldp")
        rows = build_rows(sw.name, driver.parse_mac_table(mac_text), driver.parse_lldp(lldp_text))
        return {"switch": sw.name, "ok": True, "error": None,
                "connections": [r.to_dict() for r in rows]}
    except Exception as e:
        return {"switch": sw.name, "ok": False, "error": f"{type(e).__name__}: {e}",
                "connections": []}


def collect_all(switches: list) -> list[dict]:
    with ThreadPoolExecutor(max_workers=8) as pool:
        return list(pool.map(collect_switch, switches))
