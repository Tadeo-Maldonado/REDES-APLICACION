"""Vista consolidada del proyecto y comparación entre ejecuciones."""
from __future__ import annotations

from .models import CAT_HOST, CAT_INFRA, CAT_UNMANAGED
from .storage import Storage
from .utils import short_hostname


def enrich_with_project_arp(storage: Storage,
                            runs_with_rows: list[tuple[dict, list[dict]]]) -> list[tuple[dict, list[dict]]]:
    """Resuelve IPs de hosts usando la ARP de TODOS los switches del conjunto.

    Un switch de acceso no tiene la ARP (el gateway está en el core): si el core también se
    recolectó, la IP del host se toma de ahí. Devuelve copias de las filas con 'ip_source'.
    """
    runs = [r for r, _ in runs_with_rows]
    names = {r["id"]: r.get("hostname") or r["switch_ip"] for r in runs}
    ip_by_mac: dict[str, tuple[str, str]] = {}
    for a in storage.get_arp([r["id"] for r in runs]):
        ip_by_mac.setdefault(a["mac"], (a["ip"], names.get(a["run_id"], "")))
    out = []
    for run, rows in runs_with_rows:
        new_rows = []
        for row in rows:
            row = dict(row)
            if row["category"] == CAT_HOST and row["mac"] and not row["ip"] and row["mac"] in ip_by_mac:
                ip, src = ip_by_mac[row["mac"]]
                row["ip"], row["ip_source"] = ip, f"ARP de {src}"
                row["method"] = f"{row['method']} · IP vía ARP de {src}"
            new_rows.append(row)
        out.append((run, new_rows))
    return out


def project_summary(storage: Storage, project_id: int) -> dict:
    """Acumulado del proyecto usando la última ejecución exitosa de cada switch."""
    runs = storage.latest_runs_per_switch(project_id)
    all_runs = storage.list_runs(project_id)
    host_macs, infra_links, vlans, svis = set(), set(), set(), set()
    totals = {"puertos_total": 0, "puertos_activos": 0, "puertos_inactivos": 0,
              "uplinks_no_admin": 0}
    for run in runs:
        for k in totals:
            totals[k] += run["summary"].get(k, 0)
        sw = short_hostname(run.get("hostname") or run["switch_ip"])
        for r in storage.get_port_rows(run["id"]):
            if r["category"] == CAT_HOST and r["mac"]:
                host_macs.add(r["mac"])
            elif r["category"] == CAT_INFRA:
                infra_links.add(tuple(sorted((sw, short_hostname(r["name"]) or r["mac"] or ""))))
        for v in storage.get_vlans(run["id"]):
            vlans.add(v["vlan_id"])
            if v["svi_ip"]:
                svis.add((sw, v["vlan_id"]))
    return {
        "ejecuciones": len(all_runs),
        "ejecuciones_ok": sum(1 for r in all_runs if r["status"] == "ok"),
        "switches_escaneados": len(runs),
        **totals,
        "hosts_unicos": len(host_macs),
        "enlaces_infra": len(infra_links),
        "vlans_unicas": len(vlans),
        "svis": len(svis),
    }


def _row_key(r: dict):
    if r["category"] == CAT_INFRA:
        return (r["port"], "infra", short_hostname(r["name"]) or r["mac"])
    if r["category"] == CAT_HOST:
        return (r["port"], "host", r["mac"])
    if r["category"] == CAT_UNMANAGED:
        return (r["port"], "unmanaged", "")
    return None


def diff_runs(rows_old: list[dict], rows_new: list[dict]) -> dict[str, list[dict]]:
    """Qué apareció, qué desapareció y qué puertos cambiaron de estado entre dos ejecuciones."""
    old = {k: r for r in rows_old if (k := _row_key(r))}
    new = {k: r for r in rows_new if (k := _row_key(r))}
    status_old = {r["port"]: r["status"] for r in rows_old}
    status_new = {r["port"]: r["status"] for r in rows_new}
    changed = [
        {"port": p, "antes": status_old[p], "ahora": status_new[p]}
        for p in sorted(set(status_old) & set(status_new)) if status_old[p] != status_new[p]
    ]
    moved = []
    old_host_ports = {r["mac"]: r["port"] for r in rows_old if r["category"] == CAT_HOST and r["mac"]}
    for r in rows_new:
        if r["category"] == CAT_HOST and r["mac"] in old_host_ports \
                and old_host_ports[r["mac"]] != r["port"]:
            moved.append({"mac": r["mac"], "ip": r["ip"], "antes": old_host_ports[r["mac"]],
                          "ahora": r["port"]})
    return {
        "nuevos": [new[k] for k in new.keys() - old.keys()],
        "desaparecidos": [old[k] for k in old.keys() - new.keys()],
        "cambios_estado": changed,
        "hosts_movidos": moved,
    }
