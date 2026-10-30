"""ALGORITMO DE FILTRADO: aísla las conexiones directas del switch y descarta el ruido.

Reglas, por puerto:
1. Si hay CDP/LLDP en el puerto -> "Vecino Directo de Infraestructura" y se identifica
   el tipo (Switch, Router, Firewall, Phone, AP...). Si el vecino es un IP Phone y queda
   exactamente una MAC adicional, esa MAC es la PC conectada detrás del teléfono.
2. Sin CDP/LLDP:
   - Exactamente 1 MAC aprendida -> "Dispositivo Final (Host)"; la IP se resuelve
     cruzando esa MAC con la tabla ARP del switch (si tiene la SVI/GW).
   - 2 o más MACs -> "Uplink No Administrado / Hub / Switch no compatible". NO se listan
     sus MACs/IPs (solo el conteo), para no saturar la vista.
   - 0 MACs -> activo sin MAC, trunk vacío o inactivo, según el estado del puerto.
Las MACs que el switch aprende en sus uplinks (cientos, de toda la red) nunca se
muestran como hosts: quedan absorbidas en la fila del vecino o del uplink.
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Optional

from .models import (CAT_DOWN, CAT_HOST, CAT_INFRA, CAT_ROUTED, CAT_TRUNK_EMPTY,
                     CAT_UNMANAGED, CAT_UP_NO_MAC, Interface, Neighbor, ParsedData, PortRow)
from .utils import compact_vlan_list, normalize_port, short_hostname

FW_REGEX = re.compile(r"\bpa-(?:\d|vm)|\basa\s?\d|adaptive security")
FW_KEYWORDS = ("fortigate", "fortinet", "palo alto", "pan-os", "firepower",
               "sophos", "checkpoint", "check point", "srx", "watchguard", "sonicwall", "meraki mx")
AP_KEYWORDS = ("air-", "access point", "aruba ap", "instant on", "unifi ap", "cisco ap",
               "catalyst 91", "ruckus")
PHONE_KEYWORDS = ("ip phone", "cp-", "polycom", "yealink", "avaya", "mitel")


def neighbor_type(n: Neighbor) -> str:
    """Tipo de equipo vecino a partir de capacidades + plataforma/descr."""
    text = f"{n.platform or ''} {n.name or ''}".lower()
    caps = set(n.capabilities)
    if any(k in text for k in FW_KEYWORDS) or FW_REGEX.search(text):
        return "Firewall"
    if "Phone" in caps or any(k in text for k in PHONE_KEYWORDS) \
            or (n.name or "").upper().startswith("SEP"):
        return "Phone"
    if "AP" in caps or any(k in text for k in AP_KEYWORDS):
        return "AP"
    if "Switch" in caps:
        return "Switch"
    if "Router" in caps:
        return "Router"
    if "Station" in caps:
        return "Servidor / Host (LLDP)"
    return "Otro (CDP/LLDP)"


def _vlan_text(iface: Optional[Interface]) -> str:
    if not iface:
        return ""
    if iface.mode == "routed":
        return "routed"
    if iface.mode == "trunk":
        tagged = compact_vlan_list(iface.tagged_vlans) or iface.allowed_raw or "all"
        native = f"N:{iface.access_vlan}" if iface.access_vlan is not None else "N:?"
        return f"{native} T:{tagged}"
    if iface.access_vlan is not None:
        extra = f" +T:{compact_vlan_list(iface.tagged_vlans)}" if iface.tagged_vlans else ""
        return f"{iface.access_vlan} (U){extra}"
    return ""


def _merge_neighbors(neighbors: list[Neighbor]) -> list[tuple[Neighbor, str]]:
    """Un mismo equipo puede verse por CDP y por LLDP en el mismo puerto: se fusiona."""
    merged: dict[tuple[str, str], tuple[Neighbor, set[str]]] = {}
    for n in neighbors:
        key = (n.local_port, short_hostname(n.name) or (n.chassis_mac or ""))
        if key in merged:
            base, protos = merged[key]
            protos.add(n.protocol)
            for attr in ("remote_port", "platform", "mgmt_ip", "chassis_mac"):
                if not getattr(base, attr) and getattr(n, attr):
                    setattr(base, attr, getattr(n, attr))
            base.capabilities = list(dict.fromkeys(base.capabilities + n.capabilities))
        else:
            merged[key] = (Neighbor(**{**n.__dict__, "capabilities": list(n.capabilities)}),
                           {n.protocol})
    return [(n, "+".join(sorted(p))) for n, p in merged.values()]


def _port_sort_key(port: str):
    return [int(t) if t.isdigit() else t.lower() for t in re.split(r"(\d+)", port)]


def build_port_map(data: ParsedData) -> list[PortRow]:
    # --- Índices ---------------------------------------------------------
    interfaces = {normalize_port(p): i for p, i in data.interfaces.items()}
    macs_by_port: dict[str, set[str]] = defaultdict(set)
    for e in data.macs:
        macs_by_port[normalize_port(e.port)].add(e.mac)
    neigh_by_port: dict[str, list[tuple[Neighbor, str]]] = defaultdict(list)
    for n, protos in _merge_neighbors(data.neighbors):
        neigh_by_port[normalize_port(n.local_port)].append((n, protos))
    ip_by_mac: dict[str, list[str]] = defaultdict(list)
    for a in data.arp:
        if a.ip not in ip_by_mac[a.mac]:
            ip_by_mac[a.mac].append(a.ip)

    def ip_for(mac: str) -> Optional[str]:
        ips = ip_by_mac.get(mac)
        return ", ".join(ips) if ips else None

    ports = set(interfaces) | set(macs_by_port) | set(neigh_by_port)
    rows: list[PortRow] = []

    for port in sorted(ports, key=_port_sort_key):
        if port.lower().startswith(("vlan", "lo", "mgmt", "tunnel", "nve")):
            continue
        iface = interfaces.get(port)
        macs = macs_by_port.get(port, set())
        status = iface.status if iface else ("up" if macs or port in neigh_by_port else "unknown")
        vlan = _vlan_text(iface)
        mode = iface.mode if iface else None

        # 1) Vecinos directos de infraestructura (CDP/LLDP)
        if port in neigh_by_port:
            known_macs: set[str] = set()
            single = len(neigh_by_port[port]) == 1
            for n, protos in neigh_by_port[port]:
                ntype = neighbor_type(n)
                mac = n.chassis_mac
                # Vecino sin MAC en el chassis-id (p. ej. anuncia una IP) y 1 sola MAC en el puerto
                if not mac and single and len(macs) == 1:
                    mac = next(iter(macs))
                if mac:
                    known_macs.add(mac)
                # Un servidor/PC que habla LLDP es un host final, no infraestructura
                category = CAT_HOST if ntype == "Servidor / Host (LLDP)" else CAT_INFRA
                rows.append(PortRow(
                    port=port, status=status if status != "unknown" else "up", vlan=vlan,
                    device_type=ntype, category=category, name=n.name,
                    mac=mac, ip=n.mgmt_ip or (ip_for(mac) if mac else None),
                    method=protos, mac_count=len(macs), remote_port=n.remote_port,
                    platform=n.platform,
                ))
            # PC detrás de un IP Phone: el teléfono + exactamente una MAC más
            types = {neighbor_type(n) for n, _ in neigh_by_port[port]}
            extra = macs - known_macs
            if types == {"Phone"} and len(extra) == 1:
                mac = next(iter(extra))
                rows.append(PortRow(
                    port=port, status=status, vlan=vlan, device_type="PC / Host",
                    category=CAT_HOST, mac=mac, ip=ip_for(mac),
                    method="Access MAC (detrás de IP Phone)", mac_count=len(macs),
                ))
            continue

        # 2) Sin protocolo de descubrimiento
        if mode == "routed":
            rows.append(PortRow(port=port, status=status, vlan=vlan, device_type="L3",
                                category=CAT_ROUTED, mac_count=len(macs)))
        elif len(macs) == 1:
            mac = next(iter(macs))
            method = "Access MAC" if mode != "trunk" else "MAC única (puerto trunk/tagged)"
            rows.append(PortRow(port=port, status=status, vlan=vlan, device_type="PC / Host",
                                category=CAT_HOST, mac=mac, ip=ip_for(mac), method=method,
                                mac_count=1))
        elif len(macs) > 1:
            rows.append(PortRow(port=port, status=status, vlan=vlan,
                                device_type="No administrado", category=CAT_UNMANAGED,
                                name=f"{len(macs)} MACs aprendidas", method="Conteo de MACs",
                                mac_count=len(macs)))
        elif status == "up":
            cat = CAT_TRUNK_EMPTY if mode == "trunk" else CAT_UP_NO_MAC
            rows.append(PortRow(port=port, status=status, vlan=vlan, device_type="-",
                                category=cat))
        else:
            rows.append(PortRow(port=port, status=status, vlan=vlan, device_type="-",
                                category=CAT_DOWN))
    return rows


def summarize(rows: list[PortRow], data: ParsedData) -> dict:
    """Métricas del switch para el Resumen Ejecutivo."""
    by_port: dict[str, str] = {}
    for r in rows:
        by_port.setdefault(r.port, r.status)
    infra = [r for r in rows if r.category == CAT_INFRA]
    count_type = lambda t: sum(1 for r in infra if r.device_type == t)
    return {
        "puertos_total": len(by_port),
        "puertos_activos": sum(1 for s in by_port.values() if s == "up"),
        "puertos_inactivos": sum(1 for s in by_port.values() if s in ("down", "disabled")),
        "vlans": len(data.vlans),
        "svis": sum(1 for v in data.vlans.values() if v.svi_ip),
        "hosts": sum(1 for r in rows if r.category == CAT_HOST),
        "vecinos_infra": len(infra),
        "switches": count_type("Switch"),
        "routers": count_type("Router"),
        "firewalls": count_type("Firewall"),
        "phones": count_type("Phone"),
        "aps": count_type("AP"),
        "uplinks_no_admin": sum(1 for r in rows if r.category == CAT_UNMANAGED),
        "macs_en_tabla": len(data.macs),
        "arp_en_tabla": len(data.arp),
    }
