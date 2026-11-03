"""Diagnóstico de red: con qué IP sale la app, si el puerto SSH responde y qué contesta.

Útil cuando PuTTY sí llega al switch (p. ej. por VPN) pero la app no.
"""
from __future__ import annotations

import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from typing import Optional

AUTO = ""      # origen automático: lo decide la tabla de rutas del sistema


def local_interfaces() -> list[tuple[str, str]]:
    """[(nombre_de_tarjeta, ipv4)] de este equipo, sin loopback ni APIPA (169.254.x.x)."""
    out: list[tuple[str, str]] = []
    try:
        import psutil
        stats = psutil.net_if_stats()
        for name, addrs in psutil.net_if_addrs().items():
            if name in stats and not stats[name].isup:
                continue
            for a in addrs:
                if a.family == socket.AF_INET and _usable(a.address):
                    out.append((name, a.address))
    except Exception:
        # Sin psutil: al menos las IPs que resuelve el nombre del equipo
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
                ip = info[4][0]
                if _usable(ip) and ip not in [x[1] for x in out]:
                    out.append(("(tarjeta)", ip))
        except Exception:
            pass
    return sorted(out, key=lambda x: (x[0].lower(), x[1]))


def _usable(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_loopback or addr.is_link_local)


def route_source_ip(host: str, port: int = 22) -> Optional[str]:
    """IP local que el sistema usaría para llegar a `host` (no envía tráfico: es UDP sin datos)."""
    try:
        ipaddress.ip_address(host)          # solo IPs: evita esperas por DNS
    except ValueError:
        return None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((host, int(port or 22)))
            return s.getsockname()[0]
    except Exception:
        return None


def interface_of(ip: Optional[str]) -> str:
    for name, addr in local_interfaces():
        if addr == ip:
            return name
    return ""


def open_socket(host: str, port: int, timeout: float, source_ip: str = AUTO) -> socket.socket:
    """Conexión TCP, opcionalmente saliendo por una IP local concreta (tarjeta/VPN)."""
    src = (source_ip, 0) if source_ip else None
    return socket.create_connection((host, int(port)), timeout=timeout, source_address=src)


@dataclass
class ProbeResult:
    host: str
    port: int
    source_ip: str          # IP de origen usada
    source_iface: str       # tarjeta de red de esa IP
    tcp: str                # ok | timeout | rechazado | error
    ms: Optional[int]
    banner: str             # p. ej. "SSH-2.0-Cisco-1.25"
    diagnosis: str

    def to_dict(self) -> dict:
        return asdict(self)


def probe(host: str, port: int = 22, timeout: float = 5.0, source_ip: str = AUTO) -> ProbeResult:
    port = int(port or 22)
    src = source_ip or route_source_ip(host, port) or ""
    iface = interface_of(src)
    start = time.monotonic()
    banner, tcp, err = "", "error", ""
    try:
        with open_socket(host, port, timeout, source_ip) as s:
            tcp = "ok"
            ms = int((time.monotonic() - start) * 1000)
            s.settimeout(min(timeout, 4))
            try:
                banner = s.recv(256).decode("utf-8", "replace").strip().splitlines()[0]
            except Exception:
                banner = ""
    except socket.timeout:
        tcp, ms = "timeout", None
    except ConnectionRefusedError:
        tcp, ms = "rechazado", None
    except OSError as exc:
        tcp, ms, err = "error", None, str(exc)
    return ProbeResult(host, port, src, iface, tcp, ms, banner,
                       _diagnose(tcp, banner, src, source_ip, err, port))


def _diagnose(tcp: str, banner: str, src: str, forced: str, err: str, port: int) -> str:
    origin = f"desde {src}" if src else "sin ruta de origen"
    if tcp == "ok" and banner.startswith("SSH-"):
        return (f"✅ SSH responde {origin}. Si la recolección falla, el error de la ejecución dice "
                "la causa (credenciales, algoritmos SSH o prompt).")
    if tcp == "ok":
        return (f"⚠️ El puerto {port} abre {origin}, pero no contesta como SSH "
                f"({banner or 'sin banner'}). ¿Es Telnet u otro servicio?")
    if tcp == "rechazado":
        return f"❌ El switch rechaza el puerto {port} {origin}: SSH apagado o en otro puerto."
    if tcp == "error" and forced and ("10049" in err or "assign" in err.lower()):
        return f"❌ La IP de origen {forced} no existe en este equipo (¿la VPN se desconectó?)."
    if tcp == "error" and ("10051" in err or "unreachable" in err.lower()):
        return f"❌ No hay ruta hacia el switch {origin}: revisa que la VPN esté conectada."
    tips = ("Si con PuTTY sí entras: 1) en PuTTY revisa Connection › Proxy y el puerto de la "
            "sesión guardada; 2) si tu VPN hace split-tunnel por aplicación, agrega python.exe; "
            "3) elige como origen la IP de la tarjeta de la VPN.")
    return f"❌ Sin respuesta TCP {origin} ({err or 'timeout'}). {tips}"


def probe_many(targets: list[tuple[str, int]], timeout: float = 5.0,
               source_ip: str = AUTO) -> list[ProbeResult]:
    if not targets:
        return []
    with ThreadPoolExecutor(max_workers=min(16, len(targets))) as pool:
        return list(pool.map(lambda t: probe(t[0], t[1], timeout, source_ip), targets))
