"""Motor de recolección: SSH a UN switch (sin escaneos), comandos, parseo, filtrado y guardado."""
from __future__ import annotations

import logging
import re
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Protocol

from .classifier import build_port_map, summarize
from .commands import PLATFORMS
from .parsers import parse_outputs
from .parsers.aruba import parse_vlans_aoss
from .storage import Storage
from .utils import looks_like_error

log = logging.getLogger(__name__)
MAX_VLAN_DETAIL = 128          # tope de "show vlans <id>" en AOS-S
DEMO_DIR = Path(__file__).resolve().parent / "demo_data"

ProgressFn = Callable[[str, float], None]


@dataclass
class Target:
    host: str
    platform: str
    username: str
    password: str = ""
    secret: str = ""              # enable password (si aplica)
    port: int = 22
    key_file: Optional[str] = None
    key_passphrase: Optional[str] = None
    timeout: int = 20
    name: Optional[str] = None    # nombre que le da el usuario (SW1, Core MTY...)

    @property
    def label(self) -> str:
        return self.name or self.host


class Session(Protocol):
    def send(self, command: str) -> str: ...
    def hostname(self) -> Optional[str]: ...
    def close(self) -> None: ...


class NetmikoSession:
    """Sesión SSH real con Netmiko."""

    def __init__(self, target: Target):
        from netmiko import ConnectHandler

        platform = PLATFORMS[target.platform]
        params = {
            "device_type": platform.netmiko_type,
            "host": target.host,
            "port": int(target.port or 22),
            "username": target.username,
            "password": target.password or "",
            "secret": target.secret or "",
            "timeout": target.timeout,
            "conn_timeout": target.timeout,
            "fast_cli": False,
        }
        if target.key_file:
            params.update(use_keys=True, key_file=target.key_file, allow_agent=False,
                          passphrase=target.key_passphrase or None)
        self.conn = ConnectHandler(**params)
        self.warnings: list[str] = []
        if target.secret:
            try:
                self.conn.enable()
            except Exception as exc:          # no todos los equipos tienen modo enable
                self.warnings.append(f"No se pudo entrar a modo enable: {exc}")

    def send(self, command: str) -> str:
        return self.conn.send_command(command, read_timeout=180)

    def hostname(self) -> Optional[str]:
        prompt = self.conn.find_prompt()
        name = re.sub(r"[#>\s]+$", "", prompt.strip()).strip()
        name = re.sub(r"\(.*\)$", "", name)        # quita "(config)" o "(su)"
        return name if name and name not in ("->", "-") else None

    def close(self) -> None:
        try:
            self.conn.disconnect()
        except Exception:
            pass


def demo_filename(command: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "_", command.strip()).strip("_") + ".txt"


class DemoSession:
    """Sesión simulada: responde con salidas de ejemplo guardadas en demo_data/<plataforma>/."""

    def __init__(self, target: Target):
        self.dir = DEMO_DIR / target.platform
        self.warnings: list[str] = []
        if not self.dir.exists():
            raise ValueError(f"No hay datos demo para la plataforma {target.platform}")

    def send(self, command: str) -> str:
        f = self.dir / demo_filename(command)
        if f.exists():
            return f.read_text(encoding="utf-8")
        return f"% Invalid input detected at '^' marker. ({command})"

    def hostname(self) -> Optional[str]:
        f = self.dir / "hostname.txt"
        return f.read_text(encoding="utf-8").strip() if f.exists() else None

    def close(self) -> None:
        pass


def _friendly_error(exc: Exception) -> str:
    name = type(exc).__name__
    if "Authentication" in name:
        return "Autenticación SSH fallida: revisa usuario, contraseña o llave."
    if "Timeout" in name or "timed out" in str(exc).lower():
        return "Sin respuesta SSH (timeout): revisa IP, puerto, ACLs o firewall intermedio."
    if "NoValidConnections" in name or "refused" in str(exc).lower():
        return "Conexión rechazada: el puerto SSH no está abierto en el equipo."
    return f"{name}: {exc}"


def run_collection(storage: Storage, project_id: int, target: Target,
                   custom_commands: Optional[list[str]] = None,
                   progress: Optional[ProgressFn] = None,
                   session_factory: Callable[[Target], Session] = NetmikoSession,
                   notes: str = "") -> int:
    """Ejecuta una recolección completa y la guarda en el proyecto. Devuelve el id de ejecución."""
    progress = progress or (lambda msg, frac: None)
    platform = PLATFORMS[target.platform]
    custom_commands = [c.strip() for c in (custom_commands or []) if c.strip()]
    run_id = storage.start_run(project_id, target.host, target.platform, target.username, notes)
    seq = 0
    session: Optional[Session] = None
    hostname = None
    try:
        progress(f"Conectando por SSH a {target.host}:{target.port}…", 0.02)
        session = session_factory(target)
        hostname = session.hostname() or target.name
        warnings = list(getattr(session, "warnings", []))
        outputs: dict[str, str] = {}

        steps = [k for k in platform.commands if k != "vlan_detail"]
        total = len(steps) + len(custom_commands) + 1
        for i, key in enumerate(steps):
            for alt in platform.commands[key]:
                progress(f"Ejecutando: {alt}", 0.05 + 0.85 * i / total)
                out = session.send(alt)
                ok = not looks_like_error(out)
                seq += 1
                storage.add_raw(run_id, seq, key, alt, out, ok=ok)
                if ok:
                    outputs[key] = out
                    break
            else:
                warnings.append(f"Ningún comando funcionó para '{key}' "
                                f"({' / '.join(platform.commands[key])}).")

        # Aruba AOS-S: detalle por VLAN para saber qué puertos son tagged/untagged
        if "vlan_detail" in platform.commands and outputs.get("vlans"):
            vids = sorted(parse_vlans_aoss(outputs["vlans"]))[:MAX_VLAN_DETAIL]
            for vid in vids:
                cmd = platform.commands["vlan_detail"][0].format(vlan=vid)
                progress(f"Ejecutando: {cmd}", 0.6)
                out = session.send(cmd)
                seq += 1
                storage.add_raw(run_id, seq, f"vlan_detail:{vid}", cmd, out,
                                ok=not looks_like_error(out))
                outputs[f"vlan_detail:{vid}"] = out

        for j, cmd in enumerate(custom_commands):
            progress(f"Custom CLI: {cmd}", 0.05 + 0.85 * (len(steps) + j) / total)
            out = session.send(cmd)
            seq += 1
            storage.add_raw(run_id, seq, "custom", cmd, out, is_custom=True,
                            ok=not looks_like_error(out))

        progress("Interpretando salidas y filtrando conexiones directas…", 0.93)
        data = parse_outputs(target.platform, outputs)
        rows = build_port_map(data)
        summary = summarize(rows, data)
        warnings += data.warnings
        if not data.neighbors:
            warnings.append("No se detectaron vecinos CDP/LLDP (¿protocolo deshabilitado?).")
        storage.finish_run(run_id, status="ok", hostname=hostname, rows=rows,
                           vlans=list(data.vlans.values()), summary=summary, warnings=warnings)
        progress("Listo.", 1.0)
    except Exception as exc:
        log.exception("Fallo en la ejecución %s", run_id)
        storage.finish_run(run_id, status="error", hostname=hostname or target.name,
                           error=_friendly_error(exc),
                           warnings=[traceback.format_exc(limit=3)])
    finally:
        if session:
            session.close()
    return run_id


def run_many(storage: Storage, project_id: int, targets: list[Target],
             custom_commands: Optional[list[str]] = None,
             progress: Optional[Callable[[int, str, float], None]] = None,
             session_factory: Callable[[Target], Session] = NetmikoSession,
             max_workers: int = 4, notes: str = "") -> list[int]:
    """Ejecuta la recolección en varios switches en paralelo (una sesión SSH por switch).

    progress(i, mensaje, fracción) se llama desde hilos de trabajo; i = índice del switch.
    Devuelve los ids de ejecución en el mismo orden que `targets`.
    """
    from concurrent.futures import ThreadPoolExecutor

    progress = progress or (lambda i, msg, frac: None)
    results: list[int] = [0] * len(targets)

    def work(i: int, t: Target) -> None:
        results[i] = run_collection(storage, project_id, t, custom_commands,
                                    progress=lambda msg, frac: progress(i, msg, frac),
                                    session_factory=session_factory, notes=notes)
        run = storage.get_run(results[i])
        progress(i, "✅ Listo" if run["status"] == "ok" else f"❌ {run['error']}", 1.0)

    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(targets)))) as pool:
        futures = [pool.submit(work, i, t) for i, t in enumerate(targets)]
        for f in futures:
            f.result()
    return results
