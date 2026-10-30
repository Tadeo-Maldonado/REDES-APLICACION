"""Motor de recolección: SSH a UN switch (sin escaneos), comandos, parseo, filtrado y guardado."""
from __future__ import annotations

import logging
import re
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
    no_user: bool = False         # el equipo pide solo contraseña (sin usuario)
    no_password: bool = False     # el equipo no pide nada (sin usuario ni contraseña)

    @property
    def label(self) -> str:
        return self.name or self.host


class Session(Protocol):
    def send(self, command: str, slow: bool = False) -> str: ...
    def hostname(self) -> Optional[str]: ...
    def close(self) -> None: ...


# Comandos que pueden tardar en equipos grandes (miles de MACs/ARP)
SLOW_KEYS = ("mac", "arp", "neighbors_cdp", "neighbors_lldp", "port_config")
NO_USER_FALLBACK = "netorch"      # algunos servidores SSH no aceptan un usuario vacío


def _no_auth_client_class():
    """SSHClient de Paramiko que primero intenta la autenticación 'none' (equipos abiertos)."""
    import paramiko

    class NoAuthSSHClient(paramiko.SSHClient):
        def _auth(self, username, password, *args, **kwargs):
            try:
                self._transport.auth_none(username or "")
                if self._transport.is_authenticated():
                    return
            except paramiko.BadAuthenticationType:
                pass                      # el servidor no permite 'none': se prueba vacío
            except paramiko.AuthenticationException:
                pass
            return super()._auth(username, password or "", *args, **kwargs)

    return NoAuthSSHClient


class ConnectionLost(Exception):
    """La sesión SSH se cayó a mitad de la recolección."""


class NetmikoSession:
    """Sesión SSH real con Netmiko."""

    def __init__(self, target: Target):
        from netmiko import ConnectHandler
        from netmiko.exceptions import NetmikoAuthenticationException

        platform = PLATFORMS[target.platform]
        params = {
            "device_type": platform.netmiko_type,
            "host": target.host,
            "port": int(target.port or 22),
            "username": "" if target.no_user else (target.username or ""),
            "password": target.password or "",
            "secret": target.secret or "",
            "timeout": target.timeout,
            "conn_timeout": target.timeout,
            "auth_timeout": max(target.timeout, 15),
            "banner_timeout": max(target.timeout, 15),
            "fast_cli": False,
        }
        if target.key_file:
            params.update(use_keys=True, key_file=target.key_file, allow_agent=False,
                          passphrase=target.key_passphrase or None)
        self.warnings: list[str] = []
        if target.no_password and not target.key_file:
            params.update(username="", password="")
        try:
            self.conn = self._connect(ConnectHandler, params, target.no_password)
        except NetmikoAuthenticationException:
            # Equipos con solo contraseña: el usuario se ignora, pero hay servidores SSH que
            # rechazan el usuario vacío. Se reintenta una vez con un usuario genérico.
            if not target.no_user:
                raise
            params["username"] = NO_USER_FALLBACK
            self.conn = self._connect(ConnectHandler, params, target.no_password)
            self.warnings.append("El equipo no aceptó usuario vacío; se conectó con un usuario "
                                 "genérico y solo la contraseña.")
        if target.secret:
            try:
                self.conn.enable()
            except Exception as exc:          # no todos los equipos tienen modo enable
                self.warnings.append(f"No se pudo entrar a modo enable: {exc}")
        try:
            if platform.vendor == "cisco" and self.conn.find_prompt().strip().endswith(">"):
                self.warnings.append("La sesión quedó en modo usuario (>): algunos comandos pueden "
                                     "fallar. Agrega el enable password si el equipo lo usa.")
        except Exception:
            pass

    @staticmethod
    def _connect(handler, params: dict, no_auth: bool):
        if not no_auth:
            return handler(**params)
        # Sin credenciales: se crea la conexión sin abrirla, se cambia el cliente SSH por uno
        # que intenta auth 'none' (y luego contraseña vacía), y entonces se abre.
        conn = handler(**params, auto_connect=False)
        client_cls = _no_auth_client_class()
        conn._get_ssh_client_instance = lambda: client_cls()
        conn._open()
        return conn

    def send(self, command: str, slow: bool = False) -> str:
        return self.conn.send_command(command, read_timeout=420 if slow else 180)

    def hostname(self) -> Optional[str]:
        try:
            prompt = self.conn.find_prompt()
        except Exception:
            return None
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
        self.dir = DEMO_DIR / PLATFORMS[target.platform].demo_dir
        self.warnings: list[str] = []
        if not self.dir.exists():
            raise ValueError(f"No hay datos demo para la plataforma {target.platform}")

    def send(self, command: str, slow: bool = False) -> str:
        f = self.dir / demo_filename(command)
        if f.exists():
            return f.read_text(encoding="utf-8")
        return f"% Invalid input detected at '^' marker. ({command})"

    def hostname(self) -> Optional[str]:
        f = self.dir / "hostname.txt"
        return f.read_text(encoding="utf-8").strip() if f.exists() else None

    def close(self) -> None:
        pass


def _is_connection_lost(exc: Exception) -> bool:
    text = f"{type(exc).__name__} {exc}".lower()
    return any(k in text for k in ("socket is closed", "eoferror", "connection reset",
                                   "broken pipe", "not connected", "connection closed",
                                   "socket closed", "channel closed"))


def _friendly_error(exc: Exception) -> str:
    name = type(exc).__name__
    if isinstance(exc, ConnectionLost):
        return f"La conexión SSH se cayó antes de obtener datos: {exc}"
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

        def run_cmd(key: str, cmd: str, is_custom: bool = False) -> Optional[str]:
            """Ejecuta un comando; un error en uno no detiene los demás."""
            nonlocal seq
            seq += 1
            try:
                out = session.send(cmd, slow=key in SLOW_KEYS)
            except Exception as exc:          # noqa: BLE001
                if _is_connection_lost(exc):
                    storage.add_raw(run_id, seq, key, cmd, f"ERROR: conexión perdida ({exc})",
                                    is_custom=is_custom, ok=False)
                    raise ConnectionLost(str(exc)) from exc
                storage.add_raw(run_id, seq, key, cmd, f"ERROR: {type(exc).__name__}: {exc}",
                                is_custom=is_custom, ok=False)
                warnings.append(f"«{cmd}» no respondió a tiempo o falló ({type(exc).__name__}).")
                return None
            out = out if isinstance(out, str) else str(out or "")
            ok = not looks_like_error(out)
            storage.add_raw(run_id, seq, key, cmd, out, is_custom=is_custom, ok=ok)
            return out if ok else None

        try:
            for i, key in enumerate(steps):
                for alt in platform.commands[key]:
                    progress(f"Ejecutando: {alt}", 0.05 + 0.85 * i / total)
                    out = run_cmd(key, alt)
                    if out is not None:
                        outputs[key] = out
                        break
                else:
                    warnings.append(f"Ningún comando funcionó para '{key}' "
                                    f"({' / '.join(platform.commands[key])}).")

            # Aruba AOS-S: detalle por VLAN para saber qué puertos son tagged/untagged
            if "vlan_detail" in platform.commands and outputs.get("vlans"):
                try:
                    vids = sorted(parse_vlans_aoss(outputs["vlans"]))[:MAX_VLAN_DETAIL]
                except Exception:
                    vids = []
                for vid in vids:
                    cmd = platform.commands["vlan_detail"][0].format(vlan=vid)
                    progress(f"Ejecutando: {cmd}", 0.6)
                    out = run_cmd(f"vlan_detail:{vid}", cmd)
                    if out is not None:
                        outputs[f"vlan_detail:{vid}"] = out

            for j, cmd in enumerate(custom_commands):
                progress(f"Custom CLI: {cmd}", 0.05 + 0.85 * (len(steps) + j) / total)
                run_cmd("custom", cmd, is_custom=True)
        except ConnectionLost as exc:
            # Se guarda lo que alcanzó a recolectarse en vez de perder toda la ejecución
            warnings.append(f"La conexión se cayó a mitad de la recolección ({exc}); el resultado "
                            "es parcial.")
            if not outputs:
                raise

        progress("Interpretando salidas y filtrando conexiones directas…", 0.93)
        data = parse_outputs(target.platform, outputs)
        rows = build_port_map(data)
        summary = summarize(rows, data)
        warnings += data.warnings
        if not data.neighbors:
            warnings.append("No se detectaron vecinos CDP/LLDP (¿protocolo deshabilitado?).")
        storage.finish_run(run_id, status="ok", hostname=hostname, rows=rows,
                           vlans=list(data.vlans.values()), summary=summary, warnings=warnings,
                           arp=data.arp)
        progress("Listo.", 1.0)
    except Exception as exc:
        # Fallas esperadas (switch apagado, credenciales, timeout): una línea en la terminal,
        # sin traceback que asuste. Las inesperadas sí muestran el detalle completo.
        expected = any(k in type(exc).__name__ for k in ("Timeout", "Authentication",
                                                          "NoValidConnections", "ConnectionLost"))
        if expected:
            log.warning("%s (%s): %s", target.label, target.host, _friendly_error(exc))
        else:
            log.exception("Fallo en la ejecución %s", run_id)
        try:
            storage.finish_run(run_id, status="error", hostname=hostname or target.name,
                               error=_friendly_error(exc),
                               warnings=[f"Detalle técnico: {type(exc).__name__}: {exc}"])
        except Exception:
            log.exception("No se pudo registrar el error de la ejecución %s", run_id)
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
    Devuelve los ids de ejecución en el mismo orden que `targets` (si un switch tuvo un fallo
    tan grave que ni siquiera se pudo registrar, se omite).
    """
    from concurrent.futures import ThreadPoolExecutor

    progress = progress or (lambda i, msg, frac: None)
    results: list[int] = [0] * len(targets)

    def safe_progress(i: int, msg: str, frac: float) -> None:
        try:
            progress(i, msg, frac)
        except Exception:                     # la UI nunca debe tumbar la recolección
            pass

    def work(i: int, t: Target) -> None:
        try:
            results[i] = run_collection(storage, project_id, t, custom_commands,
                                        progress=lambda msg, frac: safe_progress(i, msg, frac),
                                        session_factory=session_factory, notes=notes)
            run = storage.get_run(results[i])
            safe_progress(i, "✅ Listo" if run["status"] == "ok" else f"❌ {run['error']}", 1.0)
        except Exception as exc:              # p. ej. base de datos bloqueada
            log.exception("Fallo inesperado con %s", t.host)
            safe_progress(i, f"❌ Error inesperado: {exc}", 1.0)

    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(targets)))) as pool:
        futures = [pool.submit(work, i, t) for i, t in enumerate(targets)]
        for f in futures:
            f.result()
    return [r for r in results if r]
