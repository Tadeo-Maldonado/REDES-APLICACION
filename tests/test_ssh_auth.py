"""Conexión SSH real (servidor local de prueba) para los modos de acceso sin credenciales."""
import socket
import threading

import paramiko
import pytest

pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")

from netorch.engine import NetmikoSession, Target

PROMPT = b"SW-ABIERTO#"


class FakeSwitch(paramiko.ServerInterface):
    """allow: 'none' (no pide nada), 'empty' (contraseña vacía), 'password:<clave>'."""

    def __init__(self, allow: str):
        self.allow = allow

    def get_allowed_auths(self, username):
        return "none,password" if self.allow == "none" else "password"

    def check_auth_none(self, username):
        return paramiko.AUTH_SUCCESSFUL if self.allow == "none" else paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        if self.allow == "empty" and password == "":
            return paramiko.AUTH_SUCCESSFUL
        if self.allow.startswith("password:") and password == self.allow.split(":", 1)[1]:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_channel_pty_request(self, *args):
        return True

    def check_channel_shell_request(self, channel):
        threading.Thread(target=self._shell, args=(channel,), daemon=True).start()
        return True

    @staticmethod
    def _shell(chan):
        chan.send(b"\r\n" + PROMPT)
        buf = b""
        try:
            while True:
                data = chan.recv(1024)
                if not data:
                    break
                buf += data
                while b"\n" in buf or b"\r" in buf:
                    idx = min(i for i in (buf.find(b"\n"), buf.find(b"\r")) if i >= 0)
                    line, buf = buf[:idx].strip(), buf[idx + 1:].lstrip(b"\r\n")
                    out = b"Cisco IOS Software, Catalyst L3 Switch" if line == b"show version" else b""
                    chan.send(line + b"\r\n" + (out + b"\r\n" if out else b"") + PROMPT)
        except Exception:
            pass


def _serve(allow: str):
    host_key = paramiko.RSAKey.generate(1024)
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(5)

    def loop():
        while True:
            try:
                client, _ = sock.accept()
            except OSError:
                return
            t = paramiko.Transport(client)
            t.add_server_key(host_key)
            t.start_server(server=FakeSwitch(allow))

    threading.Thread(target=loop, daemon=True).start()
    return sock


@pytest.mark.parametrize("allow", ["none", "empty"])
def test_no_credentials_connects(allow):
    srv = _serve(allow)
    try:
        s = NetmikoSession(Target(host="127.0.0.1", port=srv.getsockname()[1],
                                  platform="cisco_ios", username="", no_user=True,
                                  no_password=True, timeout=10))
        assert s.hostname() == "SW-ABIERTO"
        assert "Catalyst" in s.send("show version")
        s.close()
    finally:
        srv.close()


def test_password_only_connects():
    srv = _serve("password:secreta")
    try:
        s = NetmikoSession(Target(host="127.0.0.1", port=srv.getsockname()[1],
                                  platform="cisco_ios", username="", password="secreta",
                                  no_user=True, timeout=10))
        assert s.hostname() == "SW-ABIERTO"
        s.close()
    finally:
        srv.close()


# ------------------------------------------------- IP de origen / diagnóstico --
def test_connect_from_chosen_source_ip():
    srv = _serve("password:x")
    try:
        port = srv.getsockname()[1]
        s = NetmikoSession(Target(host="127.0.0.1", port=port, platform="cisco_ios", username="u",
                                  password="x", source_ip="127.0.0.1", timeout=10))
        assert s.hostname() == "SW-ABIERTO"
        assert s.conn.remote_conn.get_transport().sock.getsockname()[0] == "127.0.0.1"
        s.close()
    finally:
        srv.close()


def test_probe_reports_ssh_banner_and_origin():
    from netorch.netdiag import probe
    srv = _serve("none")
    try:
        r = probe("127.0.0.1", srv.getsockname()[1], timeout=5)
        assert r.tcp == "ok" and r.banner.startswith("SSH-2.0") and r.source_ip == "127.0.0.1"
        assert r.diagnosis.startswith("✅")
    finally:
        srv.close()
    closed = probe("127.0.0.1", 1, timeout=2)
    assert closed.tcp == "rechazado" and "rechaza" in closed.diagnosis


def test_bad_source_ip_gives_clear_error(tmp_path):
    from netorch.engine import run_collection
    from netorch.storage import Storage
    from netorch.netdiag import probe
    r = probe("127.0.0.1", 22, timeout=2, source_ip="203.0.113.77")   # IP que no es de este equipo
    assert r.tcp == "error"
    db = Storage(tmp_path / "t.db")
    pid = db.create_project("p")
    rid = run_collection(db, pid, Target(host="127.0.0.1", port=22, platform="cisco_ios",
                                         username="u", password="x", source_ip="203.0.113.77",
                                         timeout=3))
    run = db.get_run(rid)
    assert run["status"] == "error" and "origen 203.0.113.77" in run["error"]


# --------------------------------------- SSH legacy (Cisco IOS clásico, SHA-1) --
def test_legacy_algorithms_registered_last():
    import netorch.engine  # noqa: F401  (activa la capa de compatibilidad)
    from paramiko.transport import Transport
    for k in ("diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1",
              "diffie-hellman-group-exchange-sha1"):
        assert k in Transport._kex_info and k in Transport._preferred_kex
    assert "ssh-rsa" in Transport._key_info
    assert not Transport._preferred_kex[0].endswith("sha1")        # lo moderno va primero


def test_incompatible_peer_message_is_not_called_timeout():
    from netmiko.exceptions import NetmikoTimeoutException
    from netorch.engine import _friendly_error
    msg = _friendly_error(NetmikoTimeoutException(
        "\nA paramiko SSHException occurred during connection creation:\n\n"
        "Incompatible ssh peer (no acceptable kex algorithm)\n"))
    assert "algoritmos" in msg and "Incompatible ssh peer" in msg and "Sin respuesta" not in msg
