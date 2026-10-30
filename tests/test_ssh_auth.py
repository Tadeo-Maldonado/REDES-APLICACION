"""Conexión SSH real (servidor local de prueba) para los modos de acceso sin credenciales."""
import socket
import threading

import paramiko
import pytest

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
