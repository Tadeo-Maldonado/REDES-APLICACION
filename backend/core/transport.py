"""Cómo se obtiene el texto de un comando: por SSH real o desde archivos de muestra (demo)."""
from pathlib import Path

SAMPLES = Path(__file__).resolve().parent.parent / "drivers" / "samples"


class SampleTransport:
    """Modo demo: no se conecta a nada, lee drivers/samples/<vendor>_<comando>.txt"""

    def __init__(self, driver):
        self.driver = driver

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, key: str) -> str:
        path = SAMPLES / f"{self.driver.name}_{key}.txt"
        return path.read_text(encoding="utf-8")


class NetmikoTransport:
    """SSH real a un switch indicado. Las credenciales solo viven en memoria."""

    def __init__(self, driver, sw):
        if not (sw.host and sw.username and sw.password):
            raise ValueError("Faltan host, usuario o contraseña")
        self.driver = driver
        self.sw = sw
        self.conn = None

    def __enter__(self):
        from netmiko import ConnectHandler  # import tardío: el demo no lo necesita
        self.conn = ConnectHandler(
            device_type=self.driver.netmiko_type,
            host=self.sw.host,
            port=self.sw.port,
            username=self.sw.username,
            password=self.sw.password,
            conn_timeout=15,
        )
        return self

    def __exit__(self, *exc):
        if self.conn:
            self.conn.disconnect()
        return False

    def run(self, key: str) -> str:
        return self.conn.send_command(self.driver.commands[key], read_timeout=60)
