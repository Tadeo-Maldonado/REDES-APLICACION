"""Persistencia 100 % local en SQLite (archivo data/netorch.db).

Esquema:
    projects      1 ── N  runs
    runs          1 ── N  raw_outputs   (salida cruda de cada comando, incl. Custom CLI)
    runs          1 ── N  port_rows     (Tabla Consolidada de Mapeo ya filtrada)
    runs          1 ── N  vlans         (VLANs y SVIs del switch)
Las contraseñas NUNCA se guardan.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional

from .models import PortRow, Vlan

DEFAULT_DB = Path(__file__).resolve().parent.parent / "data" / "netorch.db"

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS projects (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    description TEXT,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    switch_ip   TEXT NOT NULL,
    platform    TEXT NOT NULL,
    hostname    TEXT,
    username    TEXT,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    status      TEXT NOT NULL DEFAULT 'running',   -- running | ok | error
    error       TEXT,
    summary     TEXT,                              -- JSON con métricas
    warnings    TEXT,                              -- JSON lista
    notes       TEXT
);
CREATE INDEX IF NOT EXISTS idx_runs_project ON runs(project_id);

CREATE TABLE IF NOT EXISTS raw_outputs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    seq         INTEGER NOT NULL,
    key         TEXT,                              -- clave lógica (mac, arp...) o 'custom'
    command     TEXT NOT NULL,
    output      TEXT,
    is_custom   INTEGER NOT NULL DEFAULT 0,
    ok          INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_raw_run ON raw_outputs(run_id);

CREATE TABLE IF NOT EXISTS port_rows (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    port        TEXT NOT NULL,
    status      TEXT,
    vlan        TEXT,
    device_type TEXT,
    category    TEXT,
    name        TEXT,
    mac         TEXT,
    ip          TEXT,
    method      TEXT,
    mac_count   INTEGER,
    remote_port TEXT,
    platform    TEXT
);
CREATE INDEX IF NOT EXISTS idx_ports_run ON port_rows(run_id);
CREATE INDEX IF NOT EXISTS idx_ports_mac ON port_rows(mac);

CREATE TABLE IF NOT EXISTS arp_entries (          -- ARP completa: permite resolver IPs entre switches
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    ip          TEXT NOT NULL,
    mac         TEXT NOT NULL,
    interface   TEXT
);
CREATE INDEX IF NOT EXISTS idx_arp_run ON arp_entries(run_id);

CREATE TABLE IF NOT EXISTS vlans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    vlan_id     INTEGER NOT NULL,
    name        TEXT,
    svi_ip      TEXT
);
"""


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


class Storage:
    def __init__(self, path: Path | str = DEFAULT_DB):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.conn() as c:
            c.execute("PRAGMA journal_mode = WAL")   # lecturas y escrituras concurrentes
            c.executescript(SCHEMA)
            # Migraciones de bases creadas con versiones anteriores
            cols = {r[1] for r in c.execute("PRAGMA table_info(port_rows)")}
            if "mac_list" not in cols:
                c.execute("ALTER TABLE port_rows ADD COLUMN mac_list TEXT")

    @contextmanager
    def conn(self) -> Iterator[sqlite3.Connection]:
        # timeout: varios switches pueden guardar resultados al mismo tiempo
        c = sqlite3.connect(self.path, timeout=30)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys = ON")
        try:
            yield c
            c.commit()
        finally:
            c.close()

    # ---------------------------------------------------------- proyectos ---
    def create_project(self, name: str, description: str = "") -> int:
        with self.conn() as c:
            cur = c.execute("INSERT INTO projects(name, description, created_at) VALUES (?,?,?)",
                            (name.strip(), description.strip(), _now()))
            return cur.lastrowid

    def list_projects(self) -> list[dict]:
        with self.conn() as c:
            rows = c.execute("""
                SELECT p.*, COUNT(r.id) AS runs
                FROM projects p LEFT JOIN runs r ON r.project_id = p.id
                GROUP BY p.id ORDER BY p.created_at DESC""").fetchall()
            return [dict(r) for r in rows]

    def delete_project(self, project_id: int) -> None:
        with self.conn() as c:
            c.execute("DELETE FROM projects WHERE id = ?", (project_id,))

    # ------------------------------------------------------------ runs -----
    def start_run(self, project_id: int, switch_ip: str, platform: str,
                  username: Optional[str] = None, notes: str = "") -> int:
        with self.conn() as c:
            cur = c.execute("""INSERT INTO runs(project_id, switch_ip, platform, username,
                               started_at, status, notes) VALUES (?,?,?,?,?, 'running', ?)""",
                            (project_id, switch_ip, platform, username, _now(), notes))
            return cur.lastrowid

    def add_raw(self, run_id: int, seq: int, key: str, command: str, output: str,
                is_custom: bool = False, ok: bool = True) -> None:
        with self.conn() as c:
            c.execute("""INSERT INTO raw_outputs(run_id, seq, key, command, output, is_custom, ok)
                         VALUES (?,?,?,?,?,?,?)""",
                      (run_id, seq, key, command, output, int(is_custom), int(ok)))

    def finish_run(self, run_id: int, *, status: str, hostname: Optional[str] = None,
                   rows: Optional[list[PortRow]] = None, vlans: Optional[list[Vlan]] = None,
                   summary: Optional[dict] = None, warnings: Optional[list[str]] = None,
                   error: Optional[str] = None, arp: Optional[list] = None) -> None:
        with self.conn() as c:
            c.execute("""UPDATE runs SET status=?, hostname=COALESCE(?, hostname), finished_at=?,
                         summary=?, warnings=?, error=? WHERE id=?""",
                      (status, hostname, _now(), json.dumps(summary or {}),
                       json.dumps(warnings or []), error, run_id))
            for r in rows or []:
                c.execute("""INSERT INTO port_rows(run_id, port, status, vlan, device_type, category,
                             name, mac, ip, method, mac_count, remote_port, platform, mac_list)
                             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                          (run_id, r.port, r.status, r.vlan, r.device_type, r.category, r.name,
                           r.mac, r.ip, r.method, r.mac_count, r.remote_port, r.platform,
                           r.mac_list))
            for v in vlans or []:
                c.execute("INSERT INTO vlans(run_id, vlan_id, name, svi_ip) VALUES (?,?,?,?)",
                          (run_id, v.vlan_id, v.name, v.svi_ip))
            c.executemany("INSERT INTO arp_entries(run_id, ip, mac, interface) VALUES (?,?,?,?)",
                          [(run_id, a.ip, a.mac, a.interface) for a in arp or []])

    def list_runs(self, project_id: int) -> list[dict]:
        with self.conn() as c:
            rows = c.execute("SELECT * FROM runs WHERE project_id=? ORDER BY started_at DESC, id DESC",
                             (project_id,)).fetchall()
        return [self._run_dict(r) for r in rows]

    def get_run(self, run_id: int) -> Optional[dict]:
        with self.conn() as c:
            r = c.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        return self._run_dict(r) if r else None

    def delete_run(self, run_id: int) -> None:
        with self.conn() as c:
            c.execute("DELETE FROM runs WHERE id=?", (run_id,))

    @staticmethod
    def _run_dict(r: sqlite3.Row) -> dict:
        d = dict(r)
        d["summary"] = json.loads(d["summary"]) if d.get("summary") else {}
        d["warnings"] = json.loads(d["warnings"]) if d.get("warnings") else []
        return d

    def get_raw(self, run_id: int) -> list[dict]:
        with self.conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM raw_outputs WHERE run_id=? ORDER BY seq", (run_id,))]

    def get_port_rows(self, run_id: int) -> list[dict]:
        with self.conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM port_rows WHERE run_id=? ORDER BY id", (run_id,))]

    def get_vlans(self, run_id: int) -> list[dict]:
        with self.conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM vlans WHERE run_id=? ORDER BY vlan_id", (run_id,))]

    def get_arp(self, run_ids: list[int]) -> list[dict]:
        if not run_ids:
            return []
        marks = ",".join("?" * len(run_ids))
        with self.conn() as c:
            return [dict(r) for r in c.execute(
                f"SELECT * FROM arp_entries WHERE run_id IN ({marks})", run_ids)]

    def latest_runs_per_switch(self, project_id: int) -> list[dict]:
        """La ejecución exitosa más reciente de cada switch del proyecto (vista consolidada)."""
        latest: dict[str, dict] = {}
        for run in self.list_runs(project_id):          # ya vienen de más nueva a más vieja
            if run["status"] != "ok":
                continue
            key = (run.get("hostname") or run["switch_ip"]).lower()
            latest.setdefault(key, run)
        return list(latest.values())
