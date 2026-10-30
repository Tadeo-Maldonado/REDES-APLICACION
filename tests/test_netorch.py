"""Pruebas con las salidas de ejemplo de netorch/demo_data (no requieren switches)."""
import pytest

from netorch.analysis import diff_runs, project_summary
from netorch.classifier import build_port_map
from netorch.engine import DemoSession, Target, run_collection
from netorch.models import (CAT_DOWN, CAT_HOST, CAT_INFRA, CAT_UNMANAGED, MacEntry, Neighbor,
                            ParsedData, Interface)
from netorch.storage import Storage
from netorch.topology import build_graph, render_html
from netorch.utils import (compact_vlan_list, expand_port_list, expand_vlan_list,
                           normalize_mac, normalize_port)

DEMOS = [("cisco_ios", "10.0.0.1"), ("aruba_aoss", "10.0.0.11"),
         ("aruba_aoscx", "10.0.0.12"), ("alcatel_aos", "10.0.0.13")]


@pytest.fixture
def db(tmp_path):
    return Storage(tmp_path / "test.db")


def demo_run(db, pid, platform, ip, custom=None):
    rid = run_collection(db, pid, Target(host=ip, platform=platform, username="t"),
                         custom or [], session_factory=DemoSession)
    run = db.get_run(rid)
    assert run["status"] == "ok", run["error"]
    return run, {r["port"]: [x for x in db.get_port_rows(rid) if x["port"] == r["port"]]
                 for r in db.get_port_rows(rid)}


# ------------------------------------------------------------------ utils ---
@pytest.mark.parametrize("raw", ["0011.2233.4455", "001122-334455", "00:11:22:33:44:55",
                                 "00-11-22-33-44-55", "00 11 22 33 44 55"])
def test_normalize_mac(raw):
    assert normalize_mac(raw) == "00:11:22:33:44:55"


def test_normalize_port():
    assert normalize_port("GigabitEthernet1/0/1") == "Gi1/0/1"
    assert normalize_port("TenGigabitEthernet1/1/1") == "Te1/1/1"
    assert normalize_port("Ethernet1/49") == "Eth1/49"
    assert normalize_port("Port-channel10") == "Po10"
    assert normalize_port("1/1/3") == "1/1/3"


def test_vlan_and_port_ranges():
    assert expand_vlan_list("1,10-12,20") == [1, 10, 11, 12, 20]
    assert expand_vlan_list("1-4094") == []          # no se expande, se muestra como texto
    assert compact_vlan_list([1, 10, 11, 12, 20]) == "1,10-12,20"
    assert expand_port_list("1-3,A1-A2,1/1/1-1/1/2") == ["1", "2", "3", "A1", "A2",
                                                         "1/1/1", "1/1/2"]


# ------------------------------------------------------------ por vendor ----
def test_cisco_core(db):
    pid = db.create_project("p")
    run, ports = demo_run(db, pid, "cisco_ios", "10.0.0.1", ["show version"])
    assert run["hostname"] == "SW-CORE-MTY"
    # PC directa: 1 MAC en puerto access + IP desde ARP
    pc = ports["Gi1/0/1"][0]
    assert (pc["category"], pc["mac"], pc["ip"]) == (CAT_HOST, "00:50:56:a1:00:01", "10.10.10.21")
    # Teléfono visto por CDP y LLDP (fusionado) + PC detrás del teléfono
    phone, pc2 = ports["Gi1/0/2"]
    assert phone["device_type"] == "Phone" and phone["method"] == "CDP+LLDP"
    assert pc2["category"] == CAT_HOST and pc2["ip"] == "10.10.10.22"
    # Hub: 5 MACs sin CDP/LLDP -> no se listan las IPs
    hub = ports["Gi1/0/4"][0]
    assert hub["category"] == CAT_UNMANAGED and hub["mac_count"] == 5 and hub["ip"] is None
    # Vecinos de infraestructura
    assert ports["Gi1/0/45"][0]["device_type"] == "Firewall"
    assert ports["Gi1/0/44"][0]["device_type"] == "Router"
    assert ports["Gi1/0/3"][0]["device_type"] == "AP"
    up = ports["Gi1/0/47"][0]
    assert up["device_type"] == "Switch" and up["vlan"] == "N:1 T:10,20,30"
    # Las MACs de los uplinks (ruido) no aparecen como hosts
    host_macs = {r["mac"] for rows in ports.values() for r in rows if r["category"] == CAT_HOST}
    assert "00:50:56:c3:00:01" not in host_macs
    assert ports["Gi1/0/6"][0]["category"] == CAT_DOWN
    s = run["summary"]
    assert (s["hosts"], s["vecinos_infra"], s["svis"], s["vlans"]) == (4, 7, 5, 7)
    raws = db.get_raw(run["id"])
    assert any(r["is_custom"] and r["command"] == "show version" for r in raws)


def test_aruba_aoss(db):
    run, ports = demo_run(db, db.create_project("p"), "aruba_aoss", "10.0.0.11")
    # Untagged 10 + voz tagged 20 se considera acceso
    assert ports["1"][0]["category"] == CAT_HOST
    assert ports["1"][0]["vlan"] == "10 (U) +T:20"
    assert ports["4"][0]["device_type"] == "AP"
    core = ports["49"][0]
    assert core["name"] == "SW-CORE-MTY" and core["ip"] == "10.0.0.1"
    assert ports["6"][0]["status"] == "disabled"


def test_aruba_cx(db):
    run, ports = demo_run(db, db.create_project("p"), "aruba_aoscx", "10.0.0.12")
    assert ports["1/1/3"][0]["device_type"] == "Phone"
    assert ports["1/1/52"][0]["vlan"] == "N:1 T:10,20,30"
    assert ports["1/1/48"][0]["category"] == "Activo sin MAC aprendida"


def test_alcatel_fallback_command(db):
    run, ports = demo_run(db, db.create_project("p"), "alcatel_aos", "10.0.0.13")
    raws = db.get_raw(run["id"])
    # AOS8 no tiene "show mac-address-table": se usa la alternativa "show mac-learning"
    assert [(r["command"], r["ok"]) for r in raws if r["key"] == "mac"] == [
        ("show mac-address-table", 0), ("show mac-learning", 1)]
    srv = ports["1/1/5"][0]
    assert srv["category"] == CAT_HOST and srv["mac"] == "00:11:22:33:44:55"
    assert ports["1/1/8"][0]["category"] == CAT_UNMANAGED
    assert ports["1/1/25"][0]["vlan"] == "N:1 T:10,20"


# --------------------------------------------------------- algoritmo -------
def test_filter_rules_minimal():
    data = ParsedData(
        interfaces={"Gi1/0/1": Interface("Gi1/0/1", "up", "access", 10),
                    "Gi1/0/2": Interface("Gi1/0/2", "up", "access", 10),
                    "Gi1/0/3": Interface("Gi1/0/3", "up", "trunk", 1, [10, 20])},
        macs=[MacEntry("00:00:00:00:00:01", "Gi1/0/1", 10)]
             + [MacEntry(f"00:00:00:00:01:{i:02x}", "Gi1/0/2", 10) for i in range(4)]
             + [MacEntry(f"00:00:00:00:02:{i:02x}", "Gi1/0/3", 10) for i in range(50)],
        neighbors=[Neighbor("GigabitEthernet1/0/3", "SW2.lab", "CDP", capabilities=["Switch"])],
    )
    rows = {r.port: r for r in build_port_map(data)}
    assert rows["Gi1/0/1"].category == CAT_HOST
    assert rows["Gi1/0/2"].category == CAT_UNMANAGED and rows["Gi1/0/2"].mac_count == 4
    assert rows["Gi1/0/3"].category == CAT_INFRA and rows["Gi1/0/3"].name == "SW2.lab"
    assert len(rows) == 3


# ------------------------------------------------------- proyecto / UI -----
def test_projects_are_isolated_and_consolidated(db):
    p1, p2 = db.create_project("Proyecto 1"), db.create_project("Proyecto 2")
    for plat, ip in DEMOS:
        demo_run(db, p1, plat, ip)
    demo_run(db, p2, "cisco_ios", "10.0.0.1")
    demo_run(db, p2, "cisco_ios", "10.0.0.1")
    assert len(db.list_runs(p1)) == 4 and len(db.list_runs(p2)) == 2
    assert len(db.latest_runs_per_switch(p2)) == 1         # mismo switch dos veces
    s = project_summary(db, p1)
    assert s["switches_escaneados"] == 4 and s["hosts_unicos"] == 12 and s["enlaces_infra"] == 9
    # Topología consolidada: el core y los 3 accesos quedan unidos (sin nodos duplicados)
    data = [(r, db.get_port_rows(r["id"])) for r in db.latest_runs_per_switch(p1)]
    g = build_graph(data)
    switches = [n for n in g.nodes.values() if n["kind"] == "Escaneado"]
    assert len(switches) == 4
    assert not any(nid.startswith("nb:sw-") for nid in g.nodes)
    html = render_html(g)
    assert "SW-CORE-MTY" in html and "<script" in html


def test_diff(db):
    pid = db.create_project("p")
    a, _ = demo_run(db, pid, "cisco_ios", "10.0.0.1")
    b, _ = demo_run(db, pid, "cisco_ios", "10.0.0.1")
    rows = db.get_port_rows(a["id"])
    changed = [dict(r) for r in db.get_port_rows(b["id"]) if r["port"] != "Gi1/0/1"]
    d = diff_runs(rows, changed)
    assert len(d["desaparecidos"]) == 1 and not d["nuevos"]


def test_device_names_are_escaped():
    from netorch.topology import Graph
    g = Graph()
    g.node("x", "<script>alert(1)</script>", "Switch", title="</script>")
    assert "<script>alert(1)" not in render_html(g)


# ---------------------------------------------- OS6860 / LAG / multi-switch --
def test_os6860_link_status_and_linkagg(db):
    run, ports = demo_run(db, db.create_project("p"), "alcatel_aos", "10.0.0.13")
    # 'show interfaces alias' da el estado real y AOS 8 pone las MACs del uplink en 0/1
    assert "0/1" not in ports                                  # absorbido por el uplink
    up = ports["1/1/25"][0]
    assert up["name"] == "SW-CORE-MTY" and up["mac_count"] == 3 and up["vlan"] == "N:1 T:10,20"
    assert ports["1/1/26"][0]["category"] == "Miembro de LAG / Port-channel"
    assert ports["1/1/4"][0]["status"] == "disabled"


def test_cisco_port_channel_absorbed():
    from netorch.parsers.cisco import parse_lags
    lags = parse_lags("1      Po1(SU)         LACP      Gi1/0/47(P)     Gi1/0/48(P)\n")
    assert lags == {"Po1": ["Gi1/0/47", "Gi1/0/48"]}
    data = ParsedData(
        lags=lags,
        neighbors=[Neighbor("Gi1/0/47", "SW-DIST", "LLDP", capabilities=["Switch"])],
        macs=[MacEntry(f"00:00:00:00:03:{i:02x}", "Po1", 10) for i in range(30)],
    )
    rows = {r.port: r for r in build_port_map(data)}
    assert "Po1" not in rows                      # las 30 MACs no se reportan como hub
    assert rows["Gi1/0/47"].category == CAT_INFRA and rows["Gi1/0/47"].mac_count == 30
    assert rows["Gi1/0/48"].category == "Miembro de LAG / Port-channel"


def test_run_many_parallel_isolates_failures(db):
    from netorch.engine import run_many
    pid = db.create_project("multi")
    targets = [Target(host=ip, platform=plat, username="t", name=f"SW{i + 1}")
               for i, (plat, ip) in enumerate(DEMOS)]
    targets.append(Target(host="10.9.9.9", platform="cisco_nxos", username="t", name="SW-SIN-DEMO"))
    seen = []
    ids = run_many(db, pid, targets, ["show version"], session_factory=DemoSession,
                   progress=lambda i, msg, frac: seen.append(i), max_workers=3)
    runs = [db.get_run(i) for i in ids]
    assert [r["status"] for r in runs] == ["ok"] * 4 + ["error"]   # uno falla, los demás siguen
    assert runs[4]["hostname"] == "SW-SIN-DEMO"
    assert set(seen) == set(range(5))
    assert len(db.latest_runs_per_switch(pid)) == 4
