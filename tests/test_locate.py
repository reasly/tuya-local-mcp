import pytest

from tuya_local_mcp import devices
from tuya_local_mcp.devices import DeviceError, locate, prime_addresses
from tuya_local_mcp.registry import DeviceRecord, clear_runtime_ips


def _record(**overrides) -> DeviceRecord:
    fields = dict(
        device_id="bf4444444444444444dddd",
        name="Hall heater",
        local_key="0123456789abcdef",
        mac="00:33:7a:aa:bb:a9",
    )
    fields.update(overrides)
    return DeviceRecord(**fields)


@pytest.fixture(autouse=True)
def _isolated_caches():
    devices._LOCATED.clear()
    devices._BEACONS = None
    clear_runtime_ips()
    yield
    devices._LOCATED.clear()
    devices._BEACONS = None
    clear_runtime_ips()


def test_stored_ip_wins_without_touching_the_network(monkeypatch):
    def fail(*_a, **_k):
        raise AssertionError("network lookup should not run")

    monkeypatch.setattr(devices.neighbors, "ip_for_mac", fail)
    monkeypatch.setattr(devices, "passive_scan", fail)
    assert locate(_record(ip="192.168.20.50"), timeout=1) == "192.168.20.50"


def test_mac_hit_in_the_neighbor_table_skips_probe_and_beacons(monkeypatch):
    monkeypatch.setattr(devices.neighbors, "ip_for_mac", lambda *_a, **_k: "192.168.20.149")

    def fail(*_a, **_k):
        raise AssertionError("should not probe or listen")

    monkeypatch.setattr(devices.neighbors, "probe_if_needed", fail)
    monkeypatch.setattr(devices, "passive_scan", fail)

    record = _record()
    assert locate(record, timeout=5) == "192.168.20.149"
    assert record.public()["ip"] == "192.168.20.149"
    assert record.ip is None


def test_missing_neighbor_entry_probes_once_then_uses_the_table(monkeypatch):
    calls = {"probes": 0, "lookups": 0}

    def lookup(_mac, table=None):
        calls["lookups"] += 1
        if calls["lookups"] == 1:
            return None
        return "192.168.20.108"

    def probe():
        calls["probes"] += 1

    monkeypatch.setattr(devices.neighbors, "ip_for_mac", lookup)
    monkeypatch.setattr(devices.neighbors, "probe_if_needed", probe)
    monkeypatch.setattr(devices, "passive_scan", lambda **_k: [])

    assert locate(_record(), timeout=1) == "192.168.20.108"
    assert calls["probes"] == 1

    # Second device reuses the located address and does not probe again.
    assert locate(_record(), timeout=1) == "192.168.20.108"
    assert calls["probes"] == 1


def test_beacon_is_the_fallback_when_there_is_no_mac(monkeypatch):
    monkeypatch.setattr(
        devices,
        "passive_scan",
        lambda **_k: [{"device_id": "bf4444444444444444dddd", "ip": "192.168.20.110"}],
    )
    assert locate(_record(mac=None), timeout=1) == "192.168.20.110"


def test_total_miss_names_the_mac(monkeypatch):
    monkeypatch.setattr(devices.neighbors, "ip_for_mac", lambda *_a, **_k: None)
    monkeypatch.setattr(devices.neighbors, "probe_if_needed", lambda: None)
    monkeypatch.setattr(devices, "passive_scan", lambda **_k: [])
    with pytest.raises(DeviceError, match="00:33:7a:aa:bb:a9"):
        locate(_record(), timeout=1)


def test_prime_addresses_reads_the_table_and_sends_nothing(monkeypatch):
    monkeypatch.setattr(
        devices.neighbors,
        "read_arp_table",
        lambda: {"00:33:7a:aa:bb:a9": "192.168.20.149"},
    )
    monkeypatch.setattr(
        devices.neighbors,
        "probe_if_needed",
        lambda: (_ for _ in ()).throw(AssertionError("prime must not probe")),
    )
    record = _record()
    prime_addresses([record])
    assert record.public()["ip"] == "192.168.20.149"
