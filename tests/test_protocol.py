"""Protocol selection when the device file omits a version."""

import pytest

from tuya_local_mcp import devices
from tuya_local_mcp.devices import DeviceError, connect, read_status
from tuya_local_mcp.registry import DeviceRecord, clear_runtime_versions


class _FakeDevice:
    def __init__(self, dev_id, address=None, local_key=None, **_kwargs):
        self.dev_id = dev_id
        self.address = address
        self.version = None
        self.socketRetryLimit = 5
        self.socketRetryDelay = 5
        self.status_calls = 0

    def set_version(self, version):
        self.version = version

    def set_socketTimeout(self, _timeout):
        return None

    def set_socketPersistent(self, _persist):
        return None

    def set_socketRetryLimit(self, limit):
        self.socketRetryLimit = limit

    def set_socketRetryDelay(self, delay):
        self.socketRetryDelay = delay

    def status(self):
        self.status_calls += 1
        script = _SCRIPTS.get(self.version, {"Error": "no", "Err": "901"})
        return script


_BUILT: list[_FakeDevice] = []
_SCRIPTS: dict[float, dict] = {}


def _factory(*args, **kwargs):
    device = _FakeDevice(*args, **kwargs)
    _BUILT.append(device)
    return device


def _record(**overrides) -> DeviceRecord:
    fields = dict(
        device_id="bf4444444444444444dddd",
        name="Hall heater",
        local_key="0123456789abcdef",
        ip="192.168.20.149",
    )
    fields.update(overrides)
    return DeviceRecord(**fields)


@pytest.fixture(autouse=True)
def _isolated():
    _BUILT.clear()
    _SCRIPTS.clear()
    clear_runtime_versions()
    yield
    clear_runtime_versions()


@pytest.fixture
def _patched(monkeypatch):
    monkeypatch.setattr(devices.tinytuya, "OutletDevice", _factory)
    monkeypatch.setattr(devices.tinytuya, "BulbDevice", _factory)


def test_unspecified_version_keeps_the_protocol_that_returns_dps(_patched):
    _SCRIPTS[3.5] = {"Error": "Check device key or version", "Err": "914"}
    _SCRIPTS[3.4] = {"dps": {"1": False}}

    reply = read_status(_record(), timeout=1)

    # 3.5 is refused twice (a heater often rejects the session it just closed),
    # then 3.4 answers.
    assert [d.version for d in _BUILT] == [3.5, 3.5, 3.4]
    assert reply["dps"] == {"1": False}
    assert _record().public()["version"] == "3.4"

    _BUILT.clear()
    again = read_status(_record(), timeout=1)
    assert [d.version for d in _BUILT] == [3.4]
    assert again["dps"] == {"1": False}


def test_explicit_version_is_not_probed(_patched):
    device = connect(_record(version="3.3", version_specified=True), timeout=1)
    assert device.version == 3.3
    assert device.status_calls == 0
    assert len(_BUILT) == 1


def test_connect_error_stops_the_probe(_patched):
    _SCRIPTS[3.5] = {"Error": "Network Error: Unable to Connect", "Err": "901"}
    with pytest.raises(DeviceError, match="Unable to Connect"):
        read_status(_record(), timeout=1)
    assert [d.version for d in _BUILT] == [3.5, 3.5]


def test_key_rejection_tries_the_older_protocols(_patched):
    _SCRIPTS[3.5] = {"Error": "Check device key or version", "Err": "914"}
    _SCRIPTS[3.4] = {"Error": "Check device key or version", "Err": "914"}
    _SCRIPTS[3.3] = {"dps": {"1": True}}

    reply = read_status(_record(), timeout=1)
    assert reply["dps"] == {"1": True}
    assert [d.version for d in _BUILT] == [3.5, 3.5, 3.4, 3.4, 3.3]
