"""Construction of tinytuya connections and normalisation of their replies."""

from __future__ import annotations

import time
from typing import Any, Iterable

import tinytuya

from . import neighbors
from .discovery import passive_scan
from .registry import DeviceRecord, cached_version, remember_ip, remember_version


class DeviceError(RuntimeError):
    """A device was unreachable, rejected the key, or returned an error frame."""


# tinytuya reports failures as a dict with an "Error" key rather than raising.
def check(reply: Any, record: DeviceRecord) -> dict[str, Any]:
    if not isinstance(reply, dict):
        raise DeviceError(f"{record.name}: unexpected reply {reply!r}")

    if "Error" in reply:
        code = reply.get("Err")
        detail = reply.get("Error")
        hint = ""
        if code == "901":
            hint = " (connection failed or the device reset the session)"
        elif code == "914":
            hint = " (device rejected the local key; re-run the tinytuya wizard, "
            hint += "keys rotate when a device is re-paired)"
        elif code == "905":
            hint = " (device did not respond; it may be offline or busy with another connection)"
        raise DeviceError(f"{record.name}: {detail}{hint}")

    return reply


# device id -> (monotonic time, ip). Avoids repeating a subnet probe per device.
_LOCATED: dict[str, tuple[float, str]] = {}
_LOCATE_TTL = 60.0
# A beacon listen is shared. One quiet scan answers every device that follows.
_BEACONS: tuple[float, list[dict[str, Any]]] | None = None


def prime_addresses(records: Iterable[DeviceRecord]) -> None:
    """Fill runtime IPs from the neighbor table. Reads only; sends nothing."""
    pending = [r for r in records if not r.ip and r.mac]
    if not pending:
        return
    table = neighbors.read_arp_table()
    for record in pending:
        ip = neighbors.ip_for_mac(record.mac or "", table)
        if ip:
            remember_ip(record.device_id, ip)
            _LOCATED[record.device_id] = (time.monotonic(), ip)


def _beacon_ip(device_id: str, timeout: float) -> str | None:
    global _BEACONS
    now = time.monotonic()
    if _BEACONS is None or now - _BEACONS[0] >= _LOCATE_TTL:
        _BEACONS = (now, passive_scan(timeout=timeout))
    for entry in _BEACONS[1]:
        if entry.get("device_id") == device_id and entry.get("ip"):
            return str(entry["ip"])
    return None


def locate(record: DeviceRecord, timeout: float) -> str:
    """Return the device's IP.

    Order: address stored in the device file, then the kernel neighbor table
    keyed by MAC, then one ARP probe of on-link subnets, then a passive beacon
    listen matched on device id.
    """
    if record.ip:
        return record.ip

    now = time.monotonic()
    cached = _LOCATED.get(record.device_id)
    if cached and now - cached[0] < _LOCATE_TTL:
        return cached[1]

    ip: str | None = None
    probed = False
    if record.mac:
        ip = neighbors.ip_for_mac(record.mac)
        if ip is None:
            neighbors.probe_if_needed()
            probed = True
            ip = neighbors.ip_for_mac(record.mac)

    if ip is None:
        ip = _beacon_ip(record.device_id, timeout)

    if ip is None:
        detail = f"{record.name}: no IP in the device file"
        if record.mac:
            detail += f"; MAC {record.mac} was not in the neighbor table"
            if probed:
                detail += " and a local ARP probe did not find it"
        detail += (
            f"; it did not broadcast within {timeout:.0f}s. "
            "Re-run `python -m tinytuya scan` to refresh addresses."
        )
        raise DeviceError(detail)

    remember_ip(record.device_id, ip)
    _LOCATED[record.device_id] = (time.monotonic(), ip)
    return ip


# Tried when the device file does not name a protocol. 3.5 and 3.4 negotiate a
# session key and fail fast (err 914) on a mismatch. 3.3 only fails once a
# command is sent, and a 3.5 peer resets that session (err 901) after the
# socket timeout, so it is last.
_PROBE_VERSIONS = ("3.5", "3.4", "3.3")


def _build(record: DeviceRecord, ip: str, version: str, timeout: float, force_bulb: bool):
    cls = tinytuya.BulbDevice if (force_bulb or record.is_light) else tinytuya.OutletDevice
    device = cls(record.device_id, address=ip, local_key=record.local_key)
    device.set_version(float(version))
    device.set_socketTimeout(timeout)
    device.set_socketPersistent(False)
    return device


def _is_live(reply: Any) -> bool:
    return isinstance(reply, dict) and "dps" in reply and "Error" not in reply


def _error_code(reply: Any) -> str | None:
    if isinstance(reply, dict):
        code = reply.get("Err")
        return str(code) if code is not None else None
    return None


def _one_status(device):
    """One status read, then the socket is closed.

    tinytuya's default is five retries with a 5s delay. A protocol mismatch
    or a heater that just closed a session would otherwise block for half a
    minute. These devices also accept a single connection, so the socket has
    to be gone before the next attempt.
    """
    previous_limit = device.socketRetryLimit
    previous_delay = device.socketRetryDelay
    device.set_socketRetryLimit(1)
    device.set_socketRetryDelay(0.2)
    try:
        return device.status()
    finally:
        device.set_socketRetryLimit(previous_limit)
        device.set_socketRetryDelay(previous_delay)
        close = getattr(device, "_check_socket_close", None)
        if close is not None:
            close(True)


def _poll_version(record: DeviceRecord, ip: str, version: str, timeout: float, force_bulb: bool, tries: int):
    """Ask `version` for datapoints. Retries the same version before giving up.

    A 3.5 heater often answers 914 or 901 to the session that follows one it
    just closed, then accepts the next attempt.
    """
    last: Any = None
    for _ in range(tries):
        reply = _one_status(_build(record, ip, version, timeout, force_bulb))
        if _is_live(reply):
            remember_version(record.device_id, version)
            return reply
        last = reply
    return last


def read_status(record: DeviceRecord, *, timeout: float, force_bulb: bool = False) -> dict[str, Any]:
    """Read datapoints, learning the protocol version when the file omits it.

    The reply from the attempt that worked is returned as-is. Opening a second
    session to read again is what makes these heaters answer 914.
    """
    ip = locate(record, timeout=timeout)
    known = cached_version(record.device_id)
    if record.version_specified or known is not None:
        reply = _poll_version(record, ip, known or record.version, timeout, force_bulb, tries=2)
        if _is_live(reply):
            return reply
        check(reply, record)
        raise DeviceError(f"{record.name}: status reply had no datapoints")

    last: Any = None
    for version in _PROBE_VERSIONS:
        reply = _poll_version(record, ip, version, timeout, force_bulb, tries=2)
        if _is_live(reply):
            return reply
        last = reply
        # 914: peer is up but this protocol was rejected. 901: session never
        # stayed up; another version will not do better.
        if _error_code(reply) != "914":
            break

    check(last, record)
    raise DeviceError(f"{record.name}: protocol probe failed ({last!r})")


def connect(record: DeviceRecord, *, timeout: float, force_bulb: bool = False):
    """Build a tinytuya device object bound to `record`.

    Connections are non-persistent: each call opens and closes a socket. Many
    Tuya devices accept only one connection at a time, so holding one open
    would lock out the Smart Life app.

    An omitted protocol version is learned with one status read (3.5, then
    3.4, then 3.3). The object returned here is a fresh session at that
    version, for a following write. An explicit version is never overridden.
    """
    ip = locate(record, timeout=timeout)
    known = cached_version(record.device_id)
    if not record.version_specified and known is None:
        read_status(record, timeout=timeout, force_bulb=force_bulb)
        known = cached_version(record.device_id)
    return _build(record, ip, known or record.version, timeout, force_bulb)


def require_light(record: DeviceRecord) -> None:
    if not record.is_light:
        raise DeviceError(
            f"{record.name} is category {record.category!r}, which is not a light. "
            "Use set_datapoint if you know the datapoint number."
        )


def summarise(record: DeviceRecord, status: dict[str, Any]) -> dict[str, Any]:
    """Attach a human-readable reading of the datapoints where we can infer one.

    Tuya datapoint numbering is per-product. Bulbs use either the 1-5 range
    (older "A" series) or the 20-24 range ("B" series); switches and plugs
    almost always put the primary relay on datapoint 1.
    """
    dps = status.get("dps", {}) or {}
    reading: dict[str, Any] = {}

    for dp in ("1", "20"):
        if dp in dps and isinstance(dps[dp], bool):
            reading["on"] = dps[dp]
            reading["switch_dp"] = int(dp)
            break

    for dp, label, scale in (("3", "brightness_pct", 255), ("22", "brightness_pct", 1000)):
        if dp in dps and isinstance(dps[dp], int):
            reading[label] = round(dps[dp] / scale * 100)
            break

    for dp in ("2", "21"):
        if dp in dps and isinstance(dps[dp], str):
            reading["mode"] = dps[dp]
            break

    return {"device": record.public(), "dps": dps, "reading": reading}
