"""MCP server exposing local-network control of Tuya devices."""

from __future__ import annotations

import time
from typing import Any

from mcp.server.mcpserver import MCPServer

from . import __version__
from .config import Config
from .devices import DeviceError, check, connect, prime_addresses, read_status, require_light, summarise
from .discovery import passive_scan
from .registry import DeviceRecord, RegistryError, load_registry, resolve

mcp = MCPServer(
    "tuya-local",
    version=__version__,
    instructions=(
        "Controls Tuya / Smart Life devices over the local network. Address devices "
        "by friendly name, device id, or IP. A device with a MAC and no stored IP "
        "is resolved from the local neighbor table before any beacon listen. Call "
        "list_devices first to see what exists. get_status shows raw datapoints "
        "for products the helper tools do not cover; set_datapoint writes them."
    ),
)

_CONFIG = Config.from_env()
_REGISTRY: list[DeviceRecord] | None = None
_STATUS_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}


def _registry() -> list[DeviceRecord]:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = load_registry(_CONFIG.devices_file)
    return _REGISTRY


def _find(query: str) -> DeviceRecord:
    return resolve(_registry(), query)


def _guard_writes() -> None:
    if _CONFIG.read_only:
        raise DeviceError(
            "TUYA_READ_ONLY is set; this server is running in read-only mode and "
            "will not change device state. Unset it to enable control."
        )


def _status(record: DeviceRecord, *, use_cache: bool = True) -> dict[str, Any]:
    now = time.monotonic()
    if use_cache and _CONFIG.cache_ttl > 0:
        cached = _STATUS_CACHE.get(record.device_id)
        if cached and now - cached[0] < _CONFIG.cache_ttl:
            return cached[1]

    result = check(read_status(record, timeout=_CONFIG.connect_timeout), record)
    _STATUS_CACHE[record.device_id] = (now, result)
    return result


def _invalidate(record: DeviceRecord) -> None:
    _STATUS_CACHE.pop(record.device_id, None)


def _hex_to_rgb(value: str) -> tuple[int, int, int]:
    raw = value.strip().lstrip("#")
    if len(raw) == 3:
        raw = "".join(ch * 2 for ch in raw)
    if len(raw) != 6:
        raise ValueError(f"colour must be a 3- or 6-digit hex string, got {value!r}")
    try:
        return int(raw[0:2], 16), int(raw[2:4], 16), int(raw[4:6], 16)
    except ValueError as exc:
        raise ValueError(f"{value!r} is not valid hex") from exc


def _pct(value: int, label: str) -> int:
    if not 0 <= value <= 100:
        raise ValueError(f"{label} must be between 0 and 100, got {value}")
    return value


# --------------------------------------------------------------------------
# Read-only tools
# --------------------------------------------------------------------------


@mcp.tool()
def list_devices() -> dict[str, Any]:
    """List every Tuya device in the local registry.

    Returns names, device ids, IPs and protocol versions. Local keys are never
    returned. Use the `name` field when calling the other tools.
    """
    records = _registry()
    prime_addresses(records)
    return {
        "source": str(_CONFIG.devices_file),
        "read_only": _CONFIG.read_only,
        "count": len(records),
        "devices": [r.public() for r in records],
    }


@mcp.tool()
def discover_devices(timeout: float | None = None) -> dict[str, Any]:
    """Passively listen for Tuya devices broadcasting on the local network.

    This transmits nothing - it only receives the beacons devices emit every
    few seconds. Useful for finding a device whose IP has changed, or for
    spotting devices that are on the network but missing from the registry.
    """
    seconds = timeout if timeout is not None else _CONFIG.discovery_timeout
    found = passive_scan(timeout=seconds)

    known_ids = set()
    try:
        known_ids = {r.device_id for r in _registry()}
    except RegistryError:
        pass  # discovery should still work before the wizard has been run

    for entry in found:
        entry["in_registry"] = entry.get("device_id") in known_ids

    return {"listened_seconds": seconds, "count": len(found), "devices": found}


@mcp.tool()
def get_status(device: str) -> dict[str, Any]:
    """Read the current state of a device.

    `device` may be a friendly name, a device id, or an IP address. Returns the
    raw Tuya datapoints plus a best-effort interpretation of the common ones.
    """
    record = _find(device)
    return summarise(record, _status(record))


@mcp.tool()
def get_all_status() -> dict[str, Any]:
    """Read the state of every device in the registry.

    Devices that fail are reported individually rather than failing the call,
    so one offline device does not hide the rest.
    """
    results = []
    for record in _registry():
        try:
            results.append(summarise(record, _status(record)))
        except (DeviceError, OSError) as exc:
            results.append({"device": record.public(), "error": str(exc)})
    return {"count": len(results), "devices": results}


# --------------------------------------------------------------------------
# Control tools
# --------------------------------------------------------------------------


@mcp.tool()
def set_power(device: str, on: bool, switch_dp: int | None = None) -> dict[str, Any]:
    """Turn a device on or off.

    `switch_dp` overrides the datapoint carrying the relay/switch. Leave it
    unset to let tinytuya pick, which is correct for the large majority of
    plugs, switches and bulbs.
    """
    _guard_writes()
    record = _find(device)
    conn = connect(record, timeout=_CONFIG.connect_timeout)

    if switch_dp is not None:
        reply = conn.set_value(switch_dp, on)
    else:
        reply = conn.turn_on() if on else conn.turn_off()

    check(reply, record)
    _invalidate(record)
    return {"device": record.public(), "requested": {"on": on}, "result": reply}


@mcp.tool()
def set_brightness(device: str, percent: int) -> dict[str, Any]:
    """Set a light's brightness as a percentage (0-100)."""
    _guard_writes()
    record = _find(device)
    require_light(record)
    percent = _pct(percent, "percent")

    conn = connect(record, timeout=_CONFIG.connect_timeout, force_bulb=True)
    conn.status()  # primes tinytuya's A/B bulb-type detection before writing
    reply = check(conn.set_brightness_percentage(percent), record)
    _invalidate(record)
    return {"device": record.public(), "requested": {"brightness_pct": percent}, "result": reply}


@mcp.tool()
def set_color(device: str, color: str) -> dict[str, Any]:
    """Set a light's colour from a hex string such as '#FF8800' or 'f80'."""
    _guard_writes()
    record = _find(device)
    require_light(record)
    red, green, blue = _hex_to_rgb(color)

    conn = connect(record, timeout=_CONFIG.connect_timeout, force_bulb=True)
    conn.status()
    reply = check(conn.set_colour(red, green, blue), record)
    _invalidate(record)
    return {
        "device": record.public(),
        "requested": {"color": color, "rgb": [red, green, blue]},
        "result": reply,
    }


@mcp.tool()
def set_color_temp(device: str, percent: int, brightness: int | None = None) -> dict[str, Any]:
    """Set a light to white mode at a colour temperature percentage (0 warm, 100 cool).

    Optionally set brightness in the same call.
    """
    _guard_writes()
    record = _find(device)
    require_light(record)
    percent = _pct(percent, "percent")

    conn = connect(record, timeout=_CONFIG.connect_timeout, force_bulb=True)
    conn.status()

    if brightness is None:
        reply = conn.set_colourtemp_percentage(percent)
    else:
        reply = conn.set_white_percentage(_pct(brightness, "brightness"), percent)

    check(reply, record)
    _invalidate(record)
    return {
        "device": record.public(),
        "requested": {"color_temp_pct": percent, "brightness_pct": brightness},
        "result": reply,
    }


@mcp.tool()
def set_datapoint(device: str, dp: int, value: bool | int | str) -> dict[str, Any]:
    """Write a raw Tuya datapoint.

    The escape hatch for products whose datapoints the helper tools do not
    cover - fans, curtains, heaters, valves. Call get_status first to see which
    datapoints a device exposes and what types they hold.
    """
    _guard_writes()
    record = _find(device)
    conn = connect(record, timeout=_CONFIG.connect_timeout)
    reply = check(conn.set_value(dp, value), record)
    _invalidate(record)
    return {"device": record.public(), "requested": {"dp": dp, "value": value}, "result": reply}


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
