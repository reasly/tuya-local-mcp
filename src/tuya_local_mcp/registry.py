"""Loading and lookup of the local device registry.

The registry is whatever the tinytuya wizard wrote out. Two shapes exist in the
wild and both are accepted:

    devices.json  -> [ {...}, {...} ]
    snapshot.json -> { "timestamp": ..., "devices": [ {...}, {...} ] }

Field names differ slightly between them ("version" vs "ver", "ip" vs
"address"), so everything is normalised into a DeviceRecord on load.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .neighbors import normalize_mac

# IPs learned at runtime (neighbor table, beacon). The device file is not rewritten;
# DHCP addresses change, and a later lookup should be free to replace these.
_runtime_ips: dict[str, str] = {}
# Protocol version learned by a successful local handshake. Cloud dumps often
# omit it, and the 3.3 default makes a 3.4/3.5 device reset the session.
_runtime_versions: dict[str, str] = {}

# Tuya product categories that behave like lights. Anything not in here is
# treated as a generic switch/outlet, which is the safer default because the
# bulb helpers assume dimming and colour datapoints exist.
LIGHT_CATEGORIES = {"dj", "dd", "dc", "xdd", "fwd", "tgq", "tyndj", "sxd"}


class RegistryError(RuntimeError):
    """Raised when the device file is missing, malformed, or ambiguous."""


@dataclass(frozen=True)
class DeviceRecord:
    device_id: str
    name: str
    # repr=False so the key can never leak into a traceback or a log line.
    local_key: str = field(repr=False)
    ip: str | None = None
    version: str = "3.3"
    category: str | None = None
    product_name: str | None = None
    mac: str | None = None
    # False when the device file omitted version/ver and we filled in the default.
    version_specified: bool = False

    @property
    def is_light(self) -> bool:
        return (self.category or "").lower() in LIGHT_CATEGORIES

    @property
    def version_float(self) -> float:
        try:
            return float(self.version)
        except (TypeError, ValueError):
            return 3.3

    def public(self) -> dict[str, Any]:
        """Serialisable view with the local key stripped out."""
        return {
            "device_id": self.device_id,
            "name": self.name,
            "ip": _runtime_ips.get(self.device_id) or self.ip,
            "mac": self.mac,
            "version": _runtime_versions.get(self.device_id, self.version),
            "version_specified": self.version_specified,
            "category": self.category,
            "product_name": self.product_name,
            "kind": "light" if self.is_light else "switch",
            "has_local_key": bool(self.local_key),
        }


def _first(entry: dict[str, Any], *names: str) -> Any:
    for name in names:
        value = entry.get(name)
        if value not in (None, ""):
            return value
    return None


def _to_record(entry: dict[str, Any]) -> DeviceRecord | None:
    device_id = _first(entry, "id", "device_id", "devId", "gwId")
    local_key = _first(entry, "key", "local_key", "localKey")
    if not device_id or not local_key:
        # Sub-devices behind a gateway and incomplete wizard rows land here.
        return None

    raw_version = _first(entry, "version", "ver")
    mac = _first(entry, "mac", "wifi_mac", "macAddress")
    return DeviceRecord(
        device_id=str(device_id),
        name=str(_first(entry, "name", "product_name") or device_id),
        local_key=str(local_key),
        ip=_first(entry, "ip", "address"),
        version=str(raw_version) if raw_version is not None else "3.3",
        category=_first(entry, "category"),
        product_name=_first(entry, "product_name", "model"),
        mac=normalize_mac(mac if isinstance(mac, str) else None),
        version_specified=raw_version is not None,
    )


def remember_ip(device_id: str, ip: str) -> None:
    """Remember an address learned from ARP or a beacon. Does not touch the file."""
    _runtime_ips[device_id] = ip


def clear_runtime_ips() -> None:
    _runtime_ips.clear()


def remember_version(device_id: str, version: str) -> None:
    """Remember a protocol version confirmed by a local handshake."""
    _runtime_versions[device_id] = str(version)


def cached_version(device_id: str) -> str | None:
    """Protocol version confirmed earlier in this process, if any."""
    return _runtime_versions.get(device_id)


def clear_runtime_versions() -> None:
    _runtime_versions.clear()


def parse_registry(payload: Any) -> list[DeviceRecord]:
    """Turn already-decoded JSON into records. Exposed for testing."""
    if isinstance(payload, dict):
        entries = payload.get("devices", [])
    elif isinstance(payload, list):
        entries = payload
    else:
        raise RegistryError(
            f"expected a JSON list or an object with a 'devices' key, got {type(payload).__name__}"
        )

    if not isinstance(entries, list):
        raise RegistryError("'devices' must be a list")

    records = [r for r in (_to_record(e) for e in entries if isinstance(e, dict)) if r]
    return records


def load_registry(path: Path | None) -> list[DeviceRecord]:
    if path is None:
        raise RegistryError(
            "No device file found. Run `python -m tinytuya wizard` to generate "
            "devices.json, then set TUYA_DEVICES_FILE to its path."
        )
    if not path.is_file():
        raise RegistryError(f"device file does not exist: {path}")

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RegistryError(f"{path} is not valid JSON: {exc}") from exc

    records = parse_registry(payload)
    if not records:
        raise RegistryError(f"{path} contained no devices with a usable local key")
    return records


def resolve(records: Iterable[DeviceRecord], query: str) -> DeviceRecord:
    """Find one device by id, IP, or friendly name.

    Matching widens in stages and stops at the first stage that produces
    exactly one hit, so an exact name always beats a substring of another name.
    """
    records = list(records)
    needle = query.strip()
    if not needle:
        raise RegistryError("device query was empty")

    folded = needle.casefold()

    stages = (
        [r for r in records if r.device_id == needle],
        [r for r in records if r.ip and r.ip == needle],
        [r for r in records if r.name.casefold() == folded],
        [r for r in records if folded in r.name.casefold()],
    )

    for matches in stages:
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            names = ", ".join(sorted(f"{m.name} ({m.device_id})" for m in matches))
            raise RegistryError(f"{query!r} is ambiguous; matches: {names}")

    known = ", ".join(sorted(r.name for r in records)) or "(none)"
    raise RegistryError(f"no device matching {query!r}. Known devices: {known}")
