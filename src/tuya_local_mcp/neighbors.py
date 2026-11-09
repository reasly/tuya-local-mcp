"""Resolve a device IP from its MAC using the kernel neighbor table.

Tuya's cloud dump often records a MAC and no address. On the same L2 segment
the kernel already knows that MAC from ARP, including stale entries, so a
lookup is enough. When the entry has been flushed, one UDP sweep of the
on-link subnet makes the kernel learn it again. Discovery beacons stay a
separate, transmit-nothing path.
"""

from __future__ import annotations

import ipaddress
import socket
import struct
import time
from pathlib import Path

# /22 is 1022 hosts. Anything wider (docker bridges, VPNs) is not swept.
_MIN_PREFIX = 22
_MAX_PREFIX = 30
_PROBE_PORT = 9
_PROBE_TTL = 30.0

_last_probe = 0.0


def normalize_mac(value: str | None) -> str | None:
    """Return a lowercase colon-separated MAC, or None if it is not 48 bits."""
    if not value:
        return None
    hexdigits = "".join(ch for ch in value if ch in "0123456789abcdefABCDEF")
    if len(hexdigits) != 12:
        return None
    folded = hexdigits.lower()
    return ":".join(folded[i : i + 2] for i in range(0, 12, 2))


def parse_proc_net_arp(text: str) -> dict[str, str]:
    """Map MAC to IPv4 from `/proc/net/arp` contents. Incomplete rows are skipped."""
    found: dict[str, str] = {}
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        ip, _hw_type, flags, hw = parts[0], parts[1], parts[2], parts[3]
        try:
            if int(flags, 16) == 0:
                continue
        except ValueError:
            continue
        mac = normalize_mac(hw)
        if mac is None or mac == "00:00:00:00:00:00":
            continue
        try:
            ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError:
            continue
        found[mac] = ip
    return found


def _le_hex_address(value: str) -> ipaddress.IPv4Address:
    """Decode a little-endian hex address from `/proc/net/route`."""
    return ipaddress.IPv4Address(struct.pack("<I", int(value, 16)))


def parse_proc_net_route(text: str) -> list[ipaddress.IPv4Network]:
    """On-link IPv4 networks small enough to probe. Duplicates are collapsed."""
    networks: set[ipaddress.IPv4Network] = set()
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 8:
            continue
        dest_hex, gateway, flags_hex, mask_hex = parts[1], parts[2], parts[3], parts[7]
        if gateway != "00000000":
            continue
        try:
            flags = int(flags_hex, 16)
            dest = _le_hex_address(dest_hex)
            mask = _le_hex_address(mask_hex)
        except ValueError:
            continue
        if not flags & 0x1:  # RTF_UP
            continue
        prefix = bin(int(mask)).count("1")
        if not _MIN_PREFIX <= prefix <= _MAX_PREFIX:
            continue
        network = ipaddress.IPv4Network((dest, prefix), strict=False)
        if network.is_loopback or network.is_link_local or network.is_multicast:
            continue
        networks.add(network)
    return sorted(networks, key=lambda net: (int(net.network_address), net.prefixlen))


def read_arp_table(path: Path | None = None) -> dict[str, str]:
    arp_path = path or Path("/proc/net/arp")
    try:
        text = arp_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    return parse_proc_net_arp(text)


def scannable_networks(path: Path | None = None) -> list[ipaddress.IPv4Network]:
    route_path = path or Path("/proc/net/route")
    try:
        text = route_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return parse_proc_net_route(text)


def ip_for_mac(mac: str, table: dict[str, str] | None = None) -> str | None:
    folded = normalize_mac(mac)
    if folded is None:
        return None
    return (table if table is not None else read_arp_table()).get(folded)


def probe_networks(networks: list[ipaddress.IPv4Network], wait: float = 1.2) -> None:
    """Send one discard-port datagram per host so the kernel issues ARP requests.

    The datagram itself is not a Tuya frame. Replies are not read; the neighbor
    table is consulted afterwards.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sent = 0
        for network in networks:
            for host in network.hosts():
                try:
                    sock.sendto(b"\x00", (str(host), _PROBE_PORT))
                except OSError:
                    continue
                sent += 1
                if sent % 32 == 0:
                    time.sleep(0.005)
    finally:
        sock.close()
    if wait > 0:
        time.sleep(wait)


def probe_if_needed(wait: float = 1.2) -> None:
    """Sweep on-link subnets at most once per `_PROBE_TTL` seconds."""
    global _last_probe
    now = time.monotonic()
    if now - _last_probe < _PROBE_TTL:
        return
    networks = scannable_networks()
    _last_probe = time.monotonic()
    if networks:
        probe_networks(networks, wait=wait)


def reset_probe_clock() -> None:
    """Test hook. Production calls never need this."""
    global _last_probe
    _last_probe = 0.0
