import ipaddress

from tuya_local_mcp.neighbors import (
    ip_for_mac,
    normalize_mac,
    parse_proc_net_arp,
    parse_proc_net_route,
    probe_networks,
)

ARP = """\
IP address       HW type     Flags       HW address            Mask     Device
192.168.20.149   0x1         0x2         00:33:7A:AA:BB:A9     *        br0
192.168.20.133   0x1         0x0         00:00:00:00:00:00     *        br0
192.168.20.147   0x1         0x2         00-33-7a-aa-ef-a8     *        br0
"""

ROUTE = """\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
br0\t00000000\t0114A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
br0\t0014A8C0\t00000000\t0001\t0\t0\t100\t00FEFFFF\t0\t0\t0
br0\t0014A8C0\t00000000\t0001\t0\t0\t900\t00FEFFFF\t0\t0\t0
enx\t0003FEA9\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0
"""


def test_normalize_mac_accepts_common_spellings():
    assert normalize_mac("00:33:7A:AA:BB:A9") == "00:33:7a:aa:bb:a9"
    assert normalize_mac("00-33-7a-aa-bb-a9") == "00:33:7a:aa:bb:a9"
    assert normalize_mac("00337aaabba9") == "00:33:7a:aa:bb:a9"
    assert normalize_mac("nope") is None
    assert normalize_mac(None) is None
    assert normalize_mac("") is None


def test_parse_arp_skips_incomplete_rows_and_folds_macs():
    table = parse_proc_net_arp(ARP)
    assert table == {
        "00:33:7a:aa:bb:a9": "192.168.20.149",
        "00:33:7a:aa:ef:a8": "192.168.20.147",
    }
    assert ip_for_mac("00:33:7A:AA:BB:A9", table) == "192.168.20.149"
    assert ip_for_mac("aa:bb:cc:dd:ee:ff", table) is None


def test_parse_route_keeps_only_small_onlink_subnets():
    networks = parse_proc_net_route(ROUTE)
    assert networks == [ipaddress.IPv4Network("192.168.20.0/23")]


def test_probe_sends_one_datagram_per_host(monkeypatch):
    sent: list[tuple[str, int]] = []

    class FakeSocket:
        def sendto(self, _data, addr):
            sent.append(addr)

        def close(self):
            pass

    monkeypatch.setattr(
        "tuya_local_mcp.neighbors.socket.socket", lambda *_a, **_k: FakeSocket()
    )
    monkeypatch.setattr("tuya_local_mcp.neighbors.time.sleep", lambda *_a, **_k: None)

    probe_networks([ipaddress.IPv4Network("192.0.2.0/30")], wait=0)
    assert sent == [("192.0.2.1", 9), ("192.0.2.2", 9)]
