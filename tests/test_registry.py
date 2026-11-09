import json

import pytest

from tuya_local_mcp.registry import (
    DeviceRecord,
    RegistryError,
    clear_runtime_ips,
    load_registry,
    parse_registry,
    remember_ip,
    resolve,
)

DEVICES_JSON = [
    {
        "name": "Living Room Lamp",
        "id": "bf1111111111111111aaaa",
        "key": "0123456789abcdef",
        "category": "dj",
        "version": "3.3",
        "product_name": "Smart Bulb",
    },
    {
        "name": "Desk Plug",
        "id": "bf2222222222222222bbbb",
        "key": "fedcba9876543210",
        "category": "cz",
        "version": "3.4",
        "ip": "192.168.1.50",
    },
]

SNAPSHOT_JSON = {
    "timestamp": 1700000000,
    "devices": [
        {
            "name": "Hallway Light",
            "id": "bf3333333333333333cccc",
            "key": "aaaabbbbccccdddd",
            "ver": "3.3",
            "ip": "192.168.1.60",
            "category": "dj",
        }
    ],
}


def test_parses_devices_json_list():
    records = parse_registry(DEVICES_JSON)
    assert [r.name for r in records] == ["Living Room Lamp", "Desk Plug"]
    assert records[0].is_light
    assert not records[1].is_light
    assert records[1].version_float == 3.4


def test_mac_is_normalised_and_shown_without_the_local_key():
    records = parse_registry(
        [
            {
                "name": "Hall",
                "id": "bf4444444444444444dddd",
                "key": "0123456789abcdef",
                "mac": "00-33-7A-AA-BB-A9",
            }
        ]
    )
    assert records[0].mac == "00:33:7a:aa:bb:a9"
    assert records[0].version_specified is False
    public = records[0].public()
    assert public["mac"] == "00:33:7a:aa:bb:a9"
    assert public["ip"] is None

    remember_ip(records[0].device_id, "192.168.20.149")
    try:
        assert records[0].public()["ip"] == "192.168.20.149"
        assert records[0].ip is None
    finally:
        clear_runtime_ips()


def test_garbage_mac_is_dropped():
    records = parse_registry([{"name": "Hall", "id": "x", "key": "k", "mac": "not-a-mac"}])
    assert records[0].mac is None


def test_parses_snapshot_wrapper_and_ver_alias():
    records = parse_registry(SNAPSHOT_JSON)
    assert len(records) == 1
    assert records[0].version == "3.3"
    assert records[0].version_specified is True
    assert records[0].ip == "192.168.1.60"


def test_rows_without_a_local_key_are_dropped():
    records = parse_registry([{"name": "Gateway Subdevice", "id": "bf9999"}])
    assert records == []


def test_public_view_never_exposes_the_local_key():
    record = parse_registry(DEVICES_JSON)[0]
    public = record.public()
    assert "local_key" not in public
    assert "0123456789abcdef" not in json.dumps(public)
    assert public["has_local_key"] is True


def test_local_key_is_absent_from_repr():
    record = parse_registry(DEVICES_JSON)[0]
    assert "0123456789abcdef" not in repr(record)


def test_unknown_category_defaults_to_switch():
    record = parse_registry([{"name": "Mystery", "id": "x", "key": "k"}])[0]
    assert record.is_light is False
    assert record.version_float == 3.3


@pytest.mark.parametrize(
    "query,expected",
    [
        ("bf2222222222222222bbbb", "Desk Plug"),
        ("192.168.1.50", "Desk Plug"),
        ("Living Room Lamp", "Living Room Lamp"),
        ("living room lamp", "Living Room Lamp"),
        ("desk", "Desk Plug"),
    ],
)
def test_resolve_matches_id_ip_name_and_substring(query, expected):
    records = parse_registry(DEVICES_JSON)
    assert resolve(records, query).name == expected


def test_exact_name_beats_substring_of_another_name():
    records = [
        DeviceRecord(device_id="a", name="Lamp", local_key="k"),
        DeviceRecord(device_id="b", name="Lamp Corner", local_key="k"),
    ]
    assert resolve(records, "Lamp").device_id == "a"


def test_ambiguous_substring_raises_and_names_candidates():
    records = parse_registry(DEVICES_JSON) + [
        DeviceRecord(device_id="c", name="Living Room Fan", local_key="k")
    ]
    with pytest.raises(RegistryError, match="ambiguous"):
        resolve(records, "living room")


def test_unknown_device_lists_known_names():
    with pytest.raises(RegistryError, match="Desk Plug"):
        resolve(parse_registry(DEVICES_JSON), "nope")


def test_empty_query_rejected():
    with pytest.raises(RegistryError):
        resolve(parse_registry(DEVICES_JSON), "   ")


def test_load_registry_reports_missing_file_with_guidance(tmp_path):
    with pytest.raises(RegistryError, match="tinytuya wizard"):
        load_registry(None)
    with pytest.raises(RegistryError, match="does not exist"):
        load_registry(tmp_path / "nope.json")


def test_load_registry_reads_a_real_file(tmp_path):
    path = tmp_path / "devices.json"
    path.write_text(json.dumps(DEVICES_JSON), encoding="utf-8")
    assert len(load_registry(path)) == 2


def test_load_registry_rejects_malformed_json(tmp_path):
    path = tmp_path / "devices.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(RegistryError, match="not valid JSON"):
        load_registry(path)


def test_load_registry_rejects_file_with_no_usable_devices(tmp_path):
    path = tmp_path / "devices.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(RegistryError, match="no devices"):
        load_registry(path)
