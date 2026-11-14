from custom_components.headscale_monitor.entity import (
    NodeEntityMixin,
    hub_device_info,
    new_node_ids,
    node_device_info,
    unique_id,
)
from custom_components.headscale_monitor.models import parse_snapshot


def test_stable_unique_ids_and_device_identifiers() -> None:
    assert unique_id("entry-abc", "node", 42, "online") == "entry-abc_node_42_online"
    assert hub_device_info("entry-abc")["identifiers"] == {("headscale_monitor", "entry-abc")}
    info = node_device_info("entry-abc", 42, "laptop")
    assert info["identifiers"] == {("headscale_monitor", "entry-abc_node_42")}
    assert info["via_device"] == ("headscale_monitor", "entry-abc")


def test_new_node_ids_only_returns_nodes_not_already_added() -> None:
    snapshot = parse_snapshot({"version": "0.29.3", "nodes": [{"id": 1}, {"id": 2}]})
    assert new_node_ids(snapshot, {1}) == {2}


def test_removed_node_entity_becomes_unavailable_without_stop_iteration() -> None:
    class Coordinator:
        data = parse_snapshot({"version": "0.29.3", "nodes": []})
        last_update_success = True

    entity = NodeEntityMixin()
    entity.coordinator = Coordinator()
    entity.node_id = 99
    assert entity.node is None
    assert entity.available is False
