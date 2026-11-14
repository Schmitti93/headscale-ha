from custom_components.headscale_monitor.entity import hub_device_info, node_device_info, unique_id


def test_stable_unique_ids_and_device_identifiers() -> None:
    assert unique_id("entry-abc", "node", 42, "online") == "entry-abc_node_42_online"
    assert hub_device_info("entry-abc")["identifiers"] == {("headscale_monitor", "entry-abc")}
    info = node_device_info("entry-abc", 42, "laptop")
    assert info["identifiers"] == {("headscale_monitor", "entry-abc_node_42")}
    assert info["via_device"] == ("headscale_monitor", "entry-abc")
