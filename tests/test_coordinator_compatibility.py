"""Compatibility checks for the Home Assistant coordinator API."""

import ast
from pathlib import Path


def test_coordinator_passes_name_as_keyword() -> None:
    """Home Assistant 2026.11 requires the coordinator name keyword."""
    source = Path(
        "custom_components/headscale_monitor/coordinator.py"
    ).read_text(encoding="utf-8")
    tree = ast.parse(source)

    super_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "__init__"
        and isinstance(node.func.value, ast.Call)
        and isinstance(node.func.value.func, ast.Name)
        and node.func.value.func.id == "super"
    ]

    assert len(super_calls) == 1
    assert len(super_calls[0].args) == 2
    assert any(keyword.arg == "name" for keyword in super_calls[0].keywords)