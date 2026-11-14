import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_marketplace_metadata_points_to_public_project_resources():
    manifest = json.loads(
        (ROOT / "custom_components/headscale_monitor/manifest.json").read_text()
    )

    assert manifest["codeowners"] == ["@Schmitti93"]
    assert manifest["documentation"] == "https://github.com/Schmitti93/headscale-ha"
    assert manifest["issue_tracker"] == "https://github.com/Schmitti93/headscale-ha/issues"
    assert manifest["integration_type"] == "hub"
    assert manifest["version"] == "0.2.2"


def test_hacs_metadata_declares_integration_archive_layout():
    hacs = json.loads((ROOT / "hacs.json").read_text())

    assert hacs["name"] == "Headscale Monitor"
    assert hacs["content_in_root"] is False
    assert hacs["render_readme"] is True
    assert hacs["homeassistant"] == "2025.1.0"


def test_marketplace_brand_assets_are_inside_integration_directory():
    brand = ROOT / "custom_components/headscale_monitor/brand"

    assert (brand / "icon.png").is_file()
    assert (brand / "icon@2x.png").is_file()


def test_english_translation_contains_all_entity_translation_keys():
    strings = json.loads(
        (ROOT / "custom_components/headscale_monitor/strings.json").read_text()
    )
    english = json.loads(
        (
            ROOT
            / "custom_components/headscale_monitor/translations/en.json"
        ).read_text()
    )

    assert english["entity"] == strings["entity"]
