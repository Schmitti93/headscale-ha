from pathlib import Path

from scripts.prove_detect_secrets_fail_closed import is_expected_detection


def test_secret_proof_accepts_only_detection_exit_code() -> None:
    assert is_expected_detection(1)
    for unexpected in (0, 2, 3, 127):
        assert not is_expected_detection(unexpected)


def test_compose_sets_import_path_for_direct_smoke_command() -> None:
    compose = Path("docker-compose.test.yml").read_text(encoding="utf-8")
    assert "PYTHONPATH: /config" in compose


def test_isolated_compose_does_not_publish_home_assistant_to_host() -> None:
    compose = Path("docker-compose.test.yml").read_text(encoding="utf-8")
    assert "18123" not in compose
    readme = Path("README.md").read_text(encoding="utf-8")
    assert "no host-published port" in readme
