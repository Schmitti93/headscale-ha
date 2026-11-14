"""Prove the CI secret scan rejects a newly introduced fixture secret."""

from __future__ import annotations

import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path


def main() -> int:
    with tempfile.TemporaryDirectory(dir=".") as directory:
        fixture = Path(directory) / "introduced_secret.py"
        secret = "AKIA" + "ABCDEFGHIJKLMNOP"  # pragma: allowlist secret
        fixture.write_text(f'AWS_ACCESS_KEY_ID = "{secret}"\n', encoding="utf-8")
        result = subprocess.run(  # noqa: S603  # nosec B603
            [
                sys.executable,
                "scripts/check_secrets.py",
                str(fixture),
            ],
            check=False,
        )
    if result.returncode == 0:
        print("detect-secrets failed open: fixture secret was accepted", file=sys.stderr)
        return 1
    print("detect-secrets fail-closed proof passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
