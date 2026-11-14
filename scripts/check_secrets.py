"""Run detect-secrets fail-closed without modifying the tracked baseline."""

from __future__ import annotations

import shutil
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path


def run(paths: list[str]) -> int:
    with tempfile.TemporaryDirectory() as directory:
        baseline = Path(directory) / ".secrets.baseline"
        shutil.copyfile(".secrets.baseline", baseline)
        result = subprocess.run(  # noqa: S603  # nosec B603
            [
                sys.executable,
                "-m",
                "detect_secrets.pre_commit_hook",
                "--baseline",
                str(baseline),
                *paths,
            ],
            check=False,
        )
        return 0 if result.returncode in {0, 3} else result.returncode


def main() -> int:
    paths = sys.argv[1:]
    if not paths:
        git = shutil.which("git")
        if git is None:
            raise RuntimeError("git is required")
        paths = [
            path
            for path in subprocess.check_output(  # noqa: S603  # nosec B603
                [git, "ls-files", "--cached", "--others", "--exclude-standard"], text=True
            ).splitlines()
            if path != ".secrets.baseline"
        ]
    return run(paths)


if __name__ == "__main__":
    raise SystemExit(main())
