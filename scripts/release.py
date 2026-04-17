#!/usr/bin/env python
"""Build and publish PacketPulse to TestPyPI or PyPI.

Usage examples:
  python scripts/release.py --repository testpypi
  python scripts/release.py --repository pypi
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run(cmd: list[str]) -> None:
    print("[run]", " ".join(cmd))
    subprocess.run(cmd, check=True, cwd=ROOT)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build + publish PacketPulse")
    parser.add_argument(
        "--repository",
        choices=["testpypi", "pypi"],
        default="testpypi",
        help="Upload target repository (default: testpypi)",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip building artifacts and use existing dist/ files",
    )
    args = parser.parse_args()

    if not args.skip_build:
        dist = ROOT / "dist"
        if dist.exists():
            shutil.rmtree(dist)
        run([sys.executable, "-m", "pip", "install", "--upgrade", "build", "twine"])
        run([sys.executable, "-m", "build"])

    run([sys.executable, "-m", "twine", "check", "dist/*"])

    if args.repository == "testpypi":
        run([sys.executable, "-m", "twine", "upload", "--repository", "testpypi", "dist/*"])
    else:
        run([sys.executable, "-m", "twine", "upload", "dist/*"])

    print(f"\nDone: published to {args.repository}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
