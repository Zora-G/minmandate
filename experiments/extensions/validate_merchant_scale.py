#!/usr/bin/env python3
"""Validate and merge all 32 frozen E6 merchant-scale shards."""

from __future__ import annotations

import argparse
from pathlib import Path

from experiments.extensions.merchant_scale import (
    DEFAULT_RESULT_ROOT,
    ROOT,
    validate_and_merge,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument(
        "--shards-root",
        type=Path,
        default=DEFAULT_RESULT_ROOT / "shards",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_RESULT_ROOT / "merged",
    )
    args = parser.parse_args()
    return validate_and_merge(args)


if __name__ == "__main__":
    raise SystemExit(main())
