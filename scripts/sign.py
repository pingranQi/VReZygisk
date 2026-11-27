#!/usr/bin/env python3
"""Generate per-file SHA-256 integrity sidecars for the installer's extract() checks.

This repository does not currently consume or verify the legacy Ed25519
machikado/misaki signatures. Do not emit decorative, unverifiable signatures.
The hashes detect accidental corruption only; they are not an authenticity
mechanism because the hashes are shipped inside the same ZIP archive.
"""

import hashlib
import os
import sys
from pathlib import Path


def compute_sha256_hashes(module_dir: str) -> None:
    root = Path(module_dir)
    if not root.is_dir():
        raise NotADirectoryError(module_dir)

    for file_path in sorted(root.rglob("*")):
        if not file_path.is_file() or file_path.name.endswith(".sha256"):
            continue

        digest = hashlib.sha256()
        with file_path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)

        sidecar = Path(str(file_path) + ".sha256")
        temporary = Path(str(sidecar) + ".tmp")
        temporary.write_text(digest.hexdigest() + "\n", encoding="ascii")
        os.replace(temporary, sidecar)


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] != "--hash-only":
        print("Usage: sign.py --hash-only <module_dir>", file=sys.stderr)
        return 2

    try:
        compute_sha256_hashes(sys.argv[2])
    except (OSError, ValueError) as error:
        print(f"Failed to generate SHA-256 sidecars: {error}", file=sys.stderr)
        return 1

    print("Generated per-file SHA-256 sidecars (integrity only; no signatures).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
