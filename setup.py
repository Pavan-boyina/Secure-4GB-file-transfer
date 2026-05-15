#!/usr/bin/env python3
"""
Setup script: generates keys, certificates, and optionally a test file.

Usage:
    python setup.py              # Generate keys only
    python setup.py --test-file  # Generate keys + 4 GB test file
    python setup.py --small-test # Generate keys + 64 MB test file (for quick testing)
"""

import sys
import os
import argparse
import hashlib

sys.path.insert(0, os.path.dirname(__file__))

from shared.keygen import setup_approach_a_keys, setup_approach_b_keys
from shared.utils import compute_file_sha256, CHUNK_SIZE


def generate_test_file(path: str, size_bytes: int):
    """Generate a test file of the specified size using /dev/urandom or os.urandom."""
    from shared.utils import format_bytes
    print(f"\n[…] Generating test file: {path} ({format_bytes(size_bytes)})")

    written = 0
    block_size = 1024 * 1024  # 1 MB blocks
    with open(path, "wb") as f:
        while written < size_bytes:
            remaining = size_bytes - written
            block = os.urandom(min(block_size, remaining))
            f.write(block)
            written += len(block)
            if written % (100 * 1024 * 1024) == 0:
                pct = written / size_bytes * 100
                print(f"  {pct:.0f}% ({written // (1024*1024)} MB)", flush=True)

    print(f"[✓] Test file created: {path}")

    print("[…] Computing SHA-256 of test file...")
    h = compute_file_sha256(path)
    print(f"    SHA-256: {h}")

    # Save hash to a sidecar file for easy verification later
    with open(path + ".sha256", "w") as f:
        f.write(f"{h}  {os.path.basename(path)}\n")
    print(f"    Hash saved to {path}.sha256")


def main():
    parser = argparse.ArgumentParser(description="Setup keys and test files")
    parser.add_argument("--test-file", action="store_true", help="Generate 4 GB test file")
    parser.add_argument("--small-test", action="store_true", help="Generate 64 MB test file (quick)")
    parser.add_argument("--tiny-test", action="store_true", help="Generate 1 MB test file (dev)")
    args = parser.parse_args()

    print("=" * 60)
    print("  Secure File Transfer — Setup")
    print("=" * 60)

    # Generate keys for both approaches
    print("\n--- Approach A: mTLS Keys & Certificates ---")
    setup_approach_a_keys("keys-a")

    print("\n--- Approach B: Signing Keys & PSK ---")
    setup_approach_b_keys("keys-b")

    # Generate test file if requested
    if args.test_file:
        generate_test_file("test_4gb.bin", 4 * 1024 * 1024 * 1024)
    elif args.small_test:
        generate_test_file("test_64mb.bin", 64 * 1024 * 1024)
    elif args.tiny_test:
        generate_test_file("test_1mb.bin", 1 * 1024 * 1024)

    print("\n" + "=" * 60)
    print("  Setup complete! See README.md for usage instructions.")
    print("=" * 60)


if __name__ == "__main__":
    main()
