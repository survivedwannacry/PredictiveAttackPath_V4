#!/usr/bin/env python3
"""
Standalone script to download MITRE ATT&CK STIX data.

Usage:
    python scripts/download_mitre_data.py
    python scripts/download_mitre_data.py --force
"""
import argparse
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from mitre_data_loader import MitreDataLoader


def main():
    parser = argparse.ArgumentParser(
        description="Download MITRE ATT&CK Enterprise STIX data"
    )
    parser.add_argument(
        "--force", action="store_true", help="Force re-download"
    )
    args = parser.parse_args()

    loader = MitreDataLoader()
    dataset = loader.load(force_download=args.force)

    print(f"\n{'─' * 50}")
    print(f"  Techniques loaded:  {len(dataset.techniques)}")
    print(f"  Groups loaded:      {len(dataset.groups)}")
    print(f"  Tactics covered:    {len(dataset.tactic_techniques)}")
    print(f"{'─' * 50}")

    # Show top groups by technique count
    groups_sorted = sorted(
        dataset.groups.values(),
        key=lambda g: len(g.technique_ids),
        reverse=True,
    )
    print("\nTop 10 groups by technique count:")
    for g in groups_sorted[:10]:
        aliases = ", ".join(g.aliases[:3]) if g.aliases else "—"
        print(f"  {g.group_id:8s} {g.name:20s} ({len(g.technique_ids):3d} techniques)  [{aliases}]")


if __name__ == "__main__":
    main()
