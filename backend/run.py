"""
PredictiveAttackPath — Entry Point

Usage:
    python run.py                   # Start API server
    python run.py --download-only   # Download MITRE data without starting server
    python run.py --port 9000       # Custom port
"""

import argparse
import sys

import uvicorn

from config import API_HOST, API_PORT


def main():
    parser = argparse.ArgumentParser(
        description="Predictive Attack Path — Intelligence Engine"
    )
    parser.add_argument(
        "--host", default=API_HOST, help=f"Bind host (default: {API_HOST})"
    )
    parser.add_argument(
        "--port", type=int, default=API_PORT, help=f"Bind port (default: {API_PORT})"
    )
    parser.add_argument(
        "--reload", action="store_true", help="Enable auto-reload for development"
    )
    parser.add_argument(
        "--download-only",
        action="store_true",
        help="Download MITRE data and exit",
    )
    parser.add_argument(
        "--force-download",
        action="store_true",
        help="Force re-download of MITRE data even if cached",
    )

    args = parser.parse_args()

    if args.download_only or args.force_download:
        from mitre_data_loader import MitreDataLoader

        loader = MitreDataLoader()
        dataset = loader.load(force_download=args.force_download)
        print(f"Downloaded: {len(dataset.techniques)} techniques, "
              f"{len(dataset.groups)} groups")
        if args.download_only:
            sys.exit(0)

    print(f"\n{'=' * 60}")
    print(f"  Predictive Attack Path — Intelligence Engine")
    print(f"  Starting on http://{args.host}:{args.port}")
    print(f"  API docs at http://{args.host}:{args.port}/docs")
    print(f"{'=' * 60}\n")

    uvicorn.run(
        "intelligence_engine:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )


if __name__ == "__main__":
    main()
