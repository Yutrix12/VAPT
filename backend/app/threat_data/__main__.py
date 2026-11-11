"""python -m app.threat_data refresh: download the KEV and EPSS data by hand."""

import argparse
import sys

from app.threat_data.files import data_dir
from app.threat_data.refresh import SOURCES, refresh


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m app.threat_data",
        description="Local KEV and EPSS data. The app itself never downloads anything.")
    commands = parser.add_subparsers(dest="command", required=True)
    one = commands.add_parser("refresh", help="download both files into the data folder (uses the network)")
    one.add_argument("--kev-url", default=SOURCES["kev"], help="CISA KEV JSON feed (default: the official one)")
    one.add_argument("--epss-url", default=SOURCES["epss"], help="FIRST EPSS csv.gz (default: the official one)")
    try:
        args = parser.parse_args(argv)
    except SystemExit as stop:  # argparse prints the usage itself; return its code instead of exiting
        return int(stop.code or 0)

    folder = data_dir()
    print(f"Data folder: {folder}")
    results = refresh(folder, kev_url=args.kev_url, epss_url=args.epss_url)
    for result in results:
        print(result.message)
    return 0 if all(result.ok for result in results) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
