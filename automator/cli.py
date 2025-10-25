from __future__ import annotations

import argparse
import shlex
import sys
from pathlib import Path
from typing import Sequence

from .scanner import Automator, ScanError, ScanOptions


SCAN_CHOICES = [
    "Network",
    "Port",
    "Script",
    "Full",
    "UDP",
    "Vulns",
    "Recon",
    "All",
]


def parse_extra(extra: str | None) -> Sequence[str]:
    if not extra:
        return ()
    return tuple(shlex.split(extra))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Python port of nmapAutomator: automate your recon workflow.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-H", "--host", required=True, help="Target host or IP")
    parser.add_argument(
        "-t",
        "--type",
        required=True,
        choices=[choice.lower() for choice in SCAN_CHOICES]
        + [choice.upper() for choice in SCAN_CHOICES]
        + SCAN_CHOICES,
        help="Scan profile to run",
    )
    parser.add_argument("-d", "--dns", help="Use the supplied DNS server for lookups")
    parser.add_argument(
        "-o",
        "--output",
        help="Directory where results will be stored (default: ./<host>)",
    )
    parser.add_argument(
        "-c",
        "--custom-output",
        help="Optional sub-directory name inside --output (useful for engagements)",
    )
    parser.add_argument(
        "-s",
        "--static-nmap",
        help="Path to a static nmap binary if the system one is missing",
    )
    parser.add_argument(
        "-r",
        "--remote",
        action="store_true",
        help="Remote mode (POSIX only, limited functionality)",
    )
    parser.add_argument(
        "--extra",
        help="Additional CLI arguments passed directly to nmap (quoted string)",
    )
    parser.add_argument(
        "--run-recon",
        action="store_true",
        help="Automatically execute recon commands when available",
    )
    parser.add_argument(
        "--notes",
        help="Optional description stored alongside the scan (not used by CLI, surfaced in UI)",
    )
    parser.add_argument(
        "--scanners",
        nargs="*",
        help="List of recon scanners to run after the main scan (e.g. sslscan nikto)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    output_dir = (
        Path(args.output).expanduser()
        if args.output
        else Path.cwd() / args.host.replace("/", "_")
    )

    scan_type = args.type
    lowered = scan_type.lower()
    if lowered == "quick":
        scan_type = "Port"
    elif lowered == "basic":
        scan_type = "Script"

    options = ScanOptions(
        host=args.host,
        scan_type=scan_type,
        dns_server=args.dns,
        output_dir=output_dir,
        static_nmap=args.static_nmap,
        remote_mode=args.remote,
        custom_output_name=args.custom_output,
        extra_args=parse_extra(args.extra),
        run_recon_commands=args.run_recon,
        notes=args.notes,
        selected_scanners=args.scanners or (),
    )

    try:
        Automator(options).run()
    except ScanError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
