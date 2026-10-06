from __future__ import annotations

import argparse
import sys

import anyio

from pymacdns import server as server_mod
from pymacdns.resolver import DEFAULT_TIMEOUT


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pymacdns")
    parser.add_argument("--host", default=server_mod.DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=server_mod.DEFAULT_PORT)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--interval", type=float, default=server_mod.DEFAULT_INTERVAL)
    parser.add_argument(
        "--no-resolv-conf",
        action="store_true",
        help="do not keep /etc/resolv.conf pointed at us",
    )
    return parser


async def async_main(args: argparse.Namespace) -> None:
    await server_mod.run(
        host=args.host,
        port=args.port,
        timeout=args.timeout,
        interval=args.interval,
        manage_resolv_conf=not args.no_resolv_conf,
    )


def main() -> None:
    args = build_parser().parse_args()
    try:
        anyio.run(async_main, args)
    except KeyboardInterrupt:
        pass


def main_sync() -> None:
    """Console-script entry point."""
    sys.exit(main() or 0)


if __name__ == "__main__":
    main()
