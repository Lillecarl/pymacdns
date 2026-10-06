from __future__ import annotations

import argparse
import sys

import anyio

from pymacdns import server as server_mod
from pymacdns.config import DEFAULT_CONFIG_PATH, load_config


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pymacdns")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--timeout", type=float, default=None)
    parser.add_argument("--interval", type=float, default=None)
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH)
    parser.add_argument(
        "--no-resolv-conf",
        action="store_true",
        help="do not keep /etc/resolv.conf pointed at us",
    )
    return parser


async def async_main(args: argparse.Namespace) -> None:
    try:
        file_config = load_config(args.config)
    except ValueError as exc:
        print(f"pymacdns: bad config {args.config}: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    await server_mod.run(
        host=args.host or file_config.global_.host,
        port=args.port or file_config.global_.port,
        timeout=args.timeout or file_config.global_.timeout,
        interval=args.interval or file_config.global_.interval,
        manage_resolv_conf=not args.no_resolv_conf,
        config_path=args.config,
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
