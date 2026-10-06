from __future__ import annotations

import argparse
import sys

import anyio
from pydantic import ValidationError

from pymacdns import server as server_mod
from pymacdns.config import DEFAULT_CONFIG_PATH, DaemonSettings, parse_listen
from pymacdns.store import dump_toml


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pymacdns")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH)
    parser.add_argument(
        "--listen",
        action="append",
        default=None,
        help='"host:port" to listen on, repeatable (overrides config file)',
    )
    parser.add_argument("--timeout", type=float, default=None)
    parser.add_argument("--interval", type=float, default=None)
    parser.add_argument(
        "--no-resolv-conf",
        action="store_true",
        help="do not keep /etc/resolv.conf pointed at us",
    )
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("dump", help="print live macOS resolvers as TOML")
    return parser


def load_settings(args: argparse.Namespace) -> DaemonSettings:
    try:
        settings = DaemonSettings.load(args.config)
    except (ValidationError, ValueError) as exc:
        print(f"pymacdns: bad config {args.config}: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    updates = {}
    if args.listen is not None:
        try:
            updates["listen"] = parse_listen(args.listen)
        except ValueError as exc:
            print(f"pymacdns: bad --listen: {exc}", file=sys.stderr)
            raise SystemExit(2) from exc
    if args.timeout is not None:
        updates["timeout"] = args.timeout
    if args.interval is not None:
        updates["interval"] = args.interval
    if updates:
        settings = settings.model_copy(
            update={"server": settings.server.model_copy(update=updates)}
        )
    return settings


async def async_main(args: argparse.Namespace) -> None:
    settings = load_settings(args)
    try:
        await server_mod.run(
            settings,
            config_path=args.config,
            manage_resolv_conf=not args.no_resolv_conf,
        )
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        raise SystemExit(1) from exc


def main() -> None:
    args = build_parser().parse_args()
    if args.command == "dump":
        sys.stdout.write(dump_toml())
        return
    try:
        anyio.run(async_main, args)
    except KeyboardInterrupt:
        pass


def main_sync() -> None:
    """Console-script entry point."""
    sys.exit(main() or 0)


if __name__ == "__main__":
    main()
