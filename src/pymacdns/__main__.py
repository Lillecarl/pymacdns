from __future__ import annotations

import argparse
import sys

import anyio
from pydantic import ValidationError

from pymacdns import server as server_mod
from pymacdns.config import DEFAULT_CONFIG_PATH, DaemonSettings, parse_listen
from pymacdns.control import control_request
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
        "--socket",
        default=None,
        help="control socket path (overrides config file)",
    )
    parser.add_argument(
        "--no-resolv-conf",
        action="store_true",
        help="do not keep /etc/resolv.conf pointed at us",
    )
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("dump", help="print live macOS resolvers as TOML")
    cache_parser = sub.add_parser("cache", help="inspect the daemon cache")
    cache_sub = cache_parser.add_subparsers(dest="cache_op", required=True)
    cache_sub.add_parser("list", help="list cached entries")
    cache_sub.add_parser("clear", help="drop all cached entries")
    remove_parser = cache_sub.add_parser("remove", help="drop cached entries")
    remove_parser.add_argument("name", help="owner name, e.g. example.com.")
    remove_parser.add_argument(
        "--type", default="ANY", help="record type (default ANY, matches all)"
    )
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
    if args.socket is not None:
        updates["control_socket"] = args.socket
    if updates:
        settings = settings.model_copy(
            update={"server": settings.server.model_copy(update=updates)}
        )
    return settings


def socket_path(args: argparse.Namespace) -> str:
    if args.socket is not None:
        return args.socket
    return load_settings(args).server.control_socket


async def cache_main(args: argparse.Namespace) -> int:
    path = socket_path(args)
    if args.cache_op == "list":
        payload: dict[str, object] = {"op": "list"}
    elif args.cache_op == "clear":
        payload = {"op": "clear"}
    else:
        payload = {"op": "remove", "name": args.name, "qtype": args.type}
    try:
        reply = await control_request(path, payload)
    except OSError as exc:
        print(f"pymacdns: cannot reach daemon at {path}: {exc}", file=sys.stderr)
        return 1
    if "error" in reply:
        print(f"pymacdns: {reply['error']}", file=sys.stderr)
        return 1
    if args.cache_op == "list":
        entries = reply.get("entries", [])
        print(f"{'NAME':<40} {'TYPE':<6} {'AGE':>8} {'TTL':>8} {'HITS':>6}")
        for entry in entries:  # type: ignore[union-attr]
            ttl = entry["ttl_left_s"]
            state = "STALE" if entry["dead"] else f"{ttl}s"
            print(
                f"{entry['name']:<40} {entry['qtype']:<6} "
                f"{entry['age_s']:>8} {state:>8} {entry['records']:>6}"
            )
    elif args.cache_op == "clear":
        print(f"cleared {reply.get('cleared', 0)} entries")
    else:
        print(f"removed {reply.get('removed', 0)} entries")
    return 0


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
    if args.command == "cache":
        try:
            code = anyio.run(cache_main, args)
        except KeyboardInterrupt:
            return
        sys.exit(code)
    try:
        anyio.run(async_main, args)
    except KeyboardInterrupt:
        pass


def main_sync() -> None:
    """Console-script entry point."""
    sys.exit(main() or 0)


if __name__ == "__main__":
    main()
