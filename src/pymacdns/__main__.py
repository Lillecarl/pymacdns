from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
from typing import Final

import anyio
import httpx
from pydantic import ValidationError

from pymacdns import installer as installer_mod
from pymacdns import latency as latency_mod
from pymacdns import server as server_mod
from pymacdns import status as status_mod
from pymacdns import store as store_mod
from pymacdns.config import DEFAULT_CONFIG_PATH, DaemonSettings, parse_listen
from pymacdns.control import Lifecycle, control_request
from pymacdns.store import dump_toml
from pymacdns.supervise import run_supervised


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
        "--socket-group",
        default=None,
        help="group allowed onto the control socket (overrides config file)",
    )
    parser.add_argument(
        "--marker-file",
        default=None,
        help="maintain this file while running (overrides config file)",
    )
    parser.add_argument(
        "--resolv-conf",
        default=None,
        help="manage this resolv.conf while running (dummy path for tests)",
    )
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("dump", help="print live macOS resolvers as TOML")
    sub.add_parser(
        "status", help="probe effective upstreams across names and types"
    )
    sub.add_parser("latency", help="show in-memory upstream latency buckets")
    sub.add_parser(
        "nuke",
        help="remove every DNS setting pymacdns installs and flush caches (root)",
    )
    sub.add_parser(
        "restore", help="have a daemon released by nuke install its settings again"
    )
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
    if args.socket_group is not None:
        updates["control_socket_group"] = args.socket_group
    if args.marker_file is not None:
        updates["marker_file"] = args.marker_file
    if args.resolv_conf is not None:
        updates["resolv_conf"] = args.resolv_conf
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


async def latency_main(args: argparse.Namespace) -> int:
    path = socket_path(args)
    try:
        reply = await control_request(path, {"op": "latency"})
    except OSError as exc:
        print(f"pymacdns: cannot reach daemon at {path}: {exc}", file=sys.stderr)
        return 1
    if "error" in reply:
        print(f"pymacdns: {reply['error']}", file=sys.stderr)
        return 1
    summary = reply.get("latency", {})
    if not summary:
        print("pymacdns: no observations yet")
        return 0
    print(
        latency_mod.format_table(
            [
                latency_mod.UpstreamSummary(
                    nameserver=ns,
                    count=row["count"],
                    errors=row["errors"],
                    mean_ms=row["mean_ms"],
                    p50_ms=row["p50_ms"],
                    p95_ms=row["p95_ms"],
                    p99_ms=row["p99_ms"],
                )
                for ns, row in sorted(summary.items())
            ]
        )
    )
    return 0


async def status_main(args: argparse.Namespace) -> int:
    settings = load_settings(args)
    self_hosts = {host for host, _ in settings.server.listen}
    try:
        snap = store_mod.snapshot_once(
            settings.server.timeout, self_hosts, args.config
        )
    except Exception as exc:  # noqa: BLE001 - report, don't trace
        print(f"pymacdns: cannot read resolvers: {exc}", file=sys.stderr)
        return 1
    targets = status_mod.describe_targets(snap)
    if not targets:
        print("pymacdns: no upstreams discovered", file=sys.stderr)
        return 1
    # One shared client like the daemon's: status then measures the
    # pooled steady state instead of nine cold handshakes per upstream.
    async with httpx.AsyncClient(http2=True) as client:
        rows = await status_mod.check(
            targets, settings.server.timeout, doh_client=client
        )
    print(status_mod.render(rows))
    print(
        f"{len(rows)} upstreams, {len(status_mod.PROBES)} probes, "
        f"timeout {settings.server.timeout}s"
    )
    return 0


def installers_for(settings: DaemonSettings) -> list[installer_mod.Installer]:
    installers: list[installer_mod.Installer] = []
    if settings.server.marker_file is not None:
        installers.append(
            installer_mod.FileMarker(path=settings.server.marker_file)
        )
    if settings.server.resolv_conf is not None:
        installers.append(
            installer_mod.ResolvConf(
                path=settings.server.resolv_conf,
                nameservers=[host for host, _ in settings.server.listen],
            )
        )
    if settings.server.system_dns:
        installers.append(
            installer_mod.SystemDns(listen=list(settings.server.listen))
        )
    return installers


def nuke_main(args: argparse.Namespace) -> int:
    """Remove everything any pymacdns run may have installed."""
    if os.geteuid() != 0:
        print("pymacdns: nuke needs root", file=sys.stderr)
        return 1
    # A broken config must not stop the cleanup it is meant to recover from.
    try:
        settings = load_settings(args)
    except SystemExit:
        settings = DaemonSettings()
    # First, so a running daemon stops restoring what we remove below.
    released = "released" in ask_daemon(settings.server.control_socket, "release")
    if released:
        print("daemon released its settings")
    targets = installer_mod.nuke_targets(installers_for(settings))
    failed = False
    for target in targets:
        try:
            target.cleanup()
        except Exception as exc:  # noqa: BLE001 - report it, clean the rest
            print(f"pymacdns: cleanup failed: {target}: {exc}", file=sys.stderr)
            failed = True
        else:
            print(f"cleaned {target}")
    for command in FLUSH_COMMANDS:
        result = subprocess.run(command, check=False)
        if result.returncode != 0:
            print(f"pymacdns: {' '.join(command)} exited {result.returncode}",
                  file=sys.stderr)
            failed = True
    if released:
        print(
            "pymacdns: the daemon still answers on its listen addresses; "
            "`pymacdns restore` or a daemon restart installs again",
            file=sys.stderr,
        )
    return 1 if failed else 0


CONTROL_TIMEOUT: Final = 5.0
FLUSH_COMMANDS: Final = (
    ("/usr/bin/dscacheutil", "-flushcache"),
    ("/usr/bin/killall", "-HUP", "mDNSResponder"),
)


def ask_daemon(path: str, op: str) -> dict[str, object]:
    """One control request; {"error": ...} when the daemon cannot answer.

    Synchronous with a timeout: a wedged daemon must not hang the
    cleanup that is meant to recover from it.
    """
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(CONTROL_TIMEOUT)
        try:
            sock.connect(path)
            sock.sendall((json.dumps({"op": op}) + "\n").encode())
            data = b""
            while chunk := sock.recv(4096):
                data += chunk
            reply = json.loads(data)
        except (OSError, ValueError) as exc:
            return {"error": f"no answer from {path}: {exc}"}
    return reply if isinstance(reply, dict) else {"error": "bad reply"}


def restore_main(args: argparse.Namespace) -> int:
    """Have a released daemon install its settings again."""
    reply = ask_daemon(socket_path(args), "restore")
    if "restored" in reply:
        print("daemon settings installed")
        return 0
    print(f"pymacdns: {reply.get('error')}", file=sys.stderr)
    return 1


def serve_main(args: argparse.Namespace) -> int:
    settings = load_settings(args)
    installers = installers_for(settings)

    async def child_main(lifecycle: Lifecycle) -> None:
        await server_mod.run(settings, config_path=args.config, lifecycle=lifecycle)

    try:
        return run_supervised(installers, child_main)
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        return 1


def main() -> None:
    args = build_parser().parse_args()
    if args.command == "dump":
        sys.stdout.write(dump_toml())
        return
    if args.command == "status":
        try:
            code = anyio.run(status_main, args)
        except KeyboardInterrupt:
            return
        sys.exit(code)
    if args.command == "latency":
        try:
            code = anyio.run(latency_main, args)
        except KeyboardInterrupt:
            return
        sys.exit(code)
    if args.command == "cache":
        try:
            code = anyio.run(cache_main, args)
        except KeyboardInterrupt:
            return
        sys.exit(code)
    if args.command == "nuke":
        sys.exit(nuke_main(args))
    if args.command == "restore":
        sys.exit(restore_main(args))
    # Forks here, before any thread or event loop exists.
    try:
        code = serve_main(args)
    except KeyboardInterrupt:
        return
    sys.exit(code)


def main_sync() -> None:
    """Console-script entry point."""
    sys.exit(main() or 0)


if __name__ == "__main__":
    main()
