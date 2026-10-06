from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from pymacdns.resolver import _split_hostport

DEFAULT_CONFIG_PATH: Final = "/etc/pymacdns/config.toml"
DEFAULT_HOST: Final = "127.0.0.1"
DEFAULT_PORT: Final = 53
DEFAULT_TIMEOUT: Final = 2.0
DEFAULT_INTERVAL: Final = 1.0


@dataclass(frozen=True)
class ResolverRule:
    domain: str  # "" is the catch-all, lowercased, no trailing dot
    nameservers: tuple[str, ...]
    priority: int = 0


@dataclass(frozen=True)
class GlobalConfig:
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    timeout: float = DEFAULT_TIMEOUT
    interval: float = DEFAULT_INTERVAL


@dataclass(frozen=True)
class FileConfig:
    global_: GlobalConfig = GlobalConfig()
    resolvers: tuple[ResolverRule, ...] = ()


def normalize_domain(domain: object) -> str:
    if not isinstance(domain, str):
        raise ValueError(f"domain must be a string, got {domain!r}")
    return domain.strip().lower().rstrip(".")


def parse_global(data: object) -> GlobalConfig:
    if data is None:
        return GlobalConfig()
    if not isinstance(data, dict):
        raise ValueError(f"[global] must be a table, got {data!r}")
    host, port = DEFAULT_HOST, DEFAULT_PORT
    if "listen" in data:
        listen = data["listen"]
        if not isinstance(listen, str):
            raise ValueError(f"[global] listen must be a string, got {listen!r}")
        host, port = _split_hostport(listen)
    timeout = _number(data.get("timeout"), DEFAULT_TIMEOUT, "[global] timeout")
    interval = _number(data.get("interval"), DEFAULT_INTERVAL, "[global] interval")
    return GlobalConfig(host=host, port=port, timeout=timeout, interval=interval)


def _number(value: object, default: float, what: str) -> float:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{what} must be a number, got {value!r}")
    return float(value)


def parse_resolver(data: object) -> ResolverRule:
    if not isinstance(data, dict):
        raise ValueError(f"[[resolver]] must be a table, got {data!r}")
    nameservers = data.get("nameservers")
    if (
        not isinstance(nameservers, list)
        or not nameservers
        or any(not isinstance(ns, str) for ns in nameservers)
    ):
        raise ValueError(
            "[[resolver]] needs a non-empty nameservers string list, "
            f"got {nameservers!r}"
        )
    priority = data.get("priority", 0)
    if isinstance(priority, bool) or not isinstance(priority, int):
        raise ValueError(f"[[resolver]] priority must be an integer, got {priority!r}")
    return ResolverRule(
        domain=normalize_domain(data.get("domain", "")),
        nameservers=tuple(nameservers),
        priority=priority,
    )


def parse_config(text: str) -> FileConfig:
    """Parse TOML config text. Pure function, raises ValueError on bad input."""
    data = tomllib.loads(text)
    if not isinstance(data, dict):
        raise ValueError("config root must be a table")
    resolvers = data.get("resolver", [])
    if not isinstance(resolvers, list):
        raise ValueError(f"[[resolver]] must be a list, got {resolvers!r}")
    return FileConfig(
        global_=parse_global(data.get("global")),
        resolvers=tuple(parse_resolver(entry) for entry in resolvers),
    )


def load_config(path: str | Path) -> FileConfig:
    """Load config from path; missing file means system-discovered only."""
    target = Path(path)
    if not target.is_file():
        return FileConfig()
    return parse_config(target.read_text())
