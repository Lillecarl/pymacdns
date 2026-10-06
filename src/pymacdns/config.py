from __future__ import annotations

import tomllib
from contextvars import ContextVar
from pathlib import Path
from typing import Annotated, Final, Self

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StrictInt,
    field_validator,
)
from pydantic_settings import (
    BaseSettings,
    SettingsConfigDict,
    TomlConfigSettingsSource,
)

from pymacdns.resolver import _split_hostport
from pymacdns.routes import RouteFilter

DEFAULT_CONFIG_PATH: Final = "/etc/pymacdns/config.toml"
DEFAULT_CONTROL_SOCKET: Final = "/var/run/pymacdns.sock"
DEFAULT_LISTEN: Final = ["127.0.0.1:53", "[::1]:53"]
DEFAULT_TIMEOUT: Final = 2.0
DEFAULT_INTERVAL: Final = 1.0

_toml_path: ContextVar[str | None] = ContextVar("pymacdns_toml_path", default=None)


def normalize_domain(domain: object) -> str:
    if not isinstance(domain, str):
        raise ValueError(f"domain must be a string, got {domain!r}")
    return domain.strip().lower().rstrip(".")


def parse_listen(value: object) -> tuple[tuple[str, int], ...]:
    """Accept one "host:port" string or a list of them."""
    items = [value] if isinstance(value, str) else value
    if not isinstance(items, list) or not items:
        raise ValueError(
            f"[server] listen must be a string or non-empty list, got {value!r}"
        )
    parsed = []
    for item in items:
        if not isinstance(item, str):
            raise ValueError(f"[server] listen entries must be strings, got {item!r}")
        parsed.append(_split_hostport(item))
    return tuple(parsed)


ListenAddresses = Annotated[
    tuple[tuple[str, int], ...], BeforeValidator(parse_listen)
]


def format_listen(host: str, port: int) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]:{port}"
    return f"{host}:{port}"


class ResolverRule(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    domain: str = ""
    nameservers: list[str] = Field(min_length=1)
    priority: StrictInt = 0

    @field_validator("domain")
    @classmethod
    def _normalize_domain(cls, value: str) -> str:
        return normalize_domain(value)


class GlobalConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    listen: ListenAddresses = parse_listen(DEFAULT_LISTEN)
    timeout: float = DEFAULT_TIMEOUT
    interval: float = DEFAULT_INTERVAL
    route_filter: RouteFilter = RouteFilter.OFF
    control_socket: str = DEFAULT_CONTROL_SOCKET
    marker_file: str | None = None
    resolv_conf: str | None = None


class FileConfig(BaseModel):
    """The on-disk TOML schema, also used to validate dump output."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    server: GlobalConfig = Field(default_factory=GlobalConfig)
    resolver: list[ResolverRule] = Field(default_factory=list)


class DaemonSettings(BaseSettings):
    """Effective settings: CLI init kwargs beat env, env beats TOML file."""

    model_config = SettingsConfigDict(
        env_prefix="pymacdns_",
        env_nested_delimiter="__",
        extra="forbid",
        populate_by_name=True,
    )

    server: GlobalConfig = Field(default_factory=GlobalConfig)
    resolver: list[ResolverRule] = Field(default_factory=list)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: object,
        env_settings: object,
        dotenv_settings: object,
        file_secret_settings: object,
    ) -> tuple[object, ...]:
        path = _toml_path.get()
        if path is None:
            return (init_settings, env_settings)
        return (
            init_settings,
            env_settings,
            TomlConfigSettingsSource(settings_cls, toml_file=path),
        )

    @classmethod
    def load(cls, toml_path: str | Path) -> Self:
        token = _toml_path.set(str(toml_path))
        try:
            return cls()
        finally:
            _toml_path.reset(token)


def parse_config(text: str) -> FileConfig:
    """Parse TOML config text, raising pydantic.ValidationError on bad input."""
    return FileConfig.model_validate(tomllib.loads(text))


def load_config(path: str | Path) -> FileConfig:
    """Load config from path; a missing file means system-discovered only."""
    target = Path(path)
    if not target.is_file():
        return FileConfig()
    return parse_config(target.read_text())
