# pymacdns

macOS DNS forwarder (Python port of
[greenboxal/dns-heaven](https://github.com/greenboxal/dns-heaven)).

Listens on `127.0.0.53:53` and `[::1]:53` by default (either stack may
fail as long as one binds), reads upstreams from SCDynamicStore with
change notifications plus `/etc/resolver/*` files, merges in TOML
config by priority, and forwards over UDP and TCP.

## Layout

- `src/pymacdns/store.py` — system state snapshot + change notifications + `dump`
- `src/pymacdns/config.py` — pydantic TOML/env settings and validation
- `src/pymacdns/resolver.py` — split-DNS routing + upstream forwarding
- `src/pymacdns/server.py` — anyio UDP + TCP DNS server
