# pymacdns

macOS DNS forwarder (Python port of
[greenboxal/dns-heaven](https://github.com/greenboxal/dns-heaven)).

Listens on `127.0.0.1:53`, polls `scutil --dns` for DHCP-provided
upstreams, and forwards with per-domain split-DNS routing.

## Layout

- `src/pymacdns/scutil.py` — pure `scutil --dns` parsing + upstream selection
- `src/pymacdns/resolver.py` — split-DNS routing + upstream forwarding
- `src/pymacdns/server.py` — anyio UDP + TCP DNS server
