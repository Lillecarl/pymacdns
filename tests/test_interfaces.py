import anyio
import dns.message
import pytest
from helpers import free_port

from pymacdns.config import parse_config
from pymacdns.interfaces import select_addresses
from pymacdns.server import DnsState, serve_interfaces

INTERVAL = 0.05


def test_select_addresses():
    entries = {
        "bridge100": [
            "192.168.64.1",
            "fe80::fcb2:14ff:fe3c:1764",
            "fd34:1b05:c77e:b6d4::1",
        ],
        "en0": ["10.0.0.5"],
        "bridge101": ["not an address"],
    }
    assert select_addresses(entries, ["bridge*"]) == {
        "192.168.64.1",
        "fe80::fcb2:14ff:fe3c:1764%bridge100",
        "fd34:1b05:c77e:b6d4::1",
    }
    assert select_addresses(entries, ["en0"]) == {"10.0.0.5"}
    assert select_addresses(entries, []) == set()


def test_listen_interfaces_config():
    assert parse_config("").server.listen_interfaces == ()
    config = parse_config('[server]\nlisten_interfaces = ["bridge*:53", "utun3"]\n')
    assert config.server.listen_interfaces == (("bridge*", 53), ("utun3", 53))


async def answered(port: int) -> bool:
    wire = dns.message.make_query("example.com", "A").to_wire()
    try:
        async with await anyio.connect_tcp("127.0.0.1", port) as stream:
            await stream.send(len(wire).to_bytes(2, "big") + wire)
            with anyio.fail_after(2):
                header = await stream.receive(2)
            return len(header) == 2
    except OSError:
        return False


@pytest.mark.anyio
async def test_serve_interfaces_follows_addresses():
    port = free_port()
    table = {"lo0": ["127.0.0.1"]}

    async def until(expected: bool) -> None:
        with anyio.fail_after(5):
            while await answered(port) != expected:
                await anyio.sleep(INTERVAL)

    async with anyio.create_task_group() as tg:
        tg.start_soon(
            serve_interfaces,
            (("lo*", port),),
            DnsState(),
            INTERVAL,
            lambda: table,
        )
        await until(True)
        table = {}
        await until(False)
        table = {"lo0": ["127.0.0.1"]}
        await until(True)
        tg.cancel_scope.cancel()
