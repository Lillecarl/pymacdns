"""The real daemon under load, as a process: nothing installed, no root.

High ports, a TOML resolver pointing at a local fake upstream, and no
resolv.conf or system DNS changes, so this runs in the build sandbox
and fails the build before a broken daemon can be activated.
"""

import os
import sys
from pathlib import Path

import anyio
import dns.message
import dns.rcode
import dns.rrset
import pytest
from test_supervise import ROOT, proc_env, reap, wait_for

from pymacdns.control import control_request

UPSTREAM_PORT = 15531
DAEMON_PORT = 15532
QUERIES = 300
# Long enough that answers to concurrent queries land together.
UPSTREAM_DELAY = 0.1


async def slow_upstream(sock: anyio.abc.UDPSocket) -> None:
    async def answer(data: bytes, host: str, port: int) -> None:
        await anyio.sleep(UPSTREAM_DELAY)
        request = dns.message.from_wire(data)
        response = dns.message.make_response(request)
        response.answer.append(
            dns.rrset.from_text(request.question[0].name, 60, "IN", "A", "192.0.2.1")
        )
        await send(response.to_wire(), host, port)

    lock = anyio.Lock()

    async def send(wire: bytes, host: str, port: int) -> None:
        async with lock:
            await sock.sendto(wire, host, port)

    async with sock, anyio.create_task_group() as tg:
        while True:
            data, (host, port) = await sock.receive()
            tg.start_soon(answer, data, host, port)


async def ask(name: str) -> dns.message.Message:
    sock = await anyio.create_connected_udp_socket("127.0.0.1", DAEMON_PORT)
    async with sock:
        await sock.send(dns.message.make_query(name, "A").to_wire())
        # A crashed server answers nothing; fail on the query, not at
        # the test deadline.
        with anyio.fail_after(2):
            return dns.message.from_wire(await sock.receive())


@pytest.mark.anyio
async def test_daemon_survives_concurrent_load(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text(
        "[[resolver]]\n"
        f'nameservers = ["127.0.0.1:{UPSTREAM_PORT}"]\n'
        "priority = -100\n"
    )
    control_sock = f"/tmp/pmdns-{os.getpid()}-load.sock"
    upstream = await anyio.create_udp_socket(
        local_host="127.0.0.1", local_port=UPSTREAM_PORT
    )
    async with anyio.create_task_group() as tg:
        tg.start_soon(slow_upstream, upstream)
        proc = await anyio.open_process(
            [
                sys.executable,
                "-m",
                "pymacdns",
                "--config",
                str(config),
                "--listen",
                f"127.0.0.1:{DAEMON_PORT}",
                "--socket",
                control_sock,
            ],
            cwd=ROOT,
            env=proc_env(),
        )
        try:
            with anyio.fail_after(30):
                await wait_for(Path(control_sock))
                while (await ask("ready.example.")).rcode() != dns.rcode.NOERROR:
                    await anyio.sleep(0.05)
                before = await control_request(control_sock, {"op": "pid"})
                answers: list[dns.message.Message] = []

                async def one(index: int) -> None:
                    answers.append(await ask(f"load{index}.example."))

                async with anyio.create_task_group() as clients:
                    for index in range(QUERIES):
                        clients.start_soon(one, index)

                assert len(answers) == QUERIES
                rcodes = sorted({dns.rcode.to_text(a.rcode()) for a in answers})
                assert rcodes == ["NOERROR"]
                assert all(
                    [r.address for rr in a.answer for r in rr] == ["192.0.2.1"]
                    for a in answers
                )
                assert proc.returncode is None
                after = await control_request(control_sock, {"op": "pid"})
                assert after["pid"] == before["pid"]
        finally:
            await reap(proc)
            tg.cancel_scope.cancel()
