"""The real daemon under load, as a process: nothing installed, no root.

Free loopback ports, a TOML resolver pointing at a local fake upstream, and no
resolv.conf or system DNS changes, so this runs in the build sandbox
and fails the build before a broken daemon can be activated.
"""

import sys
from pathlib import Path

import anyio
import dns.message
import dns.rcode
import dns.rrset
import pytest
from helpers import free_port
from test_supervise import ROOT, proc_env, reap, wait_for

from pymacdns.control import control_request

QUERIES = 300
# Long enough that answers to concurrent queries land together.
UPSTREAM_DELAY = 0.1
ATTEMPTS = 3
ATTEMPT_TIMEOUT = 1.0


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


async def ask(port: int, name: str) -> dns.message.Message:
    """A NOERROR answer, resending like a real resolver.

    Loopback UDP drops datagrams under the 300-query burst in the nix
    sandbox, so one lost datagram is not a failure. A crashed server
    still is: it answers no attempt. Raises TimeoutError then.
    """
    wire = dns.message.make_query(name, "A").to_wire()
    sock = await anyio.create_connected_udp_socket("127.0.0.1", port)
    async with sock:
        for _ in range(ATTEMPTS):
            await sock.send(wire)
            with anyio.move_on_after(ATTEMPT_TIMEOUT):
                reply = dns.message.from_wire(await sock.receive())
                if reply.rcode() == dns.rcode.NOERROR:
                    return reply
    raise TimeoutError(name)


@pytest.mark.anyio
async def test_daemon_survives_concurrent_load(
    tmp_path: Path, sock_dir: Path
) -> None:
    upstream_port, daemon_port = free_port(), free_port()
    config = tmp_path / "config.toml"
    config.write_text(
        "[[resolver]]\n"
        f'nameservers = ["127.0.0.1:{upstream_port}"]\n'
        "priority = -100\n"
    )
    control_sock = str(sock_dir / "ctl.sock")
    upstream = await anyio.create_udp_socket(
        local_host="127.0.0.1", local_port=upstream_port
    )
    # A file, not a pipe: nobody reads a pipe here, and a full one blocks
    # the daemon on its next write to stderr.
    log_path = tmp_path / "daemon.log"
    log = log_path.open("wb")
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
                f"127.0.0.1:{daemon_port}",
                "--socket",
                control_sock,
            ],
            cwd=ROOT,
            env=proc_env(),
            stdout=log,
            stderr=log,
        )
        try:
            with anyio.fail_after(30):
                await wait_for(Path(control_sock))
                while True:
                    try:
                        await ask(daemon_port, "ready.example.")
                        break
                    except TimeoutError:
                        await anyio.sleep(0.05)
                before = await control_request(control_sock, {"op": "pid"})
                answers: list[dns.message.Message] = []
                lost = 0

                async def one(index: int) -> None:
                    nonlocal lost
                    try:
                        answers.append(await ask(daemon_port, f"load{index}.example."))
                    except TimeoutError:
                        lost += 1

                async with anyio.create_task_group() as clients:
                    for index in range(QUERIES):
                        clients.start_soon(one, index)

                daemon_log = log_path.read_text(errors="replace")[-3000:]
                assert lost == 0, f"{lost} of {QUERIES} unanswered\n{daemon_log}"
                assert all(
                    [r.address for rr in a.answer for r in rr] == ["192.0.2.1"]
                    for a in answers
                )
                assert proc.returncode is None
                after = await control_request(control_sock, {"op": "pid"})
                assert after["pid"] == before["pid"]
        finally:
            await reap(proc)
            log.close()
            tg.cancel_scope.cancel()
