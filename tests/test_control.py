"""Control protocol: pure dispatch plus a socket round-trip."""

import anyio
import pytest

from pymacdns import cache as cache_mod
from pymacdns import control as control_mod


def filled_cache() -> cache_mod.DnsCache:
    cache = cache_mod.DnsCache()
    import dns.message
    import dns.rrset

    for name in ("a.lab.", "b.lab."):
        q = dns.message.make_query(name, "A")
        resp = dns.message.make_response(q)
        resp.answer.append(dns.rrset.from_text(name, 60, "IN", "A", "10.0.0.1"))
        cache.store(cache_mod.key_of(resp.to_wire()), resp.to_wire())
    return cache


def test_dispatch_list_remove_clear():
    cache = filled_cache()
    listed = control_mod.dispatch(cache, {"op": "list"})
    assert len(listed["entries"]) == 2
    assert control_mod.dispatch(cache, {"op": "remove", "name": "a.lab."}) == {
        "removed": 1
    }
    assert control_mod.dispatch(cache, {"op": "bogus"}) == {
        "error": "unknown op 'bogus'"
    }
    assert control_mod.dispatch(cache, {"op": "remove"}) == {
        "error": "remove needs a name"
    }
    assert control_mod.dispatch(cache, {"op": "clear"}) == {"cleared": 1}
    assert control_mod.dispatch(cache, {"op": "list"}) == {"entries": []}


@pytest.mark.anyio
async def test_socket_round_trip(tmp_path):
    import os
    import tempfile

    # NOTE: macOS caps AF_UNIX paths at 104 chars, pytest tmp paths
    # exceed it, so bind under a short unique /tmp dir instead.
    # (A fixed /tmp name risks stale files and PID reuse across runs.)
    rundir = tempfile.mkdtemp(prefix="pmdns", dir="/tmp")
    sock = os.path.join(rundir, "ctl.sock")
    try:
        cache = filled_cache()
        async with anyio.create_task_group() as tg:
            tg.start_soon(control_mod.serve_control, sock, cache)
            await anyio.sleep(0.2)
            reply = await control_mod.control_request(sock, {"op": "list"})
            assert len(reply["entries"]) == 2
            reply = await control_mod.control_request(
                sock, {"op": "remove", "name": "a.lab.", "qtype": "A"}
            )
            assert reply == {"removed": 1}
            tg.cancel_scope.cancel()
    finally:
        try:
            os.unlink(sock)
            os.rmdir(rundir)
        except OSError:
            pass
