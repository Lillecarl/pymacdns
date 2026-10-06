"""Shared fakes for transport tests: trustme contexts, loopback servers."""

import ssl

import anyio
import dns.message
import dns.rcode
import dns.rrset
import trustme


def make_contexts(host: str = "127.0.0.1") -> tuple[ssl.SSLContext, ssl.SSLContext]:
    """A server context plus a client context trusting it, nothing else."""
    ca = trustme.CA()
    cert = ca.issue_cert(host)
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert.configure_cert(server_ctx)
    client_ctx = ssl.create_default_context()
    ca.configure_trust(client_ctx)
    return server_ctx, client_ctx


async def answer_tls(stream: anyio.abc.SocketStream) -> None:
    """DoT responder: NOERROR with an empty answer section."""
    async with stream:
        while True:
            try:
                header = await stream.receive(2)
            except anyio.EndOfStream:
                return
            while len(header) < 2:
                header += await stream.receive(2 - len(header))
            length = int.from_bytes(header, "big")
            body = b""
            while len(body) < length:
                try:
                    body += await stream.receive(length - len(body))
                except anyio.EndOfStream:
                    return
            request = dns.message.from_wire(body)
            response = dns.message.make_response(request)
            response.set_rcode(dns.rcode.NOERROR)
            reply = response.to_wire()
            await stream.send(len(reply).to_bytes(2, "big") + reply)


async def answer_plain_udp(sock: anyio.abc.UDPSocket) -> None:
    """Plaintext responder, MARKEDLY different from the TLS one."""
    async with sock:
        while True:
            try:
                data, (host, port) = await sock.receive()
            except anyio.EndOfStream:
                return
            request = dns.message.from_wire(data)
            response = dns.message.make_response(request)
            response.answer.append(
                dns.rrset.from_text("example.com.", 60, "IN", "A", "192.0.2.1")
            )
            await sock.sendto(response.to_wire(), host, port)


async def answer_doh(stream: anyio.abc.SocketStream) -> None:
    """Minimal DoH responder: one POST, NOERROR with an empty answer."""
    try:
        async with stream:
            raw = b""
            while b"\r\n\r\n" not in raw:
                try:
                    chunk = await stream.receive(65536)
                except anyio.EndOfStream:
                    return
                if not chunk:
                    return
                raw += chunk
            head, _, rest = raw.partition(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
            length = 0
            for line in lines[1:]:
                if line.lower().startswith("content-length:"):
                    length = int(line.split(":", 1)[1].strip())
            body = rest
            while len(body) < length:
                try:
                    body += await stream.receive(length - len(body))
                except anyio.EndOfStream:
                    return
            request = dns.message.from_wire(body)
            response = dns.message.make_response(request)
            response.set_rcode(dns.rcode.NOERROR)
            reply = response.to_wire()
            await stream.send(
                f"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n"
                f"Content-Length: {len(reply)}\r\nConnection: close\r\n\r\n".encode()
                + reply
            )
    except anyio.BrokenResourceError:
        # httpx closes the TCP connection without a TLS close_notify;
        # the answer already went out, so there is nothing to report.
        pass
