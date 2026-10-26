# SPDX-License-Identifier: Apache-2.0
import asyncio
import contextlib
import gc
import ipaddress
import logging
import socket
import stat
import subprocess
import sys
import threading
import time
import warnings
from http import HTTPStatus
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from valetkey import proxy as proxy_module
from valetkey import sites
from valetkey.proxy import (
    Mode,
    Proxy,
    Refusal,
    Request,
    RequestError,
    SeenHost,
    address_refusal,
    parse_request,
    policy_refusal,
    port_refusal,
    system_resolver,
    upstream_head,
)

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Awaitable, Iterator

POLICY = sites.Policy(
    site="sitex",
    start="https://sitex.test/",
    allow=("sitex.test", "login.okta.test"),
    excluded=("track.sitex.test",),
)
NOT_ALLOWED = "not in the allow list"
PRIVATE = "resolves to a private address"


def run[T](scenario: Awaitable[T]) -> T:
    return asyncio.run(asyncio.wait_for(scenario, 20))


@pytest.fixture
def sock(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("s") / "p.sock"


# -- pure decisions ------------------------------------------------------------------------


def head(*lines: str) -> bytes:
    return "\r\n".join(lines).encode("ascii")


def test_parse_connect() -> None:
    request = parse_request(head("CONNECT SiteX.test.:443 HTTP/1.1", "Host: sitex.test:443"))
    assert request == Request("CONNECT", "sitex.test", 443, "", (b"Host: sitex.test:443",))


def test_parse_connect_ip_literals() -> None:
    assert parse_request(head("CONNECT [::1]:443 HTTP/1.1")).host == "::1"
    assert parse_request(head("CONNECT 10.0.0.1:8443 HTTP/1.0")).port == 8443


@pytest.mark.parametrize(
    ("line", "path", "port"),
    [
        ("GET http://sitex.test/ HTTP/1.1", "/", 80),
        ("GET http://sitex.test HTTP/1.1", "/", 80),
        ("GET http://sitex.test/a/b?x=1&y=2 HTTP/1.1", "/a/b?x=1&y=2", 80),
        ("GET http://sitex.test?x=1 HTTP/1.1", "/?x=1", 80),
        ("GET http://sitex.test/a#frag HTTP/1.1", "/a", 80),
        ("POST http://sitex.test:8080/up HTTP/1.1", "/up", 8080),
        ("GET http://[::1]:80/ HTTP/1.1", "/", 80),
    ],
)
def test_parse_plain(line: str, path: str, port: int) -> None:
    request = parse_request(head(line))
    assert (request.path, request.port) == (path, port)


def test_parse_plain_methods() -> None:
    for method in ("GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
        assert parse_request(head(f"{method} http://a.test/ HTTP/1.1")).method == method


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"GET",
        b"GET http://a.test/ HTTP/1.1 extra",
        b"GET  http://a.test/ HTTP/1.1",
        b"GET http://a.test/ SPDY/3",
        b"GET http://a.test/ HTTP/2",
        b"get http://a.test/ HTTP/1.1",
        b"G3T http://a.test/ HTTP/1.1",
        b"GET / HTTP/1.1",
        b"GET /http://a.test/ HTTP/1.1",
        b"GET https://a.test/ HTTP/1.1",
        b"GET ftp://a.test/ HTTP/1.1",
        b"GET http:///x HTTP/1.1",
        b"GET http://a.test:abc/ HTTP/1.1",
        b"GET http://a.test:99999/ HTTP/1.1",
        b"GET http://user:pw@a.test/ HTTP/1.1",
        b"GET http://a.test\\@evil.test/ HTTP/1.1",
        b"GET http://[::1/ HTTP/1.1",
        b"GET http://a_b.test/ HTTP/1.1",
        b"GET http://fe80::1%25eth0/ HTTP/1.1",
        b"GET http://[fe80::1%25eth0]/ HTTP/1.1",
        b"GET http://a.test/\x01 HTTP/1.1",
        b"GET http://a.test/\x7f HTTP/1.1",
        b"GET http://\xc3\xa9.test/ HTTP/1.1",
        b"GET http://a.test/ HTTP/1.1\r\nBad header",
        b"GET http://a.test/ HTTP/1.1\r\n: empty",
        b"GET http://a.test/ HTTP/1.1\r\n folded: x",
        b"GET http://a.test/ HTTP/1.1\r\nName : x",
        b"GET http://a.test/ HTTP/1.1\r\nA: b\nC: d",
        b"GET http://a.test/ HTTP/1.1\r\nA: b\x00",
        b"CONNECT a.test HTTP/1.1",
        b"CONNECT a.test:443/x HTTP/1.1",
        b"CONNECT a.test:443?x HTTP/1.1",
        b"CONNECT user@a.test:443 HTTP/1.1",
        b"CONNECT a.test:abc HTTP/1.1",
        b"CONNECT :443 HTTP/1.1",
        b"CONNECT http://a.test:443 HTTP/1.1",
        b"CONNECT a.test:443#x HTTP/1.1",
    ],
)
def test_parse_rejects_malformed_requests_with_400(raw: bytes) -> None:
    with pytest.raises(RequestError) as info:
        parse_request(raw)
    assert info.value.status is HTTPStatus.BAD_REQUEST


@pytest.mark.parametrize("method", ["TRACE", "TRACK", "LINK", "PRI"])
def test_parse_rejects_other_methods_with_405(method: str) -> None:
    with pytest.raises(RequestError) as info:
        parse_request(head(f"{method} http://a.test/ HTTP/1.1"))
    assert info.value.status is HTTPStatus.METHOD_NOT_ALLOWED


def test_upstream_head_rewrites_to_origin_form() -> None:
    request = parse_request(
        head(
            "GET http://sitex.test/a?b=1 HTTP/1.0",
            "Host: other.test",
            "Accept: */*",
            "Connection: keep-alive",
            "proxy-connection: keep-alive",
            "Proxy-Authorization: Basic abc",
            "Keep-Alive: 5",
            "X-Test: Host: not-a-host",
            "Cookie: a=b",
        )
    )
    assert upstream_head(request) == head(
        "GET /a?b=1 HTTP/1.1",
        "Host: sitex.test",
        "Accept: */*",
        "X-Test: Host: not-a-host",
        "Cookie: a=b",
        "Connection: close",
        "",
        "",
    )


def test_upstream_head_brackets_ipv6_hosts() -> None:
    request = parse_request(head("GET http://[2001:db8::1]/ HTTP/1.1"))
    assert b"Host: [2001:db8::1]\r\n" in upstream_head(request)


def test_port_refusal() -> None:
    connect = Request("CONNECT", "a.test", 443, "", ())
    plain = Request("GET", "a.test", 80, "/", ())
    assert port_refusal(connect) is None
    assert port_refusal(plain) is None
    assert (
        port_refusal(Request("CONNECT", "a.test", 80, "", ()))
        == "port 80 is not allowed (only 443)"
    )
    assert (
        port_refusal(Request("GET", "a.test", 443, "/", ())) == "port 443 is not allowed (only 80)"
    )
    assert port_refusal(Request("CONNECT", "a.test", 0, "", ())) is not None
    assert port_refusal(Request("GET", "a.test", 8080, "/", ())) is not None


def test_policy_refusal() -> None:
    assert policy_refusal(POLICY, Mode.ENFORCE, "sitex.test") is None
    assert policy_refusal(POLICY, Mode.ENFORCE, "cdn.sitex.test") is None
    assert policy_refusal(POLICY, Mode.ENFORCE, "notsitex.test") == NOT_ALLOWED
    assert policy_refusal(POLICY, Mode.ENFORCE, "track.sitex.test") == NOT_ALLOWED
    assert policy_refusal(POLICY, Mode.RECORD, "anything.test") is None
    assert policy_refusal(POLICY, Mode.RECORD, "track.sitex.test") is None


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "127.255.255.254",
        "::1",
        "0.0.0.0",  # noqa: S104 - an address the checker must refuse
        "::",
        "10.0.0.1",
        "172.16.5.4",
        "192.168.1.1",
        "169.254.169.254",
        "fe80::1",
        "fe80::1%eth0",
        "fc00::1",
        "fd12:3456::1",
        "224.0.0.1",
        "ff02::1",
        "240.0.0.1",
        "255.255.255.255",
        "100.64.0.1",
        "192.0.2.1",
        "2001:db8::1",
        "::ffff:127.0.0.1",
        "::ffff:10.1.2.3",
        "::ffff:192.168.0.1",
        "::ffff:169.254.1.1",
        "not-an-address",
        "",
        "sitex.test",
    ],
)
def test_address_refusal_blocks_non_public(address: str) -> None:
    assert address_refusal(address) == PRIVATE


@pytest.mark.parametrize(
    "address",
    ["93.184.216.34", "8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"],
)
def test_address_refusal_allows_public(address: str) -> None:
    assert address_refusal(address) is None


def test_system_resolver_resolves_literals_once() -> None:
    assert run(system_resolver("127.0.0.1", 80)) == ["127.0.0.1"]
    assert run(system_resolver("::1", 443)) == ["::1"]


# -- rig -----------------------------------------------------------------------------------


class Upstream:
    """A local server that echoes what it receives and keeps a copy."""

    def __init__(self) -> None:
        self.received = bytearray()
        self.connections = 0
        self.port = 0

    async def _echo(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections += 1
        with contextlib.suppress(OSError):
            while data := await reader.read(65536):
                self.received += data
                writer.write(data)
                await writer.drain()
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()

    @contextlib.asynccontextmanager
    async def serving(self) -> AsyncGenerator[Upstream]:
        server = await asyncio.start_server(self._echo, "127.0.0.1", 0)
        self.port = server.sockets[0].getsockname()[1]
        try:
            yield self
        finally:
            server.close()
            server.close_clients()
            await server.wait_closed()


@contextlib.asynccontextmanager
async def running(
    sock: Path,
    mode: Mode = Mode.ENFORCE,
    policy: sites.Policy = POLICY,
    **options: Any,  # noqa: ANN401 - forwarded to Proxy
) -> AsyncGenerator[tuple[Proxy, Upstream]]:
    async with Upstream().serving() as upstream:

        async def resolve(_host: str, _port: int) -> list[str]:
            return ["127.0.0.1"]

        async def connect(_address: str, _port: int) -> proxy_module.Streams:
            return await asyncio.open_connection("127.0.0.1", upstream.port)

        settings: dict[str, Any] = {
            "resolver": resolve,
            "connector": connect,
            "address_check": lambda _address: None,
        } | options
        async with Proxy(policy, mode, **settings).serving(sock) as proxy:
            yield proxy, upstream


async def close(writer: asyncio.StreamWriter) -> None:
    writer.close()
    with contextlib.suppress(OSError):
        await writer.wait_closed()


async def send(sock: Path, data: bytes) -> bytes:
    """Send ``data``, then read until the proxy closes the connection."""
    reader, writer = await asyncio.open_unix_connection(sock)
    try:
        writer.write(data)
        await writer.drain()
        return await reader.read()
    finally:
        await close(writer)


def connect_request(target: str, *extra: str) -> bytes:
    return head(f"CONNECT {target} HTTP/1.1", f"Host: {target}", *extra, "", "")


def status_of(response: bytes) -> int:
    return int(response.split(b" ", 2)[1])


# -- tunnels -------------------------------------------------------------------------------


def test_connect_tunnels_bytes_both_ways(sock: Path) -> None:
    async def scenario() -> None:
        async with running(sock) as (proxy, upstream):
            reader, writer = await asyncio.open_unix_connection(sock)
            try:
                writer.write(connect_request("sitex.test:443"))
                response = await reader.readuntil(b"\r\n\r\n")
                assert response == b"HTTP/1.1 200 Connection Established\r\n\r\n"
                writer.write(b"\x16\x03\x01 not really tls")
                assert await reader.readexactly(18) == b"\x16\x03\x01 not really tls"
                assert bytes(upstream.received) == b"\x16\x03\x01 not really tls"
            finally:
                await close(writer)
            assert proxy.refused_since() == ([], 0)
            assert proxy.seen_hosts() == []

    run(scenario())


def test_bytes_sent_right_after_connect_reach_the_upstream(sock: Path) -> None:
    async def scenario() -> None:
        async with running(sock) as (_proxy, _upstream):
            reader, writer = await asyncio.open_unix_connection(sock)
            try:
                writer.write(connect_request("sitex.test:443") + b"early")
                await reader.readuntil(b"\r\n\r\n")
                assert await reader.readexactly(5) == b"early"
            finally:
                await close(writer)

    run(scenario())


def test_subdomains_of_allowed_hosts_connect(sock: Path) -> None:
    async def scenario() -> None:
        async with running(sock) as (proxy, upstream):
            response = await send_and_hangup(sock, connect_request("cdn.sitex.test:443"))
            assert status_of(response) == 200
            assert upstream.connections == 1
            assert proxy.refused_since()[0] == []

    run(scenario())


async def send_and_hangup(sock: Path, data: bytes) -> bytes:
    reader, writer = await asyncio.open_unix_connection(sock)
    try:
        writer.write(data)
        return await reader.readuntil(b"\r\n\r\n")
    finally:
        await close(writer)


def test_either_side_ending_closes_the_other(sock: Path) -> None:
    async def scenario() -> None:
        async with running(sock) as (_proxy, upstream):
            reader, writer = await asyncio.open_unix_connection(sock)
            try:
                writer.write(connect_request("sitex.test:443"))
                await reader.readuntil(b"\r\n\r\n")
                writer.write(b"x")
                await reader.readexactly(1)
                writer.write_eof()
                assert await reader.read() == b""
                assert upstream.connections == 1
            finally:
                await close(writer)

    run(scenario())


# -- enforce mode --------------------------------------------------------------------------


def test_enforce_refuses_unlisted_hosts_and_records_them(sock: Path) -> None:
    async def scenario() -> None:
        async with running(sock) as (proxy, upstream):
            response = await send(sock, connect_request("evil.test:443"))
            assert response.startswith(b"HTTP/1.1 403 Forbidden\r\n")
            assert b"blocked evil.test: not in the allow list" in response
            refusals, cursor = proxy.refused_since()
            assert refusals == [Refusal(1, "evil.test", 443, NOT_ALLOWED)]
            assert cursor == 1
            assert proxy.refused_since(cursor) == ([], 1)
            await send(sock, connect_request("notsitex.test:443"))
            await send(sock, connect_request("track.sitex.test:443"))
            later, cursor = proxy.refused_since(1)
            assert [r.host for r in later] == ["notsitex.test", "track.sitex.test"]
            assert [r.seq for r in later] == [2, 3]
            assert cursor == 3
            assert upstream.connections == 0
            assert proxy.seen_hosts() == []

    run(scenario())


def test_ports_other_than_443_and_80_are_refused(sock: Path) -> None:
    async def scenario() -> None:
        async with running(sock) as (proxy, upstream):
            assert status_of(await send(sock, connect_request("sitex.test:8443"))) == 403
            assert status_of(await send(sock, connect_request("sitex.test:80"))) == 403
            request = head("GET http://sitex.test:8080/ HTTP/1.1", "", "")
            assert status_of(await send(sock, request)) == 403
            assert [(r.host, r.port, r.reason) for r in proxy.refused_since()[0]] == [
                ("sitex.test", 8443, "port 8443 is not allowed (only 443)"),
                ("sitex.test", 80, "port 80 is not allowed (only 443)"),
                ("sitex.test", 8080, "port 8080 is not allowed (only 80)"),
            ]
            assert upstream.connections == 0

    run(scenario())


def test_update_policy_applies_to_new_connections(sock: Path) -> None:
    async def scenario() -> None:
        async with running(sock) as (proxy, upstream):
            assert status_of(await send(sock, connect_request("new.test:443"))) == 403
            wider = sites.Policy(POLICY.site, POLICY.start, (*POLICY.allow, "new.test"))
            proxy.update_policy(wider)
            assert proxy.policy is wider
            reader, writer = await asyncio.open_unix_connection(sock)
            try:
                writer.write(connect_request("new.test:443"))
                assert status_of(await reader.readuntil(b"\r\n\r\n")) == 200
            finally:
                await close(writer)
            assert upstream.connections == 1
            assert len(proxy.refused_since()[0]) == 1
            assert proxy.mode is Mode.ENFORCE

    run(scenario())


def test_refusal_history_is_bounded_and_numbers_keep_counting(sock: Path) -> None:
    async def scenario() -> None:
        async with running(sock, max_refusals=3) as (proxy, _upstream):
            for number in range(5):
                await send(sock, connect_request(f"h{number}.test:443"))
            refusals, cursor = proxy.refused_since()
            assert [r.host for r in refusals] == ["h2.test", "h3.test", "h4.test"]
            assert cursor == 5
            assert [r.seq for r in proxy.refused_since(3)[0]] == [4, 5]

    run(scenario())


# -- record mode ---------------------------------------------------------------------------


def test_record_mode_allows_everything_and_counts_hosts(sock: Path) -> None:
    async def scenario() -> None:
        async with running(sock, Mode.RECORD) as (proxy, upstream):
            for target in ("a.test:443", "b.test:443", "a.test:443", "track.sitex.test:443"):
                response = await send_and_hangup(sock, connect_request(target))
                assert status_of(response) == 200
            assert proxy.mode is Mode.RECORD
            assert proxy.seen_hosts() == [
                SeenHost("a.test", 2),
                SeenHost("b.test", 1),
                SeenHost("track.sitex.test", 1),
            ]
            assert proxy.refused_since()[0] == []
            assert upstream.connections == 4

    run(scenario())


def test_record_mode_still_checks_ports_and_does_not_see_refused_hosts(sock: Path) -> None:
    async def scenario() -> None:
        async with running(sock, Mode.RECORD) as (proxy, _upstream):
            assert status_of(await send(sock, connect_request("a.test:8443"))) == 403
            assert proxy.seen_hosts() == []
            assert proxy.refused_since()[0] == [
                Refusal(1, "a.test", 8443, "port 8443 is not allowed (only 443)")
            ]

    run(scenario())


def test_record_mode_ignores_new_hosts_past_the_cap(sock: Path) -> None:
    async def scenario() -> None:
        async with running(sock, Mode.RECORD, max_seen_hosts=2) as (proxy, _upstream):
            for target in ("a.test:443", "b.test:443", "c.test:443", "a.test:443"):
                await send_and_hangup(sock, connect_request(target))
            assert proxy.seen_hosts() == [SeenHost("a.test", 2), SeenHost("b.test", 1)]

    run(scenario())


# -- quiet hosts ---------------------------------------------------------------------------


def test_quiet_hosts_are_refused_but_not_reported(sock: Path) -> None:
    quiet = frozenset({"Update.Quiet.test."})

    async def scenario() -> None:
        async with running(sock, quiet_hosts=quiet) as (proxy, upstream):
            assert status_of(await send(sock, connect_request("update.quiet.test:443"))) == 403
            assert status_of(await send(sock, connect_request("update.quiet.test:80"))) == 403
            plain = head("GET http://update.quiet.test/ HTTP/1.1", "", "")
            assert status_of(await send(sock, plain)) == 403
            assert proxy.refused_since() == ([], 0)
            assert proxy.quiet_refusals == 3
            assert status_of(await send(sock, connect_request("sub.update.quiet.test:443"))) == 403
            assert proxy.refused_since()[0] == [
                Refusal(1, "sub.update.quiet.test", 443, NOT_ALLOWED)
            ]
            assert upstream.connections == 0

    run(scenario())


def test_quiet_refusals_have_a_history_with_a_cursor_of_their_own(sock: Path) -> None:
    async def scenario() -> None:
        async with running(sock, quiet_hosts=frozenset({"bg.test"})) as (proxy, _):
            assert proxy.quiet_refused_since() == ([], 0)
            await send(sock, connect_request("bg.test:443"))
            await send(sock, connect_request("evil.test:443"))
            await send(sock, connect_request("bg.test:80"))
            events, cursor = proxy.quiet_refused_since()
            assert events == [
                Refusal(1, "bg.test", 443, NOT_ALLOWED),
                Refusal(2, "bg.test", 80, "port 80 is not allowed (only 443)"),
            ]
            assert cursor == 2
            assert proxy.quiet_refused_since(cursor) == ([], 2)
            await send(sock, connect_request("bg.test:443"))
            assert [r.seq for r in proxy.quiet_refused_since(cursor)[0]] == [3]
            # Never mixed into the reported refusals, which have their own numbers.
            assert [r.host for r in proxy.refused_since()[0]] == ["evil.test"]

    run(scenario())


def test_the_quiet_history_is_bounded_and_numbers_keep_counting(sock: Path) -> None:
    async def scenario() -> None:
        async with running(sock, quiet_hosts=frozenset({"bg.test"}), max_refusals=2) as (proxy, _):
            for _n in range(3):
                await send(sock, connect_request("bg.test:443"))
            events, cursor = proxy.quiet_refused_since()
            assert [r.seq for r in events] == [2, 3]
            assert cursor == 3

    run(scenario())


def test_a_quiet_host_the_policy_allows_connects_like_any_other(sock: Path) -> None:
    allowed = sites.Policy("sitex", "https://sitex.test/", ("sitex.test", "bg.test"))

    async def scenario() -> None:
        async with running(sock, policy=allowed, quiet_hosts=frozenset({"bg.test"})) as (
            proxy,
            upstream,
        ):
            assert status_of(await send_and_hangup(sock, connect_request("bg.test:443"))) == 200
            assert upstream.connections == 1
            assert proxy.quiet_refusals == 0
            assert proxy.quiet_refused_since() == ([], 0)
            assert proxy.refused_since() == ([], 0)

    run(scenario())


def test_quiet_hosts_are_not_recorded_as_seen_in_record_mode(sock: Path) -> None:
    async def scenario() -> None:
        async with running(sock, Mode.RECORD, quiet_hosts=frozenset({"bg.test"})) as (proxy, _):
            await send_and_hangup(sock, connect_request("bg.test:443"))
            await send_and_hangup(sock, connect_request("a.test:443"))
            assert proxy.seen_hosts() == [SeenHost("a.test", 1)]
            assert proxy.quiet_refusals == 0

    run(scenario())


# -- addresses -----------------------------------------------------------------------------


def test_a_name_resolving_to_a_private_address_is_refused(sock: Path) -> None:
    attempts: list[str] = []

    async def resolve(_host: str, _port: int) -> list[str]:
        return ["10.0.0.5", "127.0.0.1", "::ffff:192.168.1.1"]

    async def connect(address: str, _port: int) -> proxy_module.Streams:
        attempts.append(address)
        raise AssertionError(address)

    async def scenario() -> None:
        options: dict[str, Any] = {
            "resolver": resolve,
            "connector": connect,
            "address_check": address_refusal,
        }
        async with running(sock, **options) as (proxy, _upstream):
            response = await send(sock, connect_request("sitex.test:443"))
            assert status_of(response) == 403
            assert proxy.refused_since()[0] == [Refusal(1, "sitex.test", 443, PRIVATE)]
            assert attempts == []

    run(scenario())


@pytest.mark.parametrize(
    "target",
    ["127.0.0.1:443", "[::1]:443", "10.1.2.3:443", "[::ffff:127.0.0.1]:443", "169.254.169.254:443"],
)
def test_ip_literals_get_the_same_address_check(sock: Path, target: str) -> None:
    resolved: list[str] = []

    async def resolve(host: str, _port: int) -> list[str]:
        resolved.append(host)
        return ["127.0.0.1"]

    async def scenario() -> None:
        async with running(sock, Mode.RECORD, resolver=resolve, address_check=address_refusal) as (
            proxy,
            upstream,
        ):
            assert status_of(await send(sock, connect_request(target))) == 403
            host = target.rsplit(":", 1)[0].strip("[]")
            assert proxy.refused_since()[0] == [Refusal(1, host, 443, PRIVATE)]
            assert proxy.seen_hosts() == []
            assert upstream.connections == 0
            assert resolved == []

    run(scenario())


def test_public_ip_literal_is_connected_without_resolving(sock: Path) -> None:
    resolved: list[str] = []

    async def resolve(host: str, _port: int) -> list[str]:
        resolved.append(host)
        return []

    async def scenario() -> None:
        async with running(sock, Mode.RECORD, resolver=resolve, address_check=address_refusal) as (
            proxy,
            upstream,
        ):
            response = await send_and_hangup(sock, connect_request("93.184.216.34:443"))
            assert status_of(response) == 200
            assert upstream.connections == 1
            assert proxy.seen_hosts() == [SeenHost("93.184.216.34", 1)]
            assert resolved == []

    run(scenario())


def test_connection_falls_back_to_the_next_address(sock: Path) -> None:
    tried: list[str] = []

    async def resolve(_host: str, _port: int) -> list[str]:
        return ["192.0.2.1", "198.51.100.7", "127.0.0.1"]

    def check(_address: str) -> str | None:
        return None

    async def scenario() -> None:
        async with Upstream().serving() as upstream:

            async def connect(address: str, _port: int) -> proxy_module.Streams:
                tried.append(address)
                if address != "127.0.0.1":
                    raise ConnectionRefusedError
                return await asyncio.open_connection(address, upstream.port)

            proxy = Proxy(POLICY, resolver=resolve, connector=connect, address_check=check)
            async with proxy.serving(sock):
                response = await send_and_hangup(sock, connect_request("sitex.test:443"))
                assert status_of(response) == 200
            assert tried == ["192.0.2.1", "198.51.100.7", "127.0.0.1"]

    run(scenario())


def test_unreachable_host_is_a_502_and_not_a_refusal(sock: Path) -> None:
    async def connect(_address: str, _port: int) -> proxy_module.Streams:
        raise ConnectionRefusedError

    async def scenario() -> None:
        async with running(sock, connector=connect) as (proxy, _upstream):
            response = await send(sock, connect_request("sitex.test:443"))
            assert status_of(response) == 502
            assert proxy.refused_since() == ([], 0)

    run(scenario())


def test_slow_connect_times_out(sock: Path) -> None:
    async def connect(_address: str, _port: int) -> proxy_module.Streams:
        await asyncio.sleep(30)
        raise AssertionError

    async def scenario() -> None:
        async with running(sock, connector=connect, connect_timeout=0.05) as (_proxy, _upstream):
            assert status_of(await send(sock, connect_request("sitex.test:443"))) == 502

    run(scenario())


@pytest.mark.parametrize("failure", [OSError("no dns"), None])
def test_failed_or_empty_resolution_is_a_502(sock: Path, failure: OSError | None) -> None:
    async def resolve(_host: str, _port: int) -> list[str]:
        if failure is not None:
            raise failure
        return []

    async def scenario() -> None:
        async with running(sock, resolver=resolve) as (proxy, _upstream):
            assert status_of(await send(sock, connect_request("sitex.test:443"))) == 502
            assert proxy.refused_since() == ([], 0)

    run(scenario())


def test_an_unexpected_error_is_a_500_and_the_proxy_keeps_serving(
    sock: Path, caplog: pytest.LogCaptureFixture
) -> None:
    calls = 0

    async def resolve(_host: str, _port: int) -> list[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            msg = "bug"
            raise RuntimeError(msg)
        return ["127.0.0.1"]

    async def scenario() -> None:
        async with running(sock, resolver=resolve) as (_proxy, _upstream):
            with caplog.at_level(logging.ERROR, logger="valetkey.proxy"):
                assert status_of(await send(sock, connect_request("sitex.test:443"))) == 500
            response = await send_and_hangup(sock, connect_request("sitex.test:443"))
            assert status_of(response) == 200

    run(scenario())
    assert "proxy connection failed" in caplog.text


# -- plain HTTP ----------------------------------------------------------------------------


def test_plain_http_is_rewritten_and_forwarded(sock: Path) -> None:
    request = head(
        "POST http://sitex.test/a/b?x=1 HTTP/1.1",
        "Host: other.test",
        "Connection: keep-alive",
        "Content-Length: 4",
        "",
        "abcd",
    )
    expected = head(
        "POST /a/b?x=1 HTTP/1.1",
        "Host: sitex.test",
        "Content-Length: 4",
        "Connection: close",
        "",
        "abcd",
    )

    async def scenario() -> None:
        async with running(sock) as (proxy, upstream):
            reader, writer = await asyncio.open_unix_connection(sock)
            try:
                writer.write(request)
                assert await reader.readexactly(len(expected)) == expected
                assert bytes(upstream.received) == expected
            finally:
                await close(writer)
            assert proxy.refused_since() == ([], 0)

    run(scenario())


def test_plain_http_to_an_unlisted_host_is_refused(sock: Path) -> None:
    async def scenario() -> None:
        async with running(sock) as (proxy, upstream):
            response = await send(sock, head("GET http://evil.test/ HTTP/1.1", "", ""))
            assert status_of(response) == 403
            assert proxy.refused_since()[0] == [Refusal(1, "evil.test", 80, NOT_ALLOWED)]
            assert upstream.connections == 0

    run(scenario())


def test_one_connection_never_reaches_a_second_host(sock: Path) -> None:
    async def scenario() -> None:
        async with running(sock) as (_proxy, upstream):
            first = head("GET http://sitex.test/ HTTP/1.1", "", "")
            second = head("GET http://evil.test/ HTTP/1.1", "Host: evil.test", "", "")
            reader, writer = await asyncio.open_unix_connection(sock)
            try:
                writer.write(first + second)
                await reader.readuntil(b"\r\n\r\n")
            finally:
                await close(writer)
            assert upstream.connections == 1
            assert b"Host: sitex.test" in upstream.received

    run(scenario())


def test_a_pipelined_request_is_not_forwarded_to_the_first_requests_server(sock: Path) -> None:
    """Both hosts are allowed; the second request still must not reach the first one's server."""

    async def scenario() -> None:
        async with running(sock) as (_proxy, upstream):
            first = head("POST http://sitex.test/a HTTP/1.1", "Content-Length: 3", "", "abc")
            second = head("GET http://login.okta.test/b HTTP/1.1", "Host: login.okta.test", "", "")
            reader, writer = await asyncio.open_unix_connection(sock)
            try:
                writer.write(first + second)
                await reader.readuntil(b"abc")
                await asyncio.sleep(0.1)
            finally:
                await close(writer)
            assert upstream.connections == 1
            assert b"POST /a HTTP/1.1" in upstream.received
            assert upstream.received.endswith(b"abc")
            assert b"okta" not in upstream.received

    run(scenario())


def test_the_body_is_forwarded_in_pieces_and_no_more_than_announced(sock: Path) -> None:
    async def scenario() -> None:
        async with running(sock) as (_proxy, upstream):
            request = head("POST http://sitex.test/a HTTP/1.1", "Content-Length: 6", "", "")
            reader, writer = await asyncio.open_unix_connection(sock)
            try:
                writer.write(request + b"ab")
                await writer.drain()
                await asyncio.sleep(0.05)
                writer.write(b"cdefGHIJ")
                await reader.readuntil(b"abcdef")
                await asyncio.sleep(0.1)
            finally:
                await close(writer)
            assert upstream.received.endswith(b"abcdef")

    run(scenario())


@pytest.mark.parametrize(
    ("headers", "status"),
    [
        (("Transfer-Encoding: chunked", "Content-Length: 4"), 400),
        (("Content-Length: 4", "transfer-encoding: identity"), 400),
        (("Transfer-Encoding: chunked",), 411),
        (("Content-Length: 4", "Content-Length: 5"), 400),
        (("Content-Length: 4, 4",), 400),
        (("Content-Length: -1",), 400),
        (("Content-Length: 0x4",), 400),
    ],
)
def test_a_request_that_states_its_length_unclearly_is_refused(
    sock: Path, headers: tuple[str, ...], status: int
) -> None:
    async def scenario() -> None:
        async with running(sock) as (proxy, upstream):
            request = head("POST http://sitex.test/a HTTP/1.1", *headers, "", "abcd")
            assert status_of(await send(sock, request)) == status
            assert upstream.connections == 0
            assert proxy.refused_since() == ([], 0)  # a malformed request is not a refusal

    run(scenario())


def test_the_same_content_length_twice_is_one_length() -> None:
    request = head(
        "POST http://sitex.test/a HTTP/1.1", "Content-Length: 4", "content-length: 4", "", ""
    )
    assert proxy_module.parse_request(request[:-4]).body_length == 4


# -- malformed input -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "status"),
    [
        (head("GET / HTTP/1.1", "", ""), 400),
        (head("GET https://sitex.test/ HTTP/1.1", "", ""), 400),
        (head("TRACE http://sitex.test/ HTTP/1.1", "", ""), 405),
        (head("CONNECT sitex.test HTTP/1.1", "", ""), 400),
        (b"\x00\xff\xfe\r\n\r\n", 400),
        (b"\r\n\r\n", 400),
        (b"GET http://sitex.test/ HTTP/1.1\r\nbroken\r\n\r\n", 400),
    ],
)
def test_malformed_requests_get_an_error_status(sock: Path, raw: bytes, status: int) -> None:
    async def scenario() -> None:
        async with running(sock) as (proxy, upstream):
            assert status_of(await send(sock, raw)) == status
            assert proxy.refused_since() == ([], 0)
            assert upstream.connections == 0

    run(scenario())


def test_an_oversized_head_gets_431(sock: Path) -> None:
    async def scenario() -> None:
        async with running(sock) as (_proxy, upstream):
            big = b"GET http://sitex.test/ HTTP/1.1\r\nX: " + b"a" * 20000 + b"\r\n\r\n"
            assert status_of(await send(sock, big)) == 431
            assert upstream.connections == 0

    run(scenario())


def test_a_head_that_never_ends_gets_408(sock: Path) -> None:
    async def scenario() -> None:
        async with running(sock, head_timeout=0.05) as (_proxy, _upstream):
            reader, writer = await asyncio.open_unix_connection(sock)
            try:
                writer.write(b"GET http://sitex.test/ HTTP/1.1\r\n")
                assert status_of(await reader.read()) == 408
            finally:
                await close(writer)

    run(scenario())


def test_clients_that_hang_up_early_do_not_disturb_the_proxy(sock: Path) -> None:
    async def scenario() -> None:
        async with running(sock) as (_proxy, _upstream):
            _reader, writer = await asyncio.open_unix_connection(sock)
            await close(writer)
            _reader, writer = await asyncio.open_unix_connection(sock)
            writer.write(b"CONNECT sitex.test:443 HTTP/1.1\r\n")
            await writer.drain()
            await close(writer)
            response = await send_and_hangup(sock, connect_request("sitex.test:443"))
            assert status_of(response) == 200

    run(scenario())


def test_many_connections_at_once(sock: Path) -> None:
    async def one(number: int) -> None:
        reader, writer = await asyncio.open_unix_connection(sock)
        try:
            writer.write(connect_request("sitex.test:443"))
            await reader.readuntil(b"\r\n\r\n")
            payload = f"hello {number}".encode()
            writer.write(payload)
            assert await reader.readexactly(len(payload)) == payload
        finally:
            await close(writer)

    async def scenario() -> None:
        async with running(sock) as (_proxy, upstream):
            await asyncio.gather(*(one(n) for n in range(100)))
            assert upstream.connections == 100

    run(scenario())


# -- what is kept --------------------------------------------------------------------------


def test_only_the_host_is_recorded_never_paths_or_headers(sock: Path) -> None:
    needle = "s3cr3t-token-9f8e7d"
    request = head(
        f"GET http://evil.test/reset/{needle}?key={needle} HTTP/1.1",
        f"Authorization: Bearer {needle}",
        f"Cookie: session={needle}",
        "",
        "",
    )
    allowed = head(
        f"GET http://a.test/account/{needle}?token={needle} HTTP/1.1",
        f"Authorization: Bearer {needle}",
        f"Cookie: session={needle}",
        "",
        "",
    )

    async def scenario() -> None:
        async with running(sock) as (enforcing, _upstream):
            await send(sock, request)
            refusals, _cursor = enforcing.refused_since()
            assert refusals == [Refusal(1, "evil.test", 80, NOT_ALLOWED)]
            assert needle not in repr(vars(enforcing).values()).replace(repr(POLICY), "")
            assert needle not in repr(refusals)
        other = sock.with_name("q.sock")
        async with running(other, Mode.RECORD) as (recording, _upstream):
            reader, writer = await asyncio.open_unix_connection(other)
            try:
                writer.write(allowed)
                await reader.readuntil(b"\r\n\r\n")
            finally:
                await close(writer)
            assert recording.seen_hosts() == [SeenHost("a.test", 1)]
            assert needle not in repr(recording.seen_hosts())
            assert needle not in repr(recording.refused_since())
            assert needle not in repr(vars(recording).values()).replace(repr(POLICY), "")

    run(scenario())


# -- lifecycle -----------------------------------------------------------------------------


def socket_mode(path: Path) -> tuple[bool, int]:
    info = path.stat()
    return stat.S_ISSOCK(info.st_mode), stat.S_IMODE(info.st_mode)


def path_exists(path: Path) -> bool:
    return path.exists()


def test_socket_is_private_and_removed_on_close(sock: Path) -> None:
    async def scenario() -> None:
        async with running(sock):
            assert socket_mode(sock) == (True, 0o600)
        assert not path_exists(sock)

    run(scenario())


def test_a_stale_socket_file_is_replaced(sock: Path) -> None:
    async def scenario() -> None:
        with socket.socket(socket.AF_UNIX) as stale:
            stale.bind(str(sock))
        assert path_exists(sock)
        async with running(sock) as (_proxy, _upstream):
            assert status_of(await send_and_hangup(sock, connect_request("sitex.test:443"))) == 200

    run(scenario())


def test_start_twice_fails_and_close_is_idempotent(sock: Path) -> None:
    async def scenario() -> None:
        proxy = Proxy(POLICY)
        await proxy.close()
        await proxy.start(sock)
        try:
            with pytest.raises(RuntimeError, match="already started"):
                await proxy.start(sock)
        finally:
            await proxy.close()
        await proxy.close()

    run(scenario())


def test_close_ends_open_tunnels(sock: Path) -> None:
    async def scenario() -> None:
        reader = writer = None
        try:
            async with running(sock):
                reader, writer = await asyncio.open_unix_connection(sock)
                writer.write(connect_request("sitex.test:443"))
                await reader.readuntil(b"\r\n\r\n")
            assert await asyncio.wait_for(reader.read(), 5) == b""
        finally:
            if writer is not None:
                await close(writer)

    run(scenario())


def test_defaults_are_sensible() -> None:
    assert proxy_module.MAX_HEAD_BYTES == 16 * 1024
    assert proxy_module.MAX_REFUSALS == 1000
    assert Proxy(POLICY).mode is Mode.ENFORCE


# -- private networks ----------------------------------------------------------------------

INTRANET = sites.Policy(
    site="intra",
    start="https://wiki.corp.test/",
    allow=("corp.test",),
    private_networks=("10.20.0.0/16", "100.64.0.0/10", "fd00:ec2::/48", "fd12:3456:789a::/48"),
)


@pytest.mark.parametrize(
    ("address", "allowed"),
    [
        ("10.20.1.5", True),
        ("10.20.255.255", True),
        ("::ffff:10.20.1.5", True),
        ("100.64.0.9", True),
        ("100.127.255.254", True),
        ("fd12:3456:789a::7", True),
        ("10.21.0.1", False),
        ("10.19.255.255", False),
        ("::ffff:10.21.0.1", False),
        ("192.168.1.1", False),
        ("93.184.216.34", False),
        ("fd12:3456:789b::7", False),
        # never, whatever is listed
        ("127.0.0.1", False),
        ("::1", False),
        ("::ffff:127.0.0.1", False),
        ("169.254.169.254", False),
        ("::ffff:169.254.169.254", False),
        ("169.254.0.7", False),
        ("100.100.100.200", False),
        ("fd00:ec2::254", False),
        ("0.0.0.0", False),  # noqa: S104
        ("224.0.0.1", False),
        ("240.0.0.1", False),
        ("not an address", False),
        ("", False),
    ],
)
def test_a_private_address_is_allowed_only_inside_a_listed_range(
    address: str, *, allowed: bool
) -> None:
    assert proxy_module.private_address_allowed(address, INTRANET.private_networks) is allowed


def test_no_listed_range_allows_nothing() -> None:
    assert not proxy_module.private_address_allowed("10.20.1.5", ())


def test_a_listed_range_of_the_other_family_does_not_match() -> None:
    assert not proxy_module.private_address_allowed("10.20.1.5", ("fd12:3456:789a::/48",))
    assert not proxy_module.private_address_allowed("fd12:3456:789a::7", ("10.0.0.0/8",))


async def through_intranet(
    sock: Path, policy: sites.Policy, answers: list[str], target: str = "wiki.corp.test:443"
) -> tuple[int, list[str], list[Refusal]]:
    """Connect through a proxy that uses the real address check; return what happened."""
    tried: list[str] = []

    async def resolve(_host: str, _port: int) -> list[str]:
        return answers

    async with Upstream().serving() as upstream:

        async def connect(address: str, _port: int) -> proxy_module.Streams:
            tried.append(address)
            return await asyncio.open_connection("127.0.0.1", upstream.port)

        proxy = Proxy(policy, resolver=resolve, connector=connect)
        async with proxy.serving(sock):
            response = await send_and_hangup(sock, connect_request(target))
        return status_of(response), tried, proxy.refused_since()[0]


def test_a_site_reaches_an_address_in_its_listed_range(sock: Path) -> None:
    status, tried, refused = run(through_intranet(sock, INTRANET, ["10.20.1.5"]))
    assert (status, tried, refused) == (200, ["10.20.1.5"], [])


def test_the_same_address_is_refused_without_the_field(sock: Path) -> None:
    plain = sites.Policy(site="intra", start="https://wiki.corp.test/", allow=("corp.test",))
    status, tried, refused = run(through_intranet(sock, plain, ["10.20.1.5"]))
    assert (status, tried) == (403, [])
    assert refused == [Refusal(1, "wiki.corp.test", 443, PRIVATE)]


def test_an_address_outside_the_range_is_refused(sock: Path) -> None:
    status, tried, _ = run(through_intranet(sock, INTRANET, ["10.21.0.1"]))
    assert (status, tried) == (403, [])


@pytest.mark.parametrize(
    "answers",
    [
        ["93.184.216.34", "10.99.0.1"],  # a public address with one outside the range
        ["10.20.1.5", "127.0.0.1"],
        ["10.20.1.5", "169.254.169.254"],
        ["10.20.1.5", "100.100.100.200"],
        ["10.20.1.5", "fd00:ec2::254"],
        ["127.0.0.1", "10.20.1.5"],
        ["10.20.1.5", "not an address"],
    ],
)
def test_every_address_of_the_answer_must_pass(sock: Path, answers: list[str]) -> None:
    status, tried, refused = run(through_intranet(sock, INTRANET, answers))
    assert (status, tried) == (403, [])
    assert [r.reason for r in refused] == [PRIVATE]


def test_public_and_listed_addresses_may_be_mixed(sock: Path) -> None:
    answers = ["93.184.216.34", "10.20.1.5", "::ffff:10.20.1.9"]
    status, tried, _ = run(through_intranet(sock, INTRANET, answers))
    assert (status, tried) == (200, ["93.184.216.34"])


@pytest.mark.parametrize("address", ["169.254.169.254", "100.100.100.200", "fd00:ec2::254"])
def test_the_metadata_services_stay_refused_inside_a_listed_range(sock: Path, address: str) -> None:
    status, tried, _ = run(through_intranet(sock, INTRANET, [address]))
    assert (status, tried) == (403, [])


def test_an_ip_literal_is_still_not_an_allowed_host(sock: Path) -> None:
    status, tried, refused = run(
        through_intranet(sock, INTRANET, ["10.20.1.5"], target="10.20.1.5:443")
    )
    assert (status, tried) == (403, [])
    assert [r.reason for r in refused] == [NOT_ALLOWED]


def test_one_sites_range_does_not_open_another_site(sock: Path) -> None:
    other = sites.Policy(
        site="other", start="https://wiki.corp.test/", allow=("corp.test",),
        private_networks=("10.30.0.0/16",),
    )  # fmt: skip
    first = run(through_intranet(sock, INTRANET, ["10.20.1.5"]))
    second = run(through_intranet(sock, other, ["10.20.1.5"]))
    assert (first[0], second[0]) == (200, 403)


def test_a_new_range_applies_to_the_running_proxy(sock: Path) -> None:
    plain = sites.Policy(site="intra", start="https://wiki.corp.test/", allow=("corp.test",))

    async def scenario() -> None:
        async def resolve(_host: str, _port: int) -> list[str]:
            return ["10.20.1.5"]

        async with Upstream().serving() as upstream:

            async def connect(_address: str, _port: int) -> proxy_module.Streams:
                return await asyncio.open_connection("127.0.0.1", upstream.port)

            proxy = Proxy(plain, resolver=resolve, connector=connect)
            async with proxy.serving(sock):
                first = await send_and_hangup(sock, connect_request("wiki.corp.test:443"))
                proxy.update_policy(INTRANET)
                second = await send_and_hangup(sock, connect_request("wiki.corp.test:443"))
                proxy.update_policy(plain)
                third = await send_and_hangup(sock, connect_request("wiki.corp.test:443"))
            assert [status_of(r) for r in (first, second, third)] == [403, 200, 403]

    run(scenario())


# -- closing ---------------------------------------------------------------------------------


def unclosed_after(scenario: Awaitable[None]) -> list[str]:
    """Run ``scenario`` on a loop of its own and return what was left open, as warnings.

    The loop is closed and the garbage collected before looking, because an unclosed socket or
    transport is only reported when it is dropped. That report arrives either as a warning or
    through the hook for errors the interpreter cannot raise, so both are caught.
    """
    found: list[str] = []
    previous = sys.unraisablehook
    sys.unraisablehook = lambda hook: found.append(f"{hook.exc_type.__name__}: {hook.exc_value}")
    try:
        with warnings.catch_warnings(record=True) as seen:
            warnings.simplefilter("always")
            asyncio.run(asyncio.wait_for(scenario, 20))
            gc.collect()
        found += [str(w.message) for w in seen if issubclass(w.category, ResourceWarning)]
    finally:
        sys.unraisablehook = previous
    return found


@pytest.mark.parametrize("turns", range(8))
def test_closing_leaves_nothing_open_whatever_stage_a_connection_has_reached(
    sock: Path, turns: int
) -> None:
    """A connection can be accepted but not yet handled when the proxy closes; none leaks."""

    async def scenario() -> None:
        proxy = Proxy(POLICY)
        await proxy.start(sock)
        clients = []
        for _ in range(3):
            client = socket.socket(socket.AF_UNIX)
            client.settimeout(0)  # non-blocking
            await asyncio.get_running_loop().sock_connect(client, str(sock))
            clients.append(client)
        for _ in range(turns):
            await asyncio.sleep(0)
        await proxy.close()
        for client in clients:
            client.close()

    assert unclosed_after(scenario()) == []


def test_a_browser_that_dies_in_the_middle_of_a_tunnel_leaves_nothing_open(sock: Path) -> None:
    async def scenario() -> None:
        async with running(sock) as (proxy, upstream):
            tunnels = []
            for _ in range(3):
                reader, writer = await asyncio.open_unix_connection(sock)
                writer.write(connect_request("sitex.test:443"))
                assert status_of(await reader.readuntil(b"\r\n\r\n")) == 200
                tunnels.append((reader, writer))
            half = await asyncio.open_unix_connection(sock)  # a request head that never ends
            half[1].write(b"CONNECT sitex.te")
            await half[1].drain()
            # The browser dies: its end of every connection goes away at once, and the session
            # that owned it closes the proxy in the same moment.
            for _reader, writer in (*tunnels, half):
                writer.transport.abort()
            await proxy.close()
            assert upstream.connections == 3

    assert unclosed_after(scenario()) == []


def test_a_proxy_that_was_closed_can_serve_again(sock: Path) -> None:
    async def scenario() -> None:
        proxy = Proxy(POLICY, resolver=_local_resolver, connector=_refusing_connector)
        await proxy.start(sock)
        await proxy.close()
        await proxy.start(sock)
        try:
            assert status_of(await send(sock, connect_request("evil.test:443"))) == 403
        finally:
            await proxy.close()

    run(scenario())


async def _local_resolver(_host: str, _port: int) -> list[str]:
    return ["127.0.0.1"]


async def _refusing_connector(_address: str, _port: int) -> proxy_module.Streams:
    raise OSError


# -- lookups that never return ---------------------------------------------------------------


@pytest.fixture
def hung_lookups(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """Make ``socket.getaddrinfo`` block until the test ends; the list holds the hosts asked."""
    release = threading.Event()
    asked: list[str] = []

    def lookup(host: str, *_args: object) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        asked.append(host)
        release.wait(30)
        raise socket.gaierror(host)

    monkeypatch.setattr(socket, "getaddrinfo", lookup)
    yield asked
    release.set()


def test_hung_lookups_do_not_stall_the_rest_of_the_process(
    sock: Path, hung_lookups: list[str]
) -> None:
    """A page asks for many names of an allowed domain while the resolver does not answer."""

    async def scenario() -> None:
        async with Proxy(POLICY, resolve_timeout=0.3).serving(sock):
            started = time.monotonic()
            requests = [
                send(sock, connect_request(f"h{number}.sitex.test:443")) for number in range(30)
            ]
            answers = asyncio.gather(*requests)
            await asyncio.sleep(0.1)
            # Work on the default thread pool still answers at once.
            assert await asyncio.wait_for(asyncio.to_thread(lambda: 1), 1) == 1
            assert {status_of(answer) for answer in await answers} == {502}
            assert time.monotonic() - started < 5
            assert len(hung_lookups) <= proxy_module.RESOLVE_WORKERS

    run(scenario())


def test_a_slow_resolver_is_answered_as_a_host_that_does_not_resolve(sock: Path) -> None:
    async def resolve(_host: str, _port: int) -> list[str]:
        await asyncio.sleep(30)
        return ["93.184.216.34"]

    async def scenario() -> None:
        async with Proxy(POLICY, resolver=resolve, resolve_timeout=0.1).serving(sock) as served:
            response = await send(sock, connect_request("sitex.test:443"))
            assert status_of(response) == 502
            assert served.refused_since() == ([], 0)  # a failed lookup is not a refusal

    run(scenario())


def test_the_proxy_closes_its_own_resolver_and_leaves_one_it_was_given(sock: Path) -> None:
    async def resolve(_host: str, _port: int) -> list[str]:
        return ["93.184.216.34"]

    own = Proxy(POLICY)
    assert isinstance(own._resolver, proxy_module.ThreadedResolver)  # noqa: SLF001
    given = Proxy(POLICY, resolver=resolve)
    assert given._owned_resolver is None  # noqa: SLF001

    async def scenario() -> None:
        async with given.serving(sock):
            pass
        async with own.serving(sock):
            pass

    run(scenario())
    with pytest.raises(RuntimeError, match="shutdown"):
        run(own._resolver("sitex.test", 443))  # noqa: SLF001


# -- every special-purpose range ---------------------------------------------------------------

# The IANA special-purpose address registries (RFC 6890 and the documents that update it), less
# the entries whose "Globally Reachable" column is True. The last two are deprecated ranges the
# registry no longer lists as reachable.
SPECIAL_RANGES = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.0.0/29",
    "192.0.0.8/32",
    "192.0.0.170/32",
    "192.0.0.171/32",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "255.255.255.255/32",
    "::/128",
    "::1/128",
    "::ffff:0:0/96",
    "64:ff9b::/96",
    "64:ff9b:1::/48",
    "100::/64",
    "100:0:0:1::/64",
    "2001::/23",
    "2001::/32",
    "2001:1::3/128",
    "2001:2::/48",
    "2001:10::/28",
    "2001:db8::/32",
    "2002::/16",
    "3fff::/20",
    "5f00::/16",
    "fc00::/7",
    "fe80::/10",
    "fec0::/10",
    "ff00::/8",
)
REACHABLE_RANGES = (
    "192.0.0.9/32",
    "192.0.0.10/32",
    "192.31.196.0/24",
    "192.52.193.0/24",
    "192.175.48.0/24",
    "2001:1::1/128",
    "2001:1::2/128",
    "2001:3::/32",
    "2001:4:112::/48",
    "2001:20::/28",
    "2001:30::/28",
)
NEVER_LISTABLE = (
    "0.0.0.0/32",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "255.255.255.255/32",
    "::/128",
    "::1/128",
    "fe80::/10",
    "ff00::/8",
)


@pytest.mark.parametrize("text", SPECIAL_RANGES)
def test_every_special_purpose_range_is_refused(text: str) -> None:
    network = ipaddress.ip_network(text)
    for address in (
        network[0],
        network[1] if network.num_addresses > 1 else network[0],
        network[-1],
    ):
        assert address_refusal(str(address)) is not None, address


@pytest.mark.parametrize("text", REACHABLE_RANGES)
def test_a_globally_reachable_special_purpose_range_is_not_refused(text: str) -> None:
    assert address_refusal(str(ipaddress.ip_network(text)[0])) is None


@pytest.mark.parametrize("text", NEVER_LISTABLE)
def test_a_range_that_is_never_allowed_stays_refused_when_listed(text: str) -> None:
    network = ipaddress.ip_network(text)
    assert not proxy_module.private_address_allowed(str(network[-1]), [text])
    assert not proxy_module.private_address_allowed(str(network[0]), [text])


@pytest.mark.parametrize(
    ("text", "address"),
    [("10.0.0.0/8", "10.1.2.3"), ("fc00::/7", "fd12::1"), ("100.64.0.0/10", "100.100.1.1")],
)
def test_a_private_range_is_allowed_when_listed(text: str, address: str) -> None:
    assert address_refusal(address) is not None
    assert proxy_module.private_address_allowed(address, [text])


def swap_for_a_directory(path: Path) -> None:
    path.unlink()
    path.mkdir()
    (path / "x").write_text("x")


def test_close_survives_a_socket_path_that_became_a_directory(sock: Path) -> None:
    async def scenario() -> None:
        proxy = Proxy(POLICY)
        await proxy.start(sock)
        await asyncio.to_thread(swap_for_a_directory, sock)
        await proxy.close()  # does not raise

    run(scenario())
    assert sock.is_dir()


# -- a flood of connections ----------------------------------------------------------------

FLOOD = """
import asyncio, resource, sys, tempfile
from pathlib import Path
from valetkey import sites
from valetkey.proxy import Proxy

resource.setrlimit(resource.RLIMIT_NOFILE, (1024, resource.getrlimit(resource.RLIMIT_NOFILE)[1]))
base = Path(tempfile.mkdtemp(prefix="vk-"))
ATTACKER = '''
import resource, socket, sys, time
resource.setrlimit(resource.RLIMIT_NOFILE, (4096, 4096))
held = []
for _ in range(1100):
    held.append(socket.socket(socket.AF_UNIX))
    held[-1].connect(sys.argv[1])
print("opened", len(held), flush=True)
time.sleep(6)
'''


async def main():
    policy = sites.Policy(site="sx", start="https://sitex.test/", allow=("sitex.test",))
    proxy = Proxy(policy)
    await proxy.start(base / "p.sock")

    async def daemon_socket(_reader, writer):
        writer.write(b"pong\\n")
        await writer.drain()
        writer.close()

    await asyncio.start_unix_server(daemon_socket, str(base / "d.sock"))
    attacker = await asyncio.create_subprocess_exec(
        sys.executable, "-c", ATTACKER, str(base / "p.sock"), stdout=asyncio.subprocess.PIPE
    )
    print((await attacker.stdout.readline()).decode().strip(), flush=True)
    await asyncio.sleep(0.5)
    reader, writer = await asyncio.wait_for(asyncio.open_unix_connection(str(base / "d.sock")), 3)
    print("daemon socket:", await asyncio.wait_for(reader.readline(), 3), flush=True)
    attacker.kill()
    await attacker.wait()
    await proxy.close()


asyncio.run(main())
"""


def test_a_flood_of_idle_connections_leaves_the_rest_of_the_process_working() -> None:
    """1100 idle connections to a proxy, with the 1024 descriptors a service gets by default."""
    result = subprocess.run(  # noqa: S603  # fixed argument list
        [sys.executable, "-I", "-c", FLOOD],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
        env={"PYTHONPATH": str(Path(proxy_module.__file__).parent.parent)},
    )
    assert "opened 1100" in result.stdout, result.stderr[-500:]
    assert "daemon socket: b'pong\\n'" in result.stdout, result.stderr[-500:]
    assert "Too many open files" not in result.stderr


def test_connections_over_the_limit_are_closed_at_once(
    sock: Path, caplog: pytest.LogCaptureFixture
) -> None:
    async def scenario() -> None:
        async with running(sock, max_connections=3) as (_proxy, upstream):
            held = [await asyncio.open_unix_connection(sock) for _ in range(3)]
            await asyncio.sleep(0.1)
            for _ in range(2):
                reader, writer = await asyncio.open_unix_connection(sock)
                assert await asyncio.wait_for(reader.read(), 2) == b""  # closed, nothing said
                await close(writer)
            held[0][1].write(connect_request("sitex.test:443"))
            await held[0][1].drain()
            assert await held[0][0].readuntil(b"\r\n\r\n")  # the three held ones still work
            for _reader, writer in held:
                await close(writer)
            await asyncio.sleep(0.1)
            answer = await send(sock, connect_request("evil.test:443"))  # room again
            assert status_of(answer) == 403  # answered, so it was served
            assert upstream.connections == 1  # only the one tunnel opened above

    with caplog.at_level(logging.WARNING, logger="valetkey.proxy"):
        run(scenario())
    assert [r.getMessage() for r in caplog.records].count(
        "more than 3 connections to a proxy; closing the rest"
    ) == 1
