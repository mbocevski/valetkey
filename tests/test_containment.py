# SPDX-License-Identifier: Apache-2.0
"""Containment, proven against a real session behind the real proxy.

A page from the allowed site runs probes that try to reach hosts it may not, and the result of
each is read back through the session. ``strace`` records every network call the browser makes,
and a separate run without a network namespace shows that the same check does find a leak.
"""

import asyncio
import dataclasses
import re
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from environment import unusable_reason
from proxy_stub import PageServer, RunningProxy

from valetkey import proxy as proxy_module
from valetkey import sandbox, sessions, sites

if TYPE_CHECKING:
    from collections.abc import Iterator

BRIDGE = ("127.0.0.1", 3128)
STUN = "stun:stun.l.google.com:19302"
STUN_IP = "stun:74.125.250.129:19302"
OFF_LIST_IP = "203.0.113.9"  # documentation range: never routed, and not on the list either
TRACED_CALLS = "connect,sendto,sendmsg,sendmmsg"
NOT_FAILED = frozenset({"ok", "EINPROGRESS", "UNFINISHED"})

# --- reading strace output ----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Attempt:
    """One network call that named an Internet address."""

    pid: int
    call: str
    address: str
    port: int
    outcome: str
    """``ok``, ``UNFINISHED`` or the error name such as ``ENETUNREACH`` (``EINPROGRESS`` too)."""


_LINE = re.compile(r"^(?:\[pid\s+)?(\d+)\]?\s+(.*)$")
_CALL = re.compile(r"^(connect|sendto|sendmsg|sendmmsg)\(")
_RESUMED = re.compile(r"^<\.\.\. (\w+) resumed>(.*)$")
_V4 = re.compile(r'sa_family=AF_INET, sin_port=htons\((\d+)\), sin_addr=inet_addr\("([^"]+)"\)')
_V6 = re.compile(r'sa_family=AF_INET6, sin6_port=htons\((\d+)\).*?inet_pton\(AF_INET6, "([^"]+)"')
_RESULT = re.compile(r"\)\s+=\s+(-?\d+)(?:\s+(E[A-Z0-9]+))?")


def parse_strace(text: str) -> list[Attempt]:
    """Return the Internet connects and sends in ``text``, from ``strace -f`` output.

    A call that blocks is printed in two halves, ``<unfinished ...>`` and ``<... resumed>``, and
    the result is on the second, so the halves are joined by process. Calls on a socket that is
    already connected carry no address and are left out: their connect was judged on its own.
    """
    pending: dict[int, str] = {}
    attempts: list[Attempt] = []
    for raw in text.splitlines():
        line = _LINE.match(raw)
        if line is None:
            continue
        pid, body = int(line.group(1)), line.group(2)
        resumed = _RESUMED.match(body)
        if resumed is not None:
            if pid not in pending:
                continue
            body = pending.pop(pid) + resumed.group(2)
        elif _CALL.match(body):
            if "<unfinished ...>" in body:
                pending[pid] = body.replace("<unfinished ...>", "")
                continue
        else:
            continue
        attempt = _attempt(pid, body)
        if attempt is not None:
            attempts.append(attempt)
    # A call that never resumed was cut off when the process was killed. Its result is unknown.
    for pid, body in pending.items():
        attempt = _attempt(pid, body + ") = 0")
        if attempt is not None:
            attempts.append(dataclasses.replace(attempt, outcome="UNFINISHED"))
    return attempts


def _attempt(pid: int, body: str) -> Attempt | None:
    call = body.split("(", 1)[0]
    found = _V4.search(body)
    if found is not None or (found := _V6.search(body)) is not None:
        port, address = found.groups()
    else:
        return None
    results = _RESULT.findall(body)
    if not results:
        return None
    number, error = results[-1]
    return Attempt(pid, call, address, int(port), "ok" if int(number) >= 0 else error or "E?")


def leaks(attempts: list[Attempt], bridge: tuple[str, int] = BRIDGE) -> list[Attempt]:
    """Return the attempts that did not fail and did not go to the bridge.

    ``EINPROGRESS`` and ``UNFINISHED`` count as not failed: a non-blocking connect may still
    complete, and a call cut off by a kill has no result to judge.
    """
    return [a for a in attempts if (a.address, a.port) != bridge and a.outcome in NOT_FAILED]


SAMPLE = """\
10  connect(5, {sa_family=AF_INET, sin_port=htons(3128), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
11  connect(6, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, 16 <unfinished ...>
12  sendto(7, ""..., 40, MSG_NOSIGNAL, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, 16) = 40
11  <... connect resumed>)            = -1 EINPROGRESS (Operation now in progress)
13  connect(8, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2001:db8::1", &sin6_addr), sin6_scope_id=0}, 28) = -1 ENETUNREACH (Network is unreachable)
13  sendmsg(9, {msg_name={sa_family=AF_INET, sin_port=htons(5353), sin_addr=inet_addr("224.0.0.251")}, msg_namelen=16, msg_iov=[...]}, 0) = -1 ENETUNREACH (Network is unreachable)
14  connect(9, {sa_family=AF_UNIX, sun_path="/run/dbus/system_bus_socket"}, 29) = -1 ENOENT (No such file or directory)
14  sendto(9, ""..., 8, MSG_NOSIGNAL, NULL, 0) = 8
[pid  15] connect(10, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("5.6.7.8")}, 16) = 0
16  +++ exited with 0 +++
17  <... connect resumed>) = 0
18  connect(11, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("9.9.9.9")}, 16 <unfinished ...>
"""  # noqa: E501  # real strace lines


def test_parse_strace_reads_whole_and_split_calls() -> None:
    attempts = parse_strace(SAMPLE)
    assert [(a.pid, a.address, a.port, a.outcome) for a in attempts] == [
        (10, "127.0.0.1", 3128, "ok"),
        (12, "8.8.8.8", 53, "ok"),
        (11, "1.2.3.4", 443, "EINPROGRESS"),
        (13, "2001:db8::1", 443, "ENETUNREACH"),
        (13, "224.0.0.251", 5353, "ENETUNREACH"),
        (15, "5.6.7.8", 80, "ok"),
        (18, "9.9.9.9", 53, "UNFINISHED"),
    ]
    assert {a.call for a in attempts} == {"connect", "sendto", "sendmsg"}


def test_leaks_are_what_did_not_fail_outside_the_bridge() -> None:
    found = leaks(parse_strace(SAMPLE))
    assert [(a.address, a.outcome) for a in found] == [
        ("8.8.8.8", "ok"),
        ("1.2.3.4", "EINPROGRESS"),
        ("5.6.7.8", "ok"),
        ("9.9.9.9", "UNFINISHED"),
    ]
    assert leaks([]) == []


def test_a_clean_trace_has_no_leaks() -> None:
    clean = SAMPLE.splitlines()
    text = "\n".join(line for line in clean if "8.8.8.8" not in line and "1.2.3.4" not in line)
    text = "\n".join(
        line for line in text.splitlines() if "5.6.7.8" not in line and "9.9.9.9" not in line
    )
    assert leaks(parse_strace(text)) == []


# --- the real thing -----------------------------------------------------------------------


_SKIP = unusable_reason("bwrap", "chromium", "agent-browser", "strace")
needs_everything = pytest.mark.skipif(_SKIP is not None, reason=_SKIP or "")
integration = pytest.mark.integration

PROBE = """<!doctype html><title>probe</title><button id=r>pending</button>
<script>
const out = (text) => { document.getElementById('r').textContent = 'done: ' + text; };
const settled = (list) =>
  Promise.allSettled(list).then((all) => all.map((x) => x.status).join(','));
const noCors = (url) => fetch(url, {mode: 'no-cors'});
const socketOutcome = (url) => new Promise((resolve) => {
  let opened = false;
  const ws = new WebSocket(url);
  ws.onopen = () => { opened = true; resolve('open'); };
  ws.onclose = () => resolve(opened ? 'open' : 'closed');
  setTimeout(() => resolve('timeout'), 8000);
});
%s
</script>"""

BODIES = {
    "control": "settled([noCors('http://allowed.test/'), noCors('http://allowed.test/p/control')])"
    ".then(out);",
    "fetch": "settled([noCors('https://evil.test/f'), noCors('https://%(ip)s/f')]).then(out);",
    "image": """const img = new Image();
img.onload = () => out('loaded');
img.onerror = () => out('error');
img.src = 'https://evil.test/i.png';
setTimeout(() => out('timeout'), 8000);""",
    "socket": """Promise.all([socketOutcome('wss://evil.test/s'), socketOutcome('ws://evil.test/s')])
  .then((r) => out(r.join(',')));""",
    "loopback": """settled([noCors('http://127.0.0.1:%(port)d/secret'),
  noCors('http://localhost:%(port)d/secret'), noCors('https://127.0.0.1:%(port)d/secret')])
  .then((r) => socketOutcome('ws://127.0.0.1:%(port)d/s').then((w) => out(r + ',' + w)));""",
    "webrtc": """const urls = ['%(stun)s', '%(stun_ip)s'];
const pc = new RTCPeerConnection({iceServers: [{urls}]});
const found = [];
pc.onicecandidate = (e) => { if (e.candidate) found.push(e.candidate.candidate); };
pc.createDataChannel('x');
pc.createOffer().then((o) => pc.setLocalDescription(o));
setTimeout(() => out('candidates=' + found.length +
  ' srflx=' + found.filter((c) => / typ srflx/.test(c)).length), 3000);""",
}


@dataclass
class World:
    """Everything one containment run needs."""

    session: sessions.Session
    running: RunningProxy
    upstream: PageServer
    host_server: PageServer
    trace: Path

    def read(self, name: str, timeout: float = 25) -> str:
        """Load probe page ``name`` and return what its script reported."""
        self.session.open(f"http://allowed.test/p/{name}")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for ref in self.session.snapshot().refs.values():
                if ref.role == "button" and ref.name.startswith("done: "):
                    return ref.name.removeprefix("done: ")
            time.sleep(0.2)
        message = f"probe {name} reported nothing"
        raise AssertionError(message)

    def refused(self) -> set[tuple[str, int]]:
        return self.running.refused()

    def finish(self) -> list[Attempt]:
        """Close the session and return the network calls its browser made."""
        self.session.close()
        return parse_strace(self.trace.read_text())


@pytest.fixture(scope="module")
def world() -> Iterator[World]:
    with tempfile.TemporaryDirectory(prefix="vk-") as directory:
        base = Path(directory)
        (base / "rt").mkdir(mode=0o700)
        roots = sites.Roots(base / "cfg", base / "state", base / "rt")
        paths = sessions.session_paths(roots, "demo")
        paths.proxy_socket.parent.mkdir(parents=True)
        # The browser may write into a site's hidden screenshots folder, which a session leaves be.
        shared = paths.screenshots_dir
        shared.mkdir(parents=True, mode=0o700)
        trace, wrapper = shared / "trace.txt", shared / "chromium"
        wrapper.write_text(
            "#!/bin/sh\n"
            f"exec /usr/bin/strace -f -s 0 -e trace={TRACED_CALLS} -o {trace} "
            '/usr/bin/chromium "$@"\n'
        )
        wrapper.chmod(0o755)
        with PageServer({"/secret": "host secret"}) as host_server:
            port = host_server.address[1]
            probes = {
                f"/p/{name}": PROBE
                % (body % {"ip": OFF_LIST_IP, "port": port, "stun": STUN, "stun_ip": STUN_IP})
                for name, body in BODIES.items()
            }
            pages = {"/": "<title>Home</title><p>allowed</p>", "/offlist": "<p>never</p>", **probes}
            redirects = {"/redir-https": "https://evil.test/", "/redir-http": "http://evil.test/r"}
            with (
                PageServer(pages, redirects) as upstream,
                _proxy(paths.proxy_socket, upstream) as running,
            ):
                session = sessions.Session.start(
                    roots, "demo", "http://allowed.test/", executable=str(wrapper), timeout=60
                )
                current = World(session, running, upstream, host_server, trace)
                try:
                    yield current
                finally:
                    session.close()


def _proxy(socket_path: Path, upstream: PageServer) -> RunningProxy:
    policy = sites.Policy("demo", "http://allowed.test/", ("allowed.test",))

    async def resolve(_host: str, _port: int) -> list[str]:
        return ["93.184.216.34"]  # a public address, so the real address check passes

    async def connect(_address: str, _port: int) -> proxy_module.Streams:
        return await asyncio.open_connection(*upstream.address)

    proxy = proxy_module.Proxy(
        policy,
        proxy_module.Mode.ENFORCE,
        resolver=resolve,
        connector=connect,
        quiet_hosts=sandbox.BACKGROUND_HOSTS,
    )
    return RunningProxy(proxy, socket_path)


@integration
@needs_everything
def test_the_allowed_site_loads(world: World) -> None:
    assert world.session.first_page.url == "http://allowed.test/"
    assert world.session.open("http://allowed.test/").title == "Home"


@integration
@needs_everything
def test_probes_see_success_on_the_allowed_host(world: World) -> None:
    """The probe pages can tell success from failure, so their failures mean something."""
    assert world.read("control") == "fulfilled,fulfilled"


@integration
@needs_everything
def test_navigation_to_an_unlisted_host_is_refused(world: World) -> None:
    with pytest.raises(sessions.AgentBrowserError, match="ERR_TUNNEL_CONNECTION_FAILED"):
        world.session.open("https://evil.test/")
    world.session.open("http://evil.test/offlist")  # the proxy answers 403 for the host
    assert {("evil.test", 443), ("evil.test", 80)} <= world.refused()
    assert "/offlist" not in world.upstream.hits
    assert world.session.current_url() != "http://allowed.test/offlist"


@integration
@needs_everything
def test_fetch_to_unlisted_hosts_fails(world: World) -> None:
    assert world.read("fetch") == "rejected,rejected"
    assert {("evil.test", 443), (OFF_LIST_IP, 443)} <= world.refused()


@integration
@needs_everything
def test_an_image_from_an_unlisted_host_does_not_load(world: World) -> None:
    assert world.read("image") == "error"


@integration
@needs_everything
def test_websockets_to_unlisted_hosts_do_not_open(world: World) -> None:
    assert world.read("socket") == "closed,closed"


@integration
@needs_everything
def test_a_redirect_to_an_unlisted_host_is_not_followed(world: World) -> None:
    with pytest.raises(sessions.AgentBrowserError, match="ERR_TUNNEL_CONNECTION_FAILED"):
        world.session.open("http://allowed.test/redir-https")
    world.session.open("http://allowed.test/redir-http")
    assert {("evil.test", 443), ("evil.test", 80)} <= world.refused()
    assert world.upstream.hits.count("/redir-http") == 1
    assert "/r" not in world.upstream.hits


@integration
@needs_everything
def test_a_server_on_the_hosts_loopback_is_unreachable(world: World) -> None:
    port = world.host_server.address[1]
    outcome = world.read("loopback")
    assert outcome.endswith(",closed")
    assert world.host_server.hits == []
    assert {("127.0.0.1", port), ("localhost", port)} <= world.refused()


@integration
@needs_everything
def test_webrtc_finds_no_server_reflexive_candidates(world: World) -> None:
    outcome = world.read("webrtc")
    assert outcome.endswith("srflx=0"), outcome


@integration
@needs_everything
def test_only_expected_hosts_were_refused(world: World) -> None:
    hosts = {host for host, _ in world.refused()}
    assert hosts <= {"evil.test", OFF_LIST_IP, "127.0.0.1", "localhost"}


@integration
@needs_everything
def test_no_network_call_left_the_namespace(world: World) -> None:
    attempts = world.finish()
    assert attempts, "the trace is empty, so the check proves nothing"
    assert any((a.address, a.port) == BRIDGE and a.outcome != "ENETUNREACH" for a in attempts)
    assert leaks(attempts) == [], dataclasses.asdict(leaks(attempts)[0])
    # Whatever tried to leave (resolver, DNS over HTTPS, mDNS) failed.
    stray = [a for a in attempts if (a.address, a.port) != BRIDGE]
    assert all(a.outcome not in NOT_FAILED for a in stray)


# --- the control: the same check, on a browser that is not contained ----------------------

CONTROL_PAGE = f"""<body><script>
const pc = new RTCPeerConnection({{iceServers: [{{urls: ['{STUN}', '{STUN_IP}']}}]}});
pc.createDataChannel('x');
pc.createOffer().then((o) => pc.setLocalDescription(o));
setTimeout(() => {{ document.body.textContent = 'waited'; }}, 5000);
</script></body>"""


def _has_internet_route() -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        try:
            probe.connect(("74.125.250.129", 19302))
        except OSError:
            return False
    return True


@integration
@needs_everything
@pytest.mark.skipif(
    not _has_internet_route(), reason="no route to the Internet, so there is nothing to leak to"
)
def test_the_check_finds_the_leak_when_there_is_no_namespace(tmp_path: Path) -> None:
    """Run Chromium with only a proxy flag, outside any namespace, and look for the leak."""
    with PageServer({"/": CONTROL_PAGE}) as page:
        url = f"http://127.0.0.1:{page.address[1]}/"
        outside = _run_without_namespace(tmp_path, url, page.address[1])
    # Chrome's DNS and WebRTC ignore the proxy flag, so a lookup reaches the machine's resolver.
    assert outside, (
        "the check found no leak in a browser that is not contained, so it cannot be trusted"
    )


def _run_without_namespace(tmp_path: Path, url: str, page_port: int) -> list[Attempt]:
    # The dummy proxy and the page server are ours; anything else, a resolver on the
    # loopback included, is the machine's network.
    ours = {("127.0.0.1", 9), ("127.0.0.1", page_port)}
    outside: list[Attempt] = []
    for attempt in range(3):  # Chrome's own lookups start at slightly different times
        trace = tmp_path / f"trace{attempt}.txt"
        command = [
            "strace", "-f", "-s", "0", "-e", f"trace={TRACED_CALLS}", "-o", str(trace),
            "chromium", "--headless=new", f"--user-data-dir={tmp_path / f'profile{attempt}'}",
            "--proxy-server=http://127.0.0.1:9",  # a flag alone contains nothing
            "--virtual-time-budget=9000", "--dump-dom", url,
        ]  # fmt: skip
        subprocess.run(command, capture_output=True, check=False, timeout=60)  # noqa: S603  # fixed list
        outside = [
            a for a in leaks(parse_strace(trace.read_text())) if (a.address, a.port) not in ours
        ]
        if outside:
            break
    return outside
