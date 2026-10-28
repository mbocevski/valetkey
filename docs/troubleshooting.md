# Troubleshooting

Start with `valetkey doctor`. It prints one line per check and says which one failed. Back to the
[README](../README.md).

## Bubblewrap cannot make a sandbox

The check `namespaces` fails with a message from bubblewrap, such as "No permissions to create a
new namespace".

valetkey needs unprivileged user namespaces. Some kernels switch them off, and some security
policies restrict them. The bubblewrap message names the setting for your kernel, for example
`kernel.unprivileged_userns_clone` on Debian. Enable it with `sysctl`, run `valetkey doctor`
again, and keep it across reboots in a file under `/etc/sysctl.d`.

Inside a container, user namespaces are usually blocked by the container's own filter. Run
valetkey on the host or give the container the privileges bubblewrap needs.

## The agent-browser version

`valetkey doctor` fails when agent-browser is older than the version the README names as the
minimum. Install a newer one from the CachyOS repositories, the AUR package `agent-browser-bin` or
the agent-browser releases.

A version newer than the one valetkey was tested with is a warning. It usually works. The daemon
logs the same warning once, and the tests in `tests/test_agent_browser_drift.py` show what to check
after an upgrade.

## The client starts valetkey with a reduced environment

Some MCP clients start a server with only `HOME`, `PATH` and a few more variables. Then
`browser_sites` fails with "XDG_RUNTIME_DIR is not set", and `valetkey doctor` warns about the
`runtime-dir` check.

valetkey copes with the common cases. Without `XDG_RUNTIME_DIR` it uses `/run/user/UID`, but only
when that is your own private directory. When it has to start the daemon itself, it fills in
`WAYLAND_DISPLAY`, `DISPLAY` and `DBUS_SESSION_BUS_ADDRESS` from the systemd user manager, and
adds `~/.local/bin` and the manager's `PATH` to the daemon's. If the socket is enabled
(`systemctl --user enable --now valetkeyd.socket`), systemd starts the daemon with your session's
environment and none of this is needed.

If it still fails, set the variables in the client's configuration for the server, in the
`env` block of its entry: `XDG_RUNTIME_DIR` (such as `/run/user/1000`), `WAYLAND_DISPLAY` and
`DBUS_SESSION_BUS_ADDRESS`. If the client cannot find `valetkey`, give the full path of the
program as the command.

## No Wayland display

Logging in opens a window on your desktop, so `browser_login` fails without one. The message says
there is no desktop session, or that only X11 is available. valetkey refuses X11 because an X11
client can read every keystroke on the screen.

Log in from a Wayland session. If you are, the daemon may not see its variables. It reads
`WAYLAND_DISPLAY` and `XDG_RUNTIME_DIR` from its own environment and from the systemd user
manager's. When you start the desktop yourself, run
`systemctl --user import-environment WAYLAND_DISPLAY` from inside it.

A missing display only blocks logging in. Sessions for a site you have already logged in to run
headless and do not need one. A browser that the site has running is left alone when no login
window can open. On a machine with no screen, see [remote logins](remote.md).

## A login does not open on the laptop

Check the three parts. `valetkey status` on the server must list the bridge. The server's
`config.json` must say `{"remote_logins": {"waypipe": true}}`, because without it `browser_login`
fails with `no_display` even with a bridge connected. And the machine must have no screen of its
own, since a local screen comes first. [Remote logins](remote.md) has the steps.

## The login has expired

`browser_open` says the saved login has expired when the start page sent the browser to a sign-in
page, or when none of the sign-in cookies that the login recorded is left in the profile. In the
second case no browser is started. The agent calls `browser_login` again, and you sign in again in
the window that opens.

A site that shows its sign-in form on the start page itself, and keeps its cookies, is not noticed.
Nothing tells a form there from a sign-in box on a public front page. The agent still sees the
form in the page and calls `browser_login`.

## The session is not signed in after a login

A site that keeps you signed in only until the browser is closed sets a cookie with no expiry.
A browser forgets such a cookie when it exits, unless it is set to continue where it left off.
valetkey sets that on every site's profile before it starts the login window or a session, so
the cookie reaches the session. A login made by an older version lost its cookie when the window
closed, and the profile does not have it. Sign in again once, with `browser_login`.

## A page needs a host that is refused

The browser tools list refused hosts after a load, and a page that could not load starts with
"The page did not load: HOST is not allowed for SITE". Requests Chrome makes on its own are listed
on a separate line; ignore those unless a page needs them. If a page does need a refused host,
the agent can ask with `browser_allow`, or you can run `valetkey allow SITE HOST`.

An intranet site fails with "resolves to a private address". The name is allowed, but the address
is private. See [Private networks](security.md) and run
`valetkey allow SITE --private-network RANGE` with the narrowest range that holds the address.
Before the first login, run `valetkey add SITE START --private-network RANGE` instead.

## A tool says the session was closed

A session that nothing uses for 15 minutes is closed, and the next call says so and asks the agent
to call `browser_open`. That is normal, and the agent does it without asking. The login stays
saved. To change the time, set `session_idle_minutes` in `config.json`.

## The microphone does not work

Run `valetkey doctor`. When a site has the microphone on, it fails if PipeWire, WirePlumber, `pactl`
or `bwrap` is missing, and warns if your audio server has no socket at `$XDG_RUNTIME_DIR/pulse/native`.

If `browser_open` fails with "its audio did not start", the message ends with the log of the
session's audio graph. A graph needs the same user namespaces as the browser, and your default
microphone must exist. A call that records silence usually has the microphone muted or turned
down on your side. The graph copies the microphone you have set as the default when the session
starts, so change the default first and open the site again. `valetkey status --json` shows
`capture` for a session with the microphone: its `node` is `null` until a page records.

## The browser does not start on a busy machine

On a heavily loaded machine the browser may take longer to start than agent-browser waits, which
is 30 seconds. valetkey then starts it once more. If both starts fail, `browser_open` reports
"Failed to read: Resource temporarily unavailable". Try again when the load is lower.

## The daemon does not start

With the systemd socket, look at the service log:

```sh
systemctl --user status valetkeyd.socket
journalctl --user -u valetkeyd.service
```

When `valetkey mcp` started the daemon itself, its log is `$XDG_RUNTIME_DIR/valetkey/daemon.log`.
A message that the daemon is already running is harmless: two clients started at once, and one
of them won.

`valetkey status` printing "valetkeyd is not running" is normal when no session was started. The
command never starts the daemon.
