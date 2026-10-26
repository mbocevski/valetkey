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

## No Wayland display

Logging in opens a window on your desktop, so `browser_login` fails without one. The message says
there is no desktop session, or that only X11 is available. valetkey refuses X11 because an X11
client can read every keystroke on the screen.

Log in from a Wayland session. If you are, the daemon may not see its variables. It reads
`WAYLAND_DISPLAY` and `XDG_RUNTIME_DIR` from its own environment and from the systemd user
manager's. When you start the desktop yourself, run
`systemctl --user import-environment WAYLAND_DISPLAY` from inside it.

A missing display only blocks logging in. Sessions for a site you have already logged in to run
headless and do not need one.

## The login has expired

`browser_open` says the saved login has expired when the start page sent the browser to a sign-in
page. The agent calls `browser_login` again, and you sign in again in the window that opens.

A site that shows its sign-in form on the start page itself is not noticed this way, because
nothing tells a form there from a sign-in box on a public front page. The agent still sees the
form in the page and calls `browser_login`.

## A page needs a host that is refused

The browser tools list refused hosts after a load. Tool results also mention Chrome's own update
checks on a separate line; ignore those unless a page needs them. If a page does need a refused
host, the agent can ask with `browser_allow`, or you can run `valetkey allow SITE HOST`.

An intranet site fails with "resolves to a private address". The name is allowed, but the address
is private. See [Private networks](security.md) and run
`valetkey allow SITE --private-network RANGE` with the narrowest range that holds the address.
Before the first login, run `valetkey add SITE START --private-network RANGE` instead.

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
