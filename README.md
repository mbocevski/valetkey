# valetkey

valetkey gives an MCP client a web browser that is logged in to one site and can reach only the
hosts that site needs.

A valet key starts the car but does not open the trunk. valetkey hands out the same kind of key:
a browser session that is signed in to your account on one site, and that cannot send anything
anywhere else.

Three things hold for every session:

- The browser is signed in as you, on one site, in a profile that belongs to that site alone.
- It reaches only the hosts that site needs. Everything else is refused, DNS lookups included.
- You decide about anything more. The agent can ask for a host, and only you can say yes.

valetkey is early software. An MCP client can already open a logged-in site, read it, click, type
and download files.

## Install

On Arch Linux or CachyOS, build the package from the checkout:

```sh
cd packaging/arch && makepkg -si
systemctl --user enable --now valetkeyd.socket
valetkey doctor
```

After a `git pull`, run `makepkg -si` again to build the new code.

On other Linux systems, install from the checkout with uv:

```sh
uv tool install .
valetkey install-units
systemctl --user daemon-reload
systemctl --user enable --now valetkeyd.socket
valetkey doctor
```

`valetkey doctor` checks the requirements and says what to fix:

- Linux with unprivileged user namespaces enabled
- Python 3.14 or newer, and [uv](https://docs.astral.sh/uv/)
- [bubblewrap](https://github.com/containers/bubblewrap)
- Chromium
- [agent-browser](https://github.com/vercel-labs/agent-browser) 0.39 or newer, tested with 0.39.4
- A Wayland desktop, to log in

The [install page](docs/install.md) says what each route installs and how to remove it.

## Connect an MCP client

Add `valetkey mcp` to the client as a stdio server. In clients that read a JSON config:

```json
{"mcpServers": {"valetkey": {"command": "valetkey", "args": ["mcp"]}}}
```

The daemon starts on the first connection. The [MCP page](docs/mcp.md) lists the tools and
explains how the agent asks for a host.

## Log in and use it

1. Ask the agent to log in to a site. A browser window opens on your desktop.
2. Sign in, with two-factor authentication if the site asks for it, and close the window. valetkey
   says which hosts it will allow: the site and the sign-in provider the window visited.
3. The agent opens the site in a headless browser that is already signed in. It reads pages,
   clicks, types and downloads files into the site's folder.
4. When a page needs a host that is not allowed, the agent can ask. You answer in your client or
   through a command you set up, or you run `valetkey allow SITE HOST` yourself.
5. When the site forgets you, `browser_open` says the login expired, and the agent logs in again.

`valetkey status` shows the open sessions at any time, and nothing can hide one.

## What it contains

Each browser runs in its own Linux network namespace. Its only connection to the outside is a proxy
that allows the site's hosts and refuses the rest, including private addresses, WebRTC and services
on your machine. Page text reaches the agent labelled as untrusted data.

Pages the browser already cached still render, no tool uploads files, and a login window is refused
on X11. A process running as your user can change a site's hosts with `valetkey allow`, so keep
a shell away from the agent if that matters. The [security page](docs/security.md) has the details.

## More documentation

- [Install](docs/install.md): what each route installs, the systemd units and removal
- [Commands](docs/commands.md): every command with its help, and adding a site on a private network
- [MCP clients](docs/mcp.md): the tools, approvals and private networks
- [Security](docs/security.md): what is contained, and who decides
- [Remote logins](docs/remote.md): log in on your laptop, or in a browser tab, for a daemon on a server
- [Troubleshooting](docs/troubleshooting.md): when `valetkey doctor` fails or a login does not open

## Development and license

```sh
just setup   # install dependencies and git hooks
just check   # linters, type checks and prose checks
just test    # tests with coverage
just ci      # the CI workflow, locally, with act
```

valetkey is licensed under the Apache License 2.0. See [LICENSE](LICENSE). Contributors, start with
[AGENTS.md](AGENTS.md).
