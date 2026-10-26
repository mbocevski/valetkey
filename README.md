# valetkey

valetkey gives an MCP client a web browser that is logged in to one site and can reach only the
hosts that site needs.

A valet key starts the car but does not open the trunk. valetkey hands out the same kind of key:
a browser session that is signed in to your account on one site, and that cannot send anything
anywhere else.

## Status

Early development. An MCP client can already open a logged-in site and use it. The `valetkey`
command can list sites and change which hosts each one may reach.

## Install

```sh
uv tool install valetkey
valetkey install-units
systemctl --user daemon-reload
systemctl --user enable --now valetkeyd.socket
valetkey doctor
```

`valetkey install-units` writes two systemd user units and prints the two `systemctl` commands
above without running them. The socket starts the daemon when a client connects. `valetkey doctor`
checks the rest of the setup.

On Arch Linux, `cd packaging/arch && makepkg -si` builds a package that installs the units for
you, so skip `valetkey install-units`. It downloads the locked Python dependencies into
`/usr/lib/valetkey` and needs `agent-browser` from the CachyOS repositories or the AUR package
`agent-browser-bin`.

## Usage

<!-- begin: valetkey --help -->
```text
Usage: valetkey COMMAND

A logged-in browser for MCP clients, contained to the sites it may reach.

Commands:
  allow: Allow a host, and its subdomains, for a site.
  daemon: Run the valetkeyd daemon in the foreground.
  deny: Stop allowing a host for a site.
  doctor: Check that this machine can run valetkey.
  forget: Delete a site's policy, login profile and downloads.
  install-units: Write the systemd user units that run the valetkey daemon.
  mcp: Serve the browser tools to an MCP client over standard input and output.
  sites: List the sites valetkey knows.
  status: Show the browser sessions and login windows that are open.
  watch: Print one JSON line for every change to the sessions and login windows.
  --help, -h: Display this message and exit.
  --version: Display application version.
```
<!-- end: valetkey --help -->

### Managing sites

`valetkey sites` lists each site with its start host, how many hosts it allows and excludes, when
they were last learned and whether a login profile exists. Add `--json` for a script.

`valetkey allow SITE HOST` lets a site reach another host and its subdomains, and removes any
excluded entry that would block it. `valetkey deny SITE HOST` takes a host away. When a wider
allowed entry still covers it, the host is also excluded so it stays blocked. Tool results mention Chrome's own
update checks on a separate line; allow the host only if a page needs it.

`valetkey forget SITE` deletes the site's policy, login profile and downloads after asking. It
closes the site's session first.

<!-- begin: valetkey sites --help -->
```text
Usage: valetkey sites [OPTIONS]

List the sites valetkey knows.

Each line shows the site name, the host it starts at, how many hosts are allowed
and excluded, when the hosts were last learned, and whether a login profile
exists. With --json, each site is an object with the keys site, host, allowed,
excluded, learned (a UTC time, or null) and profile (true or false).

Parameters:
  --json: Print a JSON array instead of a table. [default: False]
```
<!-- end: valetkey sites --help -->

<!-- begin: valetkey allow --help -->
```text
Usage: valetkey allow SITE HOST

Allow a host, and its subdomains, for a site.

Any excluded entry that would block the host is removed. Allowing a host that is
already listed changes nothing.

Parameters:
  SITE, --site: The site name, as shown by valetkey sites. [required]
  HOST, --host: A host name, or a URL on it. [required]
```
<!-- end: valetkey allow --help -->

<!-- begin: valetkey deny --help -->
```text
Usage: valetkey deny SITE HOST

Stop allowing a host for a site.

The host's own entry is removed from the allowed hosts. If a wider allowed entry
still covers the host (app.example.com under example.com), the host is also
added to the excluded hosts, so it stays blocked. Otherwise nothing more is
needed.

Parameters:
  SITE, --site: The site name, as shown by valetkey sites. [required]
  HOST, --host: A host name, or a URL on it. [required]
```
<!-- end: valetkey deny --help -->

<!-- begin: valetkey forget --help -->
```text
Usage: valetkey forget [OPTIONS] SITE

Delete a site's policy, login profile and downloads.

It asks first, and refuses when input is not a terminal unless --yes is given.
If valetkeyd is running it closes the site's session before deleting. It refuses
while a login window is open, and while a browser that valetkeyd does not own is
using the profile.

Parameters:
  SITE, --site: The site name, as shown by valetkey sites. [required]
  --yes: Delete without asking. [default: False]
```
<!-- end: valetkey forget --help -->

### Setting up

`valetkey install-units` replaces only unit files it wrote itself, unless you pass `--force`. Add
`--dry-run` to see the files first. `valetkey doctor` prints one line per check and exits with
status 1 when a required check fails. A missing Wayland display is only a warning, because only
logging in needs one.

<!-- begin: valetkey install-units --help -->
```text
Usage: valetkey install-units [OPTIONS]

Write the systemd user units that run the valetkey daemon.

The units go to the systemd user directory ($XDG_CONFIG_HOME/systemd/user). The
command refuses to replace a file it did not write, and prints the commands that
start the socket. It never runs them.

Parameters:
  --dry-run: Print the files instead of writing them. [default: False]
  --force: Replace files that valetkey did not write. [default: False]
```
<!-- end: valetkey install-units --help -->

<!-- begin: valetkey doctor --help -->
```text
Usage: valetkey doctor [OPTIONS]

Check that this machine can run valetkey.

Each check prints one line: ok, FAIL, warn or info. Required checks are
bubblewrap and user namespaces, Chromium, agent-browser 0.39 or newer, and
XDG_RUNTIME_DIR. A missing Wayland display is a warning, because only logging in
needs one, and so is an agent-browser newer than 0.39.2, the version valetkey
was tested with. The state of the systemd units is shown for information. The
exit status is 1 when a required check fails. With --json, each check is an
object with the keys check, status (ok, fail, warn or info) and detail.

Parameters:
  --json: Print a JSON array instead of lines. [default: False]
```
<!-- end: valetkey doctor --help -->

### Seeing what runs

<!-- begin: valetkey status --help -->
```text
Usage: valetkey status [OPTIONS]

Show the browser sessions and login windows that are open.

The daemon reports what its own processes are doing, and nothing can hide a
session from it. A browser that was killed disappears within a second or two.
The daemon is not started: when none runs, this says so and exits 0.

With --json the output is an object with two lists. "sessions" holds objects
with the keys site, since, contained and host. "logins" holds objects with the
keys site and since. since is a UTC time like 2026-10-26T09:00:00Z. contained is
always true. host is the host of the page the browser was last reported at,
never the whole address, which may carry a token.

Parameters:
  --json: Print JSON instead of a table. [default: False]
```
<!-- end: valetkey status --help -->

<!-- begin: valetkey watch --help -->
```text
Usage: valetkey watch

Print one JSON line for every change to the sessions and login windows.

The first line is a snapshot of what is open, as status --json shows it, with
"event" set to "snapshot" and an "at" time. After that each line has the keys
event, site and at, where event is session_started, session_ended, login_opened
or login_closed. Bars and indicators can read the lines as they come. The
command runs until it is interrupted or the daemon stops; it exits 1 when no
daemon is running, and does not start one.
```
<!-- end: valetkey watch --help -->

### Use it from an MCP client

Add `valetkey mcp` to the client as a stdio server. In clients that read a JSON config:

```json
{"mcpServers": {"valetkey": {"command": "valetkey", "args": ["mcp"]}}}
```

Clients with a command line can add it the same way, with `valetkey mcp` as the command. With the
systemd socket from Install enabled, the daemon starts on the first connection and `valetkey mcp`
never has to start it. Without the socket, `valetkey mcp` starts `valetkey daemon` itself, and the
daemon keeps running so several clients can share it.

The tools are `browser_sites`, `browser_login`, `browser_open`, `browser_snapshot`,
`browser_click`, `browser_type`, `browser_navigate`, `browser_downloads`, `browser_screenshot` and
`browser_close`. `browser_click` finds its element again when it clicks and can check an `expect`ed
outcome. `browser_open` says when a saved login has expired. Nothing runs scripts, changes launch
options or edits a site's hosts. A host that is not allowed is for you to decide, with
`valetkey allow SITE HOST`.

<!-- begin: valetkey mcp --help -->
```text
Usage: valetkey mcp

Serve the browser tools to an MCP client over standard input and output.

Point an MCP client at this command. It starts valetkeyd if that is not running
yet.
```
<!-- end: valetkey mcp --help -->

## How it will work

You log in once. valetkey opens an ordinary browser window on your desktop, you sign in, with
two-factor authentication if the site asks for it, and you close the window. The session stays in
a browser profile that belongs to that site alone.

After that, an MCP client can open the site, read pages, click and type in a headless browser that
is already signed in.

Each browser runs in its own Linux network namespace. Its only connection to the outside is a
proxy that allows the site's hosts and refuses everything else, including DNS lookups, WebRTC and
connections to services on your machine. When a page needs a host that is not allowed, the client
can ask for it, and only you can say yes.

## Requirements

- Linux with unprivileged user namespaces enabled
- Python 3.14 or newer, and [uv](https://docs.astral.sh/uv/)
- [bubblewrap](https://github.com/containers/bubblewrap)
- Chromium
- [agent-browser](https://github.com/vercel-labs/agent-browser) 0.39 or newer, tested with 0.39.2
- A Wayland desktop, to log in

## Development

```sh
just setup   # install dependencies and git hooks
just check   # linters, type checks and prose checks
just test    # tests with coverage
just ci      # the CI workflow, locally, with act
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
