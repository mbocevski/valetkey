# Commands

Every command prints its own help with `--help`. The blocks on this page are that help, kept
current by the checks. Back to the [README](../README.md).

<!-- begin: valetkey --help -->
```text
Usage: valetkey COMMAND

A logged-in browser for MCP clients, contained to the sites it may reach.

Commands:
  add: Create a site before its first login, for one on a private network.
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

## Listing sites

`valetkey sites` lists each site with its start host, how many hosts it allows and excludes, the
private address ranges it may reach, when the hosts were last learned and whether a login
profile exists. Add `--json` for a script.

<!-- begin: valetkey sites --help -->
```text
Usage: valetkey sites [OPTIONS]

List the sites valetkey knows.

Each line shows the site name, the host it starts at, how many hosts are allowed
and excluded, when the hosts were last learned, the private address ranges it
may reach (a dash for none), and whether a login profile exists. With --json,
each site is an object with the keys site, host, allowed, excluded, learned (a
UTC time, or null), private_networks (a list) and profile (true or false).

Parameters:
  --json: Print a JSON array instead of a table. [default: False]
```
<!-- end: valetkey sites --help -->

## Allowing and denying hosts

`valetkey allow SITE HOST` lets a site reach another host and its subdomains, and removes any
excluded entry that would block it. `valetkey deny SITE HOST` takes a host away. When a wider
allowed entry still covers the host, it is also excluded so that it stays blocked.

`valetkey allow SITE --private-network RANGE` lets the site's allowed hosts resolve to addresses
in a private range such as `10.20.0.0/24`. Use the narrowest range that holds the address. See
[Security](security.md) for why only you can do this. Both commands act on a running daemon at
once.

<!-- begin: valetkey allow --help -->
```text
Usage: valetkey allow [OPTIONS] SITE [ARGS]

Allow a host, and its subdomains, for a site.

Any excluded entry that would block the host is removed. Allowing a host that is
already listed changes nothing. With --private-network and a range such as
10.20.0.0/24 instead of a host, the site's allowed hosts may also resolve to
addresses in that range, which they otherwise may not because it is private. Use
the narrowest range that holds the address. Only private ranges are accepted,
none wider than /8 (IPv6: /48).

Parameters:
  SITE, --site: The site name, as shown by valetkey sites. [required]
  HOST, --host: A host name, or a URL on it.
  --private-network STR: A private address range such as 10.20.0.0/24, instead
of a host.
```
<!-- end: valetkey allow --help -->

<!-- begin: valetkey deny --help -->
```text
Usage: valetkey deny [OPTIONS] SITE [ARGS]

Stop allowing a host for a site.

The host's own entry is removed from the allowed hosts. If a wider allowed entry
still covers the host (app.example.com under example.com), the host is also
added to the excluded hosts, so it stays blocked. Otherwise nothing more is
needed. With --private-network and a range instead of a host, the range is no
longer listed.

Parameters:
  SITE, --site: The site name, as shown by valetkey sites. [required]
  HOST, --host: A host name, or a URL on it.
  --private-network STR: A private address range such as 10.20.0.0/24, instead
of a host.
```
<!-- end: valetkey deny --help -->

## Adding a site

A site is normally created by logging in. A site on a private network cannot be, because the login
proxy refuses private addresses until you list their range. `valetkey add SITE START
--private-network RANGE` creates the site first, with its start URL and the ranges, and then your
client can log in to it. It refuses a site that already exists unless you pass `--force`, which
replaces the policy and keeps the login. Only you can run it.

<!-- begin: valetkey add --help -->
```text
Usage: valetkey add [OPTIONS] SITE START

Create a site before its first login, for one on a private network.

A site is normally created by logging in. A site whose host resolves to a
private address cannot be logged in to that way, because the login proxy refuses
private addresses unless the person lists their range. This writes the site's
policy with its start URL, its start host and the ranges, and nothing else; then
log in to it. Only you can do this: a client cannot create a site or list a
range. It refuses a site that already exists, unless --force, which replaces the
policy and keeps the login profile.

Parameters:
  SITE, --site: The new site's name: lowercase letters, digits and hyphens.
[required]
  START, --start: The URL the login starts at. [required]
  --private-network STR...: A private address range the site may reach, such as
10.20.0.0/24. Repeat it.
  --force: Replace the policy of an existing site. [default: False]
```
<!-- end: valetkey add --help -->

## Forgetting a site

`valetkey forget SITE` deletes the site's policy, login profile and downloads after asking. It
closes the site's session first, and refuses while a login window is open.

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

## Setting up

`valetkey install-units` writes the systemd user units. `valetkey doctor` checks that the
machine can run valetkey. See [Install](install.md) for both.

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

## Seeing what runs

`valetkey status` lists the open browser sessions and login windows. `valetkey watch` prints one
JSON line for each start or end, which a status bar can read. Both ask the daemon and never start
it. Nothing can hide a session from them. When a session starts, `notify-send` shows a desktop
notification if it is installed.

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

## The daemon and the MCP server

`valetkey daemon` runs the background process that owns every session and login. Systemd starts
it from the socket, so you rarely run it yourself. `valetkey mcp` is the server an MCP client
starts. See [MCP clients](mcp.md).

<!-- begin: valetkey daemon --help -->
```text
Usage: valetkey daemon [OPTIONS]

Run the valetkeyd daemon in the foreground.

It owns every session for the user. It listens on a Unix socket in the runtime
directory until it gets SIGTERM or SIGINT. Under systemd socket activation it
uses the socket systemd passes in.

Parameters:
  --socket PATH: Listen on this socket path.
```
<!-- end: valetkey daemon --help -->

<!-- begin: valetkey mcp --help -->
```text
Usage: valetkey mcp

Serve the browser tools to an MCP client over standard input and output.

Point an MCP client at this command. It starts valetkeyd if that is not running
yet.
```
<!-- end: valetkey mcp --help -->
