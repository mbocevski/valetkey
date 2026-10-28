# Commands

Every command prints its own help with `--help`. The blocks on this page are that help, kept
current by the checks. Back to the [README](../README.md).

<!-- begin: valetkey --help -->
```text
Usage: valetkey COMMAND

A logged-in browser for MCP clients, contained to the sites it may reach.

Commands:
  add: Create a site or another account of one before its first login.
  allow: Allow a host, and its subdomains, for a site.
  bridge: Take login windows from a server onto this desktop, until stopped.
  daemon: Run the valetkeyd daemon in the foreground.
  deny: Stop allowing a host for a site, and keep it blocked.
  doctor: Check that this machine can run valetkey.
  forget: Delete a site's policy, login profile and downloads.
  install-units: Write the systemd user units that run the valetkey daemon.
  mcp: Serve the browser tools to an MCP client over standard input and output.
  mic: Show, turn on or turn off the microphone for a site.
  sites: List the sites valetkey knows.
  status: Show the browser sessions, login windows and bridges that are open.
  watch: Print one JSON line for every change to the sessions, login windows and
bridges.
  --help, -h: Display this message and exit.
  --version: Display application version.
```
<!-- end: valetkey --help -->

## Listing sites

`valetkey sites` lists each site with its start host, how many hosts it allows, excludes and denies,
and the private address ranges it may reach. It also shows when the hosts were last learned,
whether the microphone is on, and whether a login profile exists. Add `--json` for a script. `valetkey sites SITE` prints that one site's complete
lists instead, one host to a line: the hosts it may reach, the hosts its last login left out and
the hosts you denied. With `--json` that is one object.

<!-- begin: valetkey sites --help -->
```text
Usage: valetkey sites [OPTIONS] [ARGS]

List the sites valetkey knows.

Each line shows the site name, the host it starts at, how many hosts are
allowed, excluded by a login and denied by you, when the hosts were last
learned, the private address ranges it may reach (a dash for none), and whether
a login profile exists. With --json, each site is an object with the keys site,
account (the part after the colon of sitex:work, or null), host, allowed,
excluded, denied, learned (a UTC time, or null), private_networks (a list),
microphone (true or false), microphone_source (a name, or null for the default
source) and profile (true or false). A site with several accounts has a line for
each.

With a site, it prints that one site's complete lists instead: the hosts it may
reach, the hosts its last login left out and the hosts you denied, one to a
line. With --json, that is one object with the keys of a row above, but with
allow, excluded and denied as lists of hosts.

Parameters:
  SITE, --site: One site, as shown by valetkey sites, with its account
(sitex:work) when the
  site has more than one. Leave it out to list every site.
  --json: Print a JSON array instead of a table. [default: False]
```
<!-- end: valetkey sites --help -->

## Allowing and denying hosts

`valetkey allow SITE HOST` lets a site reach another host and its subdomains, and removes any
excluded or denied entry that would block it. `valetkey deny SITE HOST` takes a host away and adds it to the
site's denied hosts, which block it even under a wider allowed entry. A login never allows a denied
host again; `valetkey allow` does.

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
  SITE, --site: The site name, as shown by valetkey sites, with its account
(sitex:work) when
  the site has more than one. [required]
  HOST, --host: A host name, or a URL on it.
  --private-network STR: A private address range such as 10.20.0.0/24, instead
of a host.
```
<!-- end: valetkey allow --help -->

<!-- begin: valetkey deny --help -->
```text
Usage: valetkey deny [OPTIONS] SITE [ARGS]

Stop allowing a host for a site, and keep it blocked.

The host's own entry is removed from the allowed hosts and the host is added to
the denied hosts, which block it even under a wider allowed entry
(app.example.com under example.com). A login never allows a denied host again;
valetkey allow does. With --private-network and a range instead of a host, the
range is no longer listed.

Parameters:
  SITE, --site: The site name, as shown by valetkey sites, with its account
(sitex:work) when
  the site has more than one. [required]
  HOST, --host: A host name, or a URL on it.
  --private-network STR: A private address range such as 10.20.0.0/24, instead
of a host.
```
<!-- end: valetkey deny --help -->

## The microphone

A session has no microphone until you turn one on for its site. `valetkey mic SITE on` turns it
on, `valetkey mic SITE off` turns it off, and `valetkey mic SITE` shows the setting. It applies to
sessions that start afterwards; a running session keeps what it started with. Only you can turn it
on. An agent can ask, and you answer. A session with it on gets an audio graph of its own, with the
microphone and a silent output in it, and nothing else of your audio (see [Security](security.md)).
It needs PipeWire with its PulseAudio server, and WirePlumber, on your machine. `valetkey doctor`
checks for them when some site has the microphone on.

The microphone copies your default source. `valetkey mic SITE on --source NAME` makes it copy the
source you name instead, such as the monitor of an output that mixes a call with your microphone.
A session of a site whose source does not exist fails to open and says so, and never falls back to
the default. `valetkey mic SITE on` without `--source` goes back to the default, and `off` clears
it. `valetkey doctor` warns about a source your audio server does not have. Only you can name a
source (see [Security](security.md)).

<!-- begin: valetkey mic --help -->
```text
Usage: valetkey mic [OPTIONS] SITE [ARGS]

Show, turn on or turn off the microphone for a site.

With the microphone on, the site's browser sessions can record what the
microphone hears, and nothing else of the machine's audio: each session gets a
private audio graph with the microphone and a silent output in it. It applies to
sessions that start afterwards; a running one keeps its setting until it is
closed. The setting is off for every site until you turn it on, and an agent can
only ask you to. Without a setting this prints the current one.

With --source NAME the microphone copies that source of your audio server
instead of the default one, such as the monitor of an output that mixes a call
with your microphone. A named source can carry anything you hear, so only you
can set it: an agent cannot ask for one. A session fails to start, and says so,
when the source does not exist; it never falls back to the default. on without
--source goes back to the default, and off clears it.

Parameters:
  SITE, --site: The site name, as shown by valetkey sites, with its account
(sitex:work) when
  the site has more than one. [required]
  SETTING, --setting: on or off. Leave it out to show the setting. [choices: on,
off]
  --source STR: With on: the source on your audio server that the microphone
copies.
```
<!-- end: valetkey mic --help -->

## Adding a site

A site is normally created by logging in. A site on a private network cannot be, because the login
proxy refuses private addresses until you list their range. `valetkey add SITE START
--private-network RANGE` creates the site first, with its start URL and the ranges, and then your
client can log in to it. It refuses a site that already exists unless you pass `--force`, which
replaces the policy and keeps the login. Only you can run it.

## Accounts

A site can have more than one account, such as `sitex` and `sitex:work`. Each has its own login,
policy and downloads, so approving a host for one never allows it for the other. The commands that
take a site name (`allow`, `deny`, `forget`, `add`) take `sitex:work` too. While a site has one
account its bare name works. Once it has several, a bare name is refused, and the account that
existed first is written `sitex:main`. An account label starts with a letter, so `intranet:8080`
is always a host and a port.

`valetkey add sitex:work START --copy-hosts-from sitex` creates the account with the allowed, excluded and
denied hosts of another account, and nothing else: not its private ranges, and not what its
login learned. `valetkey forget sitex:work` deletes that account only.

<!-- begin: valetkey add --help -->
```text
Usage: valetkey add [OPTIONS] SITE START

Create a site or another account of one before its first login.

A site is normally created by logging in. A site whose host resolves to a
private address cannot be logged in to that way, because the login proxy refuses
private addresses unless the person lists their range. This writes the site's
policy with its start URL, its start host and the ranges, and nothing else; then
log in to it. Only you can do this: a client cannot create a site or list a
range. It refuses a site that already exists, unless --force, which replaces the
policy and keeps the login profile.

A site can have more than one account, each with its own login, policy and
downloads. Name one sitex:work. With --copy-hosts-from the new account starts
with the allowed, excluded and denied hosts of another account of the site, and
with nothing else of it: not its private ranges, which are a permission of their
own, and not what its login learned.

Parameters:
  SITE, --site: The new site's name, with an account after a colon for another
account of a site
  (sitex:work): lowercase letters, digits and hyphens. An account starts with a
  letter. [required]
  START, --start: The URL the login starts at. [required]
  --private-network STR...: A private address range the site may reach, such as
10.20.0.0/24. Repeat it.
  --copy-hosts-from STR: Start with the host lists of this other account of the
site.
  --force: Replace the policy of an existing site. [default: False]
```
<!-- end: valetkey add --help -->

## Bridging a server

`valetkey bridge SERVER` takes login windows from a daemon on a server onto this desktop. It runs
until stopped, usually as a service. [Remote logins](remote.md) explains what it does and what
you need. `valetkey install-units --bridge` writes the unit that runs it. The `bridge-hold` command
is what ssh runs on the server; you never run it yourself.

<!-- begin: valetkey bridge --help -->
```text
Usage: valetkey bridge [OPTIONS] HOST

Take login windows from a server onto this desktop, until stopped.

Run it on the machine you sit at, as the service valetkey-bridge@HOST (see
valetkey install-units --bridge). It starts waypipe here and keeps an ssh
connection to HOST, which needs valetkey, key-based login and no password. A
login that valetkeyd on HOST starts then opens as a window here. waypipe always
runs with a security context, so the server's programs cannot capture your
screen. A dropped connection is tried again, after waits of up to a minute.

Parameters:
  HOST, --host: The server, as ssh knows it. [required]
  --remote-runtime PATH: The server's XDG_RUNTIME_DIR, such as /run/user/1000.
Asked for by default.
```
<!-- end: valetkey bridge --help -->

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
start the socket. It never runs them. With --bridge it writes the one unit that
runs the bridge for logins from a server, valetkey-bridge@.service, and not the
daemon's units.

Parameters:
  --dry-run: Print the files instead of writing them. [default: False]
  --force: Replace files that valetkey did not write. [default: False]
  --bridge: Write the unit of the bridge for logins from a server, on your
laptop. [default: False]
```
<!-- end: valetkey install-units --help -->

<!-- begin: valetkey doctor --help -->
```text
Usage: valetkey doctor [OPTIONS]

Check that this machine can run valetkey.

Each check prints one line: ok, FAIL, warn or info. Required checks are
bubblewrap and user namespaces, Chromium, agent-browser 0.39 or newer, and
XDG_RUNTIME_DIR. A missing Wayland display is a warning, because only logging in
needs one, and so is a compositor without security-context support, where the
login window is not restricted, and an agent-browser newer than 0.40.0, the
version valetkey was tested with, and so is a CPU other than x86_64, where the
sandbox has no syscall filter. When a site has the microphone on, the programs
its audio needs must be installed (a failure if not) and the audio server's
socket must exist (a warning if not). The state of the systemd units is shown
for information. A config.json that others can write to is ignored and fails.
The exit status is 1 when a required check fails. With --json, each check is an
object with the keys check, status (ok, fail, warn or info) and detail.

Parameters:
  --json: Print a JSON array instead of lines. [default: False]
```
<!-- end: valetkey doctor --help -->

## Seeing what runs

`valetkey status` lists the open browser sessions and login windows. `valetkey watch` prints one
JSON line for each start or end, which a status bar can read. Both ask the daemon and never start
it. `valetkey watch --wait` does not exit when there is no daemon: it waits for one, prints
`{"event":"daemon_stopped"}` when it ends, and prints the snapshot again when the next one runs. Nothing can hide a session from them. When a session starts, `notify-send` shows a desktop
notification if it is installed.

A session that nothing uses is closed after `session_idle_minutes` minutes, 15 unless you set it
in `config.json` to a whole number from 1 to 1440. `status` shows each session's idle time and the
time it will close, and `microphone` on a session that has one.

For a session with the microphone, `status --json` also gives its capture stream: the session's
private audio socket and the node the browser records with. A recorder that wants the call's audio
looks there instead of guessing from process names. `watch` says whether each session that starts
has the microphone, and the start notification says so too.

<!-- begin: valetkey status --help -->
```text
Usage: valetkey status [OPTIONS]

Show the browser sessions, login windows and bridges that are open.

The daemon reports what its own processes are doing, and nothing can hide a
session from it. A browser that was killed disappears within a second or two.
The daemon is not started: when none runs, this says so and exits 0.

With --json the output is an object with three lists. "sessions" holds objects
with the keys site, since, contained, host, microphone, source, idle_seconds and
closes_at. "source" is the source the microphone copies, or null for the default
one. A session with the microphone on also has "capture", where a recorder finds
its capture stream: "socket" is the session's private PulseAudio socket,
"directory" holds its PipeWire socket, and "node" is the number of the PipeWire
node the browser records with, or null while nothing records. "logins" holds
objects with the keys site and since. "bridges" holds objects with the keys
bridge and since, one for each laptop connected to take login windows. since is
a UTC time like 2026-10-26T09:00:00Z. contained is always true. host is the host
of the page the browser was last reported at, never the whole address, which may
carry a token. idle_seconds is how long nothing has used the session, and
closes_at is the UTC time the daemon will close it if nothing does: after
session_idle_minutes in config.json, 15 by default.

A login shown in a web browser has a link that works like a password: whoever
opens it can type into the login window. The table prints it under the table,
with the ssh command that makes it reachable. --json leaves it out unless
--show-links is given, so a script that logs its input does not keep it.

A saved site that lists a public suffix such as github.io is named below the
table, because valetkey ignores that entry: log in again to relearn the site's
hosts.

Parameters:
  --json: Print JSON instead of a table. [default: False]
  --show-links: With --json, also print the link of a login shown in a web
browser. [default: False]
```
<!-- end: valetkey status --help -->

<!-- begin: valetkey watch --help -->
```text
Usage: valetkey watch [OPTIONS]

Print one JSON line for every change to the sessions, login windows and bridges.

The first line is a snapshot of what is open, as status --json shows it, with
"event" set to "snapshot" and an "at" time. After that each line has the keys
event, site and at, where event is session_started, session_ended, login_opened
or login_closed. A session_started line also says whether the session has the
microphone ("microphone": true or false). For a bridge the key is bridge instead
of site, and event is bridge_connected or bridge_disconnected. Bars and
indicators can read the lines as they come. The command runs until it is
interrupted or the daemon stops; it exits 1 when no daemon is running, and does
not start one. With --wait it never exits for that: it waits for a daemon,
prints {"event":"daemon_stopped"} when the daemon ends, and when another one
runs it prints the snapshot again. It looks for a daemon every few seconds at
most, and never starts one.

Parameters:
  --wait: Wait for a daemon instead of failing, and for the next one when it
stops. [default: False]
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
Usage: valetkey mcp [OPTIONS]

Serve the browser tools to an MCP client over standard input and output.

Point an MCP client at this command. It starts valetkeyd if that is not running
yet.

With --site, the server acts only on the sites named, and the daemon refuses
every other site for it: browser_sites lists only those, every tool that names a
site refuses the rest with an error naming the allowed ones, and browser_login
cannot make a site or account outside the list. A bare site covers all its
accounts, including ones added later; site:account covers that one. The list is
fixed for as long as the server runs. Without --site it acts on every site.

Parameters:
  --site STR..., --empty-site: Act only on this site, or site:account for one
account. Repeat for more.
```
<!-- end: valetkey mcp --help -->
