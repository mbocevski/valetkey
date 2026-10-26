# valetkey

valetkey gives an MCP client a web browser that is logged in to one site and can reach only the
hosts that site needs.

A valet key starts the car but does not open the trunk. valetkey hands out the same kind of key:
a browser session that is signed in to your account on one site, and that cannot send anything
anywhere else.

## Status

Early development. The browser itself is not usable yet. The `valetkey` command can list sites and
change which hosts each one may reach.

## Usage

<!-- begin: valetkey --help -->
```text
Usage: valetkey COMMAND

A logged-in browser for MCP clients, contained to the sites it may reach.

Commands:
  allow: Allow a host, and its subdomains, for a site.
  daemon: Run the valetkeyd daemon in the foreground.
  deny: Stop allowing a host for a site.
  forget: Delete a site's policy, login profile and downloads.
  sites: List the sites valetkey knows.
  --help, -h: Display this message and exit.
  --version: Display application version.
```
<!-- end: valetkey --help -->

### Managing sites

`valetkey sites` lists each site with its start host, how many hosts it allows and excludes, when
they were last learned and whether a login profile exists. Add `--json` for a script.

`valetkey allow SITE HOST` lets a site reach another host and its subdomains, and removes any
excluded entry that would block it. `valetkey deny SITE HOST` takes a host away. When a wider
allowed entry still covers it, the host is also excluded so it stays blocked.

`valetkey forget SITE` deletes the site's policy, login profile and downloads after asking. It
refuses while the site's browser is open.

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
It also refuses while the site's browser is open: close that session first.

Parameters:
  SITE, --site: The site name, as shown by valetkey sites. [required]
  --yes: Delete without asking. [default: False]
```
<!-- end: valetkey forget --help -->

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
- [agent-browser](https://github.com/vercel-labs/agent-browser) 0.39 or newer
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
