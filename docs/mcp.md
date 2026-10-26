# MCP clients

How to connect an MCP client, what the agent can do, and how it asks for more. Back to the
[README](../README.md).

## Connect a client

Add `valetkey mcp` to the client as a stdio server. In clients that read a JSON config:

```json
{"mcpServers": {"valetkey": {"command": "valetkey", "args": ["mcp"]}}}
```

Clients with a command line can add it the same way, with `valetkey mcp` as the command. With
the systemd socket enabled, the daemon starts on the first connection. Without it, `valetkey mcp`
starts `valetkey daemon` itself, and that daemon keeps running so several clients can share it.

## The tools

Start with `browser_sites`. The others act on one site by its name.

- `browser_sites` lists the sites you have set up, their state, the hosts each may reach, and what
  the last login learned. That names the other sites the login allowed, and the hosts it only passed
  through and did not allow.
- `browser_login` opens a login window on your screen and returns at once. Pass `account` to add
  another account to a site (see [accounts](#accounts)). With no screen it
  uses a connected bridge if `remote_logins.waypipe` is on, so the window opens on your laptop.
  Otherwise, with `remote_logins.novnc` on, the window is shown in a web browser. The link goes to
  you, never to the agent: your client shows it, or you run `valetkey status` (see
  [remote logins](remote.md)).
- `browser_open` starts the signed-in browser for a site, or joins the running one. It says when
  the saved login has expired.
- `browser_snapshot` reads the page as a text tree, with a reference such as `e3` for each element
  to click or fill.
- `browser_click` clicks an element by reference, or by visible text and role. It looks the
  element up again at click time, and checks an `expect` of `text_appears`, `text_gone` or
  `url_changes`. Only a click with an `expect` is ever repeated, and only when the first attempt
  changed nothing.
- `browser_type` replaces the contents of a field, and presses Enter when `submit` is true.
- `browser_navigate` goes to an HTTP or HTTPS address on an allowed host.
- `browser_downloads` lists the files the browser has saved. Clicks and navigation also list new
  files.
- `browser_screenshot` returns an image of the page.
- `browser_allow` asks you to let the site reach one more host.
- `browser_close` ends the site's browser. The login stays saved.

There is no script evaluation, no launch option, no upload, no cookie access and no way to delete
a site. Text from a page is labelled as untrusted data.

Every result starts with the site's name and the page's address. The address line shows only the
scheme and host, which valetkey reads the way the browser does. The path and query, which the page
chose, come below it, fenced and labelled as untrusted, cut to 200 characters, with the full length
when they were cut. Percent-encoded text is shown as it is, never decoded.

## Hints for the client

Each tool carries the standard MCP hints, so a client can decide what to ask you about.
`browser_sites`, `browser_downloads`, `browser_snapshot` and `browser_screenshot` only read; the
first two touch nothing but valetkey's own state. `browser_click` and `browser_type` are marked
destructive, because a click or Enter can submit, send or delete. `browser_open`,
`browser_navigate`, `browser_allow` and `browser_close` are idempotent. Every tool that touches a
page is marked open world. They are hints, not promises.

## Accounts

A site can have several accounts, each its own login named like `sitex:work`. While a site has one
account the agent can use its bare name. Once it has several, a bare name is refused with the
names to choose from, because acting as the wrong account is worse than one refused call. The
account that existed first is `sitex:main`. Every answer starts with the account that acted.

The agent adds an account with `browser_login` and its `account` argument, for example
`site_or_url` `sitex` with `account` `work`. The new account starts at the same page, with its own
list of hosts. You can start it with the hosts of another account using
`valetkey add sitex:work START --copy-hosts-from sitex`. Only you can do that.

## Downloads

Files a site downloads are saved in its downloads folder, `$XDG_STATE_HOME/valetkey/downloads/SITE`.
A new file never replaces an older one of the same name; it gets a number, as in `report (2).pdf`.
valetkey reads the first bytes of a file to report its type and never opens or runs it.

## Asking for a host

When a page needs a host the site does not allow, the browser tools list it as refused. The agent
may call `browser_allow` with one exact host name and a reason. Only a host that was refused, or
that is in the site's excluded list (left out at login, or denied), can be asked about. Nothing is
allowed unless you say yes.

There are two ways to answer. A client that can show a question to you is asked first, and puts it
there. Otherwise set `approve_command` in `$XDG_CONFIG_HOME/valetkey/config.json` to a program and
its arguments. The file may hold no other key:

```json
{"approve_command": ["/home/me/bin/ask-valetkey"]}
```

The daemon runs it with one line of JSON on standard input:
`{"site": ..., "host": ..., "seen_during_login": ..., "reason": ...}`. Exit status 0 means yes.
Any other status means no. A command that runs longer than 60 seconds counts as unanswered. What it
prints is never shown to the agent. The reason is the agent's claim, so show it as one. The command
runs without a shell and gets a small environment: `PATH`, `HOME`, `XDG_RUNTIME_DIR`, `LANG`, and the
display and session bus variables (`WAYLAND_DISPLAY`, `DISPLAY`, `DBUS_SESSION_BUS_ADDRESS`), which
it can use to show you a question.

With neither, nobody can be asked, and the agent tells you to run `valetkey allow SITE HOST`.

## What `browser_allow` returns

- `allowed`: you said yes, or the host was already allowed. The next navigation to it will load.
- `denied`: you said no. The agent must not ask again for that host, and the daemon refuses to
  ask again while it runs.
- `expired`: nobody answered, the question was dismissed, or the approval command took longer than
  60 seconds. The agent may ask again.
- `could_not_ask`: nobody could be asked from here, because no approval command is set or the one
  that is set could not run. The agent tells you the exact `valetkey allow` command to run.
- `not_eligible`: the host cannot be asked about, either because it was not refused for this site
  or because its name is allowed but it resolves to a private address. The message says which.

## Private networks

A host that resolves to a private address is refused even when its name is allowed. This is true of
an intranet site. `browser_allow` cannot change it. The agent tells you to run
`valetkey allow SITE --private-network RANGE` with the narrowest range that holds the address, such
as `10.20.0.7/32` or a `/24`. [Security](security.md) explains the rule.

`browser_login` follows the same rule. When the site's start host resolves to a private address it
may not reach, the call fails and tells the agent to ask you. For a site that does not exist yet,
the command is `valetkey add SITE START --private-network RANGE`. A login that was refused hosts for
their private address says so in what it learned, so the agent can pass it on.

## Expired logins

After a session opens, valetkey compares the page it landed on with the login it saved. A start
page that sent the browser to a page you used during the login and left by submitting a form, or
to a page with a password field, means the login expired. A page that sent itself on at once does
not count. `browser_open` then says so, and the agent calls
`browser_login` again without asking first.
