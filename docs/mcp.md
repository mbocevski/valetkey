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
  the last login learned.
- `browser_login` opens a login window on your screen and returns at once.
- `browser_open` starts the signed-in browser for a site, or joins the running one. It says when
  the saved login has expired.
- `browser_snapshot` reads the page as a text tree, with a reference such as `e3` for each element
  to click or fill.
- `browser_click` clicks an element by reference, or by visible text and role. It looks the
  element up again at click time, and checks an `expect` of `text_appears`, `text_gone` or
  `url_changes`. Only a click with an `expect` is ever repeated.
- `browser_type` replaces the contents of a field, and presses Enter when `submit` is true.
- `browser_navigate` goes to a URL on an allowed host.
- `browser_downloads` lists the files the browser has saved. Clicks and navigation also list new
  files.
- `browser_screenshot` returns an image of the page.
- `browser_allow` asks you to let the site reach one more host.
- `browser_close` ends the site's browser. The login stays saved.

There is no script evaluation, no launch option, no upload, no cookie access and no way to delete
a site. Text from a page is labelled as untrusted data.

## Downloads

Files a site downloads are saved in its downloads folder, `$XDG_STATE_HOME/valetkey/downloads/SITE`.
A new file never replaces an older one of the same name; it gets a number, as in `report (2).pdf`.
valetkey reads the first bytes of a file to report its type and never opens or runs it.

## Asking for a host

When a page needs a host the site does not allow, the browser tools list it as refused. The agent
may call `browser_allow` with one exact host name and a reason. Only a host that was refused, or
that was left out at login, can be asked about. Nothing is allowed unless you say yes.

There are two ways to answer. A client that can show a question to you puts it there. Otherwise
set `approve_command` in `$XDG_CONFIG_HOME/valetkey/config.json` to a program and its arguments:

```json
{"approve_command": ["/home/me/bin/ask-valetkey"]}
```

The daemon runs it with one line of JSON on standard input:
`{"site": ..., "host": ..., "seen_during_login": ..., "reason": ...}`. Exit status 0 means yes.
Any other status means no. A command that runs longer than 60 seconds counts as unanswered. What it
prints is never shown to the agent. The reason is the agent's claim, so show it as one.

With neither, nobody can be asked, and the agent tells you to run `valetkey allow SITE HOST`.

## What `browser_allow` returns

- `allowed`: you said yes. The next navigation to the host will load.
- `denied`: you said no. The agent must not ask again for that host.
- `expired`: nobody answered, or the question was dismissed. The agent may ask again.
- `could_not_ask`: nobody could be asked from here. The agent tells you the exact
  `valetkey allow` command to run.
- `not_eligible`: the host cannot be asked about, either because it was not refused for this site
  or because its name is allowed but it resolves to a private address. The message says which.

## Private networks

A host that resolves to a private address is refused even when its name is allowed. This is true of
an intranet site. `browser_allow` cannot change it. The agent tells you to run
`valetkey allow SITE --private-network RANGE` with the narrowest range that holds the address, such
as `10.20.0.7/32` or a `/24`. [Security](security.md) explains the rule.

## Expired logins

After a session opens, valetkey compares the page it landed on with the login it saved. A start
page that sent the browser to a page where a form was filled in during the login, or to a page
with a password field, means the login expired. `browser_open` then says so, and the agent calls
`browser_login` again without asking first.
