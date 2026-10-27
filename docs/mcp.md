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

- `browser_sites` lists the sites you have set up, their state, the first hosts each may reach, and
  what the last login learned. With `site` it lists that one site's complete lists: hosts it may
  reach, hosts the login left out, and hosts denied.
- `browser_login` opens a login window on your screen and returns at once. It closes the site's
  running browser first. Pass `account` to add another account to a site (see
  [accounts](#accounts)). With no screen it uses a connected bridge if `remote_logins.waypipe` is
  on, so the window opens on your laptop.
  Otherwise, with `remote_logins.novnc` on, the window is shown in a web browser. The link goes to
  you, never to the agent: your client shows it, or you run `valetkey status` (see
  [remote logins](remote.md)).
- `browser_open` starts the signed-in browser for a site, or joins the running one. It says when
  the saved login has expired.
- `browser_snapshot` reads the page as a text tree with its text and a reference such as `e3`
  for each element to act on. A long page is cut, and `interactive` lists only those elements.
  `images` adds the biggest pictures and videos.
- `browser_click` clicks an element by reference, or by visible text and role. It looks the
  element up again at click time, and checks an `expect` of `text_appears`, `text_gone` or
  `url_changes`. Only a click with an `expect` is ever repeated, and only when the first attempt
  changed nothing.
- `browser_type` replaces the contents of a field, and presses Enter when `submit` is true.
- `browser_navigate` goes to an HTTP or HTTPS address on an allowed host.
- `browser_save` saves a picture, a video or a linked file into the downloads folder (see
  [Downloads](#downloads)).
- `browser_downloads` lists the files the browser has saved. Clicks and navigation also list new
  files.
- `browser_screenshot` returns an image of the page.
- `browser_allow` asks you to let the site reach more hosts.
- `browser_deny` asks you to stop the site reaching hosts it reaches now (see
  [denying a host](#denying-a-host)).
- `browser_close` ends the site's browser. The login stays saved.

There is no script evaluation, no launch option, no upload, no cookie access and no way to delete
a site. Text from a page is labelled as untrusted data.

## What a result starts with

Every result starts with the site's name and the page's address. The address line shows only the
scheme and host, which valetkey reads the way the browser does. The path and query, which the page
chose, come below it, fenced and labelled as untrusted, cut to 200 characters, with the full length
when they were cut. Percent-encoded text is shown as it is, never decoded. When a page loaded,
`browser_open` and `browser_navigate` then give only its title, labelled as the title, with a line
that says to call `browser_snapshot` to read the page. When none loaded (an expired login, a
refused start page, or an address that only started a download), the title, `URL: (none)` and an
empty list of refused hosts are left out. A snapshot leaves out unnamed layout nodes and text that
repeats its parent's name, and nests one space per level; every reference and all other text
stay. One of more than 40,000 characters is cut at the end of a line, with a note of how much was
left out.

When a page could not load because its host is refused, the first line says so and names the host
and the site, as in `The page did not load: example.org is not allowed for sitex.` The refused
hosts and the advice follow. `browser_open` says the same when the host of the site's own start
page is refused, and adds that no session is running.

## Idle sessions

A session that nothing uses for 15 minutes is closed, the same way `browser_close` does it. The
login, the profile and the downloads stay, so `browser_open` starts it again, logged in, in a few
seconds. These count as use: any tool call that names the site, a call that is still running, a
question waiting for you, and a download that is still being written.

The next call on that site, other than `browser_open`, returns an ordinary result, not an error:
`The sitex session was closed after 15 minutes without use. Call browser_open to start it again.`
The agent should open the site and go on.

Set the time with `session_idle_minutes` in `$XDG_CONFIG_HOME/valetkey/config.json`, from 1 to
1440. Any other value stops the daemon at start-up with a message that names the file. There is no
way to turn the limit off. `valetkey status` shows how long each session has been idle and when it
will close. `valetkey watch` reports the close as `session_ended` with `"reason": "idle"`.

## What a click or typing step returns

Once the agent has read a page with `browser_snapshot`, the result of `browser_click` and
`browser_type` ends by saying what the step changed on it, so the agent need not read the page
again. It says that the page did not change, or gives the lines that were taken out and put in,
fenced as untrusted page data. That can be a menu that opened or an error that appeared. When the
changed lines come to more than 4,000 characters, it says the page changed a lot. A step that took
the browser to another page returns that page's title and says to call `browser_snapshot`. A
reference that appears in the changed lines can be clicked at once. With no snapshot to compare
to, or after another client has taken one, the result says only that the page changed, or nothing.

## Hints for the client

Each tool carries the standard MCP hints, so a client can decide what to ask you about.
`browser_sites`, `browser_downloads`, `browser_snapshot` and `browser_screenshot` only read; the
first two touch nothing but valetkey's own state. `browser_click` and `browser_type` are marked
destructive, because a click or Enter can submit, send or delete. `browser_open`,
`browser_navigate`, `browser_allow`, `browser_deny` and `browser_close` are idempotent.
`browser_save` writes a file, so it is not read-only; it never overwrites one, so it is not
destructive. Every tool that touches a page is marked open world. They are hints, not promises.

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
When two downloads under one name run at the same time, such as two hidden frames from one page,
the browser keeps only one of the files. The result then says that downloads started and one
file was saved, lists the names and addresses, and notes that some share a name.

`browser_save` takes a reference from the latest snapshot, which saves a link's target or a media
element's source, or an address. The picture addresses are listed by `browser_snapshot` with
`images` set. The result gives the name, size and type, never the file to the model.
valetkey opens the address in a tab of its own that is closed afterwards, with the site's login
and through its proxy, and takes the body from the browser's record of the exchange. So the
site's own security policy for scripts cannot block it, only hosts the site allows work, and a
refused host is reported as it is for navigation. The file is named after the address, with the
extension its type calls for, and goes into the folder under the same rules and limits as any
download, up to 100 MiB. An address that is `data:` or `blob:` is the file itself, held in the
page, so `browser_save` says so and does not try it. The agent has no other way to get a file off
the page.

## Asking for a host

When a page needs a host the site does not allow, the browser tools list it as refused. The agent
may call `browser_allow` with up to ten exact host names and a reason. Only a host that was
refused, or that is in the site's excluded or denied list (left out at login, or denied by you),
can be asked about. Nothing is allowed unless you say yes.

There are two ways to answer. A client that can show a question to you is asked first, and puts it
there: one question that lists the hosts, each with a box you can tick or clear. A host you clear
counts as a no. How the client asks depends on the MCP protocol version it speaks. valetkey handles
both the older request in the middle of a call and the newer result that asks for input.

Otherwise set `approve_command` in `$XDG_CONFIG_HOME/valetkey/config.json` to a program and its
arguments:

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

With neither, a desktop notification asks, on a desktop whose notification daemon offers buttons
and with `notify-send` installed. It names the site and host, quotes the agent's reason, and has
Allow and Deny buttons. Closing it, or not answering for 60 seconds, counts as unanswered, never as
a no. Switch it off with `{"notifications": false}` in the same file.

If nothing can ask, the agent tells you to run `valetkey allow SITE HOST`.

## What `browser_allow` returns

Each host gets a result of its own, one line per host when there are several.

- `allowed`: you said yes, or the host was already allowed. The next navigation to it will load.
- `denied`: you said no. The agent must not ask again for that host, and the daemon refuses to
  ask again while it runs.
- `expired`: nobody answered, the question was dismissed, or the approval command took longer than
  60 seconds. The agent may ask again.
- `could_not_ask`: nobody could be asked from here, because no approval command is set or the one
  that is set could not run. The agent tells you the exact `valetkey allow` command to run.
- `not_eligible`: the host cannot be asked about, either because it was not refused for this site
  or because its name is allowed but it resolves to a private address. The message says which.

## Denying a host

The agent may call `browser_deny` with up to ten exact host names and a reason, to take hosts away
from a site. Only a host the site may reach now, or one the login left out, can be asked about.
Denying `cdn.example.com` leaves `example.com` allowed if it was: the exact host and its subdomains
are blocked, and the broader entry stays.

You are asked the way `browser_allow` asks: a form in the client with a box for each host, then
your `approve_command`, then a notification, and else the agent hands you
`valetkey deny SITE HOST`. The question says the site will no longer reach the hosts, and that this
lasts through later logins. The approval command gets `"action": "deny"` in its request, and yes
denies. The notification has Deny and Keep buttons.

Hosts you confirm move to the site's denied list and stop loading, in a running session too. The
results are `denied`, `declined` (you said no: the agent must not ask again), `expired`,
`could_not_ask` and `not_eligible`. Only you can allow a denied host again, with `valetkey allow`.

## A client that cannot show questions

MCP lets a client show you a question or a link; the feature is called elicitation. Some clients
do not declare it, and valetkey checks what the client declared instead of assuming.

- To ask for a host, the daemon runs your `approve_command` if you set one, or else shows a
  notification with Allow and Deny. If it can do neither, `browser_allow` returns `could_not_ask` with the exact `valetkey allow SITE HOST` command
  (SITE names the account, such as `sitex:work`), and the agent tells you to run it. Nothing is
  allowed until you do, or the command says yes.
- For a login in a web browser, the client cannot show you the link, and the link never goes to
  the agent. The result of `browser_login` tells the agent to ask you to run `valetkey status` on
  that machine, which prints the link and the `ssh -L` line. See [remote logins](remote.md).
- A login on your own screen or laptop needs neither.

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

A site that shows its front page logged out, without a redirect, is caught another way. When you
log in, valetkey records the names of the sign-in cookies the site set, never their values. When
the site is opened, before the browser starts, it reads the profile again. If none of those
cookies is left, the login has expired and no browser is started. It says nothing when it is
unsure: when one is still there, or the profile cannot be read.

A login usually comes while the site's browser is still running. `browser_login` closes that
browser first, as `browser_close` does, and says so in its result, but only when a window can
open. With no screen, no connected bridge and no browser view, it fails with `no_display` and
leaves the browser running. A login window that is already open for the site is an error.
