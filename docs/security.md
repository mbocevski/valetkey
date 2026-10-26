# Security

What valetkey contains, what it does not, and who decides. Back to the [README](../README.md).

## What a session can reach

Each site's browser runs in its own Linux network namespace, which has only a loopback interface.
The browser's connections go to a small forwarder on that loopback, and the forwarder hands them to
one local socket: a proxy that valetkey runs for that site. The proxy checks every connection in
turn:

- The port must be 443 for an encrypted connection or 80 for plain HTTP.
- The host must be one the site's policy allows, or a subdomain of one, and must not be in its
  excluded list. An excluded entry wins over an allowed one.
- The proxy looks the host up itself and connects only to a public address. Every address the name
  resolves to must pass, so DNS rebinding cannot steer the browser at a service on your machine or
  your network.

Anything else is refused and recorded. The record holds the host, the port and a short reason, and
never a path, a query or a header, because on a logged-in site those carry credentials. The browser
cannot look up names itself or send WebRTC traffic, because the namespace has no route out. It names
the host to the proxy, which does the lookup.

The browser's files are limited too. System directories are read-only, the home directory is an
empty throwaway one, and the environment is cleared. The only places it can write that last are the
site's profile, its downloads folder, and the directories that hold the proxy's socket and the
browser driver's socket. Its temporary directory, home and runtime directory exist only in memory.
The SSH and GPG agents, the Docker socket, the session bus and the rest of your home are not there.

## Who decides

A host is added to a site's policy only when a person says yes. Three things can change a policy:

- Logging in. The site's own domain is allowed, with its subdomains. Any other host the login
  window navigated to, such as a sign-in provider, is allowed as that exact host. A host the page
  only loaded in the background is left out and listed as excluded.
- You, with `valetkey allow` and `valetkey deny`.
- The agent's `browser_allow`, which only asks. You answer in the client's own interface or through
  the approval command, and no tool takes "the person said yes" from the agent. See
  [MCP clients](mcp.md).

Only a host that was refused for the site, or that is in its excluded list, can be asked about. The
excluded list holds the hosts left out at login and the ones you denied. A steered agent cannot
fill your screen with questions about arbitrary hosts.

## Private networks

A name that resolves to a private address is refused by default, even when the name is allowed.
This stops a page from reaching routers, other machines on your network and services on your own
machine.

Some addresses are refused whatever is listed: loopback, link-local, multicast, unspecified and
reserved addresses, and the cloud metadata services at `169.254.169.254`, `fd00:ec2::254` and
`100.100.100.200`. A page that reached one could read the credentials of the machine it runs on.

Only you can let a site reach a private range, with `valetkey allow SITE --private-network RANGE`.
The range must lie inside `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10` or
`fc00::/7`, and be no wider than a `/8` (a `/48` for IPv6). Use the narrowest range that holds the
address. The permission is for that site only, and the agent cannot grant it. For a site you have
not logged in to yet, run `valetkey add SITE START --private-network RANGE` first; a login keeps
the ranges, and an agent that asks to log in to an unknown private host is told to ask you.

## Trust boundary

valetkey defends against page content steering the browser tools. It does not defend against your
own user account.

The daemon cannot see the MCP client's interface, so for an answer given there it takes the word of
the `valetkey mcp` process that you accepted. That is the same trust the daemon gives every process
of your user: it checks the user ID of whoever connects to its socket, and nothing more. The agent
has no way to reach that operation, because the only tool that uses it does so after the client's
interface returned your answer.

A process of your user can edit the policy files with `valetkey allow` anyway. If the agent has a
shell on your account, it can do that too. Give the agent browser tools without a shell if that
matters to you.

## What containment does not cover

- Pages the browser already cached still render. A host that is no longer allowed does not have to
  be reached for a cached page to appear.
- Whatever an allowed host serves is readable by the agent, and whatever the agent types goes to
  that host. Allow only hosts you would trust with the session.
- Uploads are absent. No tool uploads a file, and the browser can see only its own profile and the
  site's downloads folder, not the rest of your files.
- While a login window is open, it can reach any public host on ports 80 and 443. That is how
  valetkey learns which hosts the site needs. The address checks still apply, so private
  addresses stay refused unless you listed their range for the site.
- A login window needs a Wayland session. An X11 client can read every keystroke and the whole
  screen, so valetkey refuses to open a login window on X11.
- Chrome makes some requests of its own, such as update checks. They are refused and listed on a
  separate line of the tool results. Allow one only if a page needs it.

## The login window

The window you sign in with is an ordinary Chromium on your Wayland desktop, in the same kind of
sandbox as the agent's browsers. valetkey asks your compositor for a restricted socket for each
login and gives the window that one instead of the compositor's own. Through it the window cannot:

- capture the screen or other windows,
- type or click for you with a virtual keyboard or pointer,
- read or change the clipboard behind your back with a clipboard manager,
- list your other windows, lock the session or change your displays.

It still shows pages, takes your typing and does ordinary copy and paste, including from a
password manager. The compositor lists the window as a sandboxed client of `valetkey`, with the
site as its instance name. The socket is removed when the window closes.

Not every compositor can do this. When yours cannot, the login still opens on the compositor's own
socket, the daemon logs a warning, and `valetkey doctor` shows `warn` on the security-context line:
the window is then not restricted.

## The login window on your laptop

Off unless `remote_logins.waypipe` is true and a bridge is connected. The window still runs in
the same sandbox on the server. The daemon does not ask for a restricted socket for it, because
the server has no compositor to ask.

The restriction that applies is the one on your laptop. The bridge's `waypipe client` always runs
with `--secctx`, so your compositor treats everything the server draws as a sandboxed client and
refuses it screen capture, virtual input and clipboard managers. See the
[remote logins page](remote.md).

## The remote login display

Off unless `remote_logins.novnc` is true. The login window then runs on a private headless
display instead of yours, and a web server on `127.0.0.1` shows it. The link carries a random
token and works once: the first page load sets an `HttpOnly`, `SameSite=Strict` cookie that the
WebSocket needs. It takes one viewer at a time, and a new one replaces the old. It drops a viewer
that has been silent for 90 seconds, allows 8 connections, and refuses a foreign `Origin`. It
stops accepting connections after ten minutes, and it is gone when the window closes. Anyone who
opens the link first and can reach the loopback port, through your `ssh -L`, can type into the
login window, so treat it like the password. It is never given to the agent: the client shows it to you, or
`valetkey status` does. The [remote logins page](remote.md) has the details.

## Page content is untrusted

A page can contain text written to look like instructions. Everything that came from a page, such
as titles, the page's text tree and the path and query of its address, is fenced and labelled as
data. The address shows only its host as fact; the rest is cut to 200 characters. The agent is told never to
follow instructions found there and to tell you when a host is refused instead of working around it.
The browser's own error messages and the tails of its logs are fenced and labelled the same way,
because they can repeat what a page chose. The summary of a login holds only valetkey's words and
host names, never text from the login's history.

## Seeing what runs

`valetkey status` and `valetkey watch` show every open session and login window, taken from the
processes the daemon owns. Nothing hides a session from them, and a browser that was killed
disappears within a second or two.
