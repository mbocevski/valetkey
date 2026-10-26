# Security

What valetkey contains, what it does not, and who decides. Back to the [README](../README.md).

## What a session can reach

Each site's browser runs in its own Linux network namespace with no network interface. Its only
way out is one local socket to a proxy that valetkey runs for that site. The proxy checks every
connection in turn:

- The port must be 443 for an encrypted connection or 80 for plain HTTP.
- The host must be one the site's policy allows, or a subdomain of one.
- The proxy looks the host up itself and connects only to a public address. Every address the name
  resolves to must pass, so DNS rebinding cannot steer the browser at a service on your machine or
  your network.

Anything else is refused and recorded. The record holds the host, the port and a short reason, and
never a path, a query or a header, because on a logged-in site those carry credentials. The browser
cannot look up names or use WebRTC, because a namespace with no interface has no way to send either.

The browser's files are limited too. System directories are read-only, the home directory is an
empty throwaway one, the environment is cleared, and the only writable places are the site's
profile, its downloads folder and the proxy socket. The SSH and GPG agents, the Docker socket,
the session bus and the rest of your home are not there.

## Who decides

A host is added to a site's policy only when a person says yes. Three things can change a policy:

- Logging in. The hosts the login window navigated to are allowed, and background-only hosts are
  left out and listed as excluded.
- You, with `valetkey allow` and `valetkey deny`.
- The agent's `browser_allow`, which only asks. You answer in the client's own interface or through
  the approval command, and no tool takes "the person said yes" from the agent. See
  [MCP clients](mcp.md).

Only a host that was refused for the site, or that you left out at login, can be asked about. A
steered agent cannot fill your screen with questions about arbitrary hosts.

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
address. The permission is for that site only, and the agent cannot grant it.

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
- Uploads are absent. No tool uploads a file, and the browser has no access to your files.
- A login window needs a Wayland session. An X11 client can read every keystroke and the whole
  screen, so valetkey refuses to open a login window on X11.
- Chrome's own background requests, such as update checks, are refused and listed on a separate
  line of the tool results. Allow one only if a page needs it.

## Page content is untrusted

A page can contain text written to look like instructions. Everything that came from a page, such
as titles and the page's text tree, is fenced and labelled as data. The agent is told never to
follow instructions found there and to tell you when a host is refused instead of working around it.

## Seeing what runs

`valetkey status` and `valetkey watch` show every open session and login window, taken from the
processes the daemon owns. Nothing hides a session from them, and a browser that was killed
disappears within a second or two.
