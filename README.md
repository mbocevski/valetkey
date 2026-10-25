# valetkey

valetkey gives an MCP client a web browser that is logged in to one site and can reach only the
hosts that site needs.

A valet key starts the car but does not open the trunk. valetkey hands out the same kind of key:
a browser session that is signed in to your account on one site, and that cannot send anything
anywhere else.

## Status

Early development. Nothing here is usable yet: the `valetkey` command only prints its version.

## How it will work

- **You log in, once.** valetkey opens an ordinary browser window on your desktop. You sign in,
  with two-factor authentication if the site asks for it, and close the window. The session stays
  in a browser profile that belongs to that site alone.
- **The client works without you.** Later, an MCP client can open the site, read pages, click and
  type, in a headless browser that is already signed in.
- **The kernel enforces the boundary.** Each browser runs in its own Linux network namespace. Its
  only connection to the outside is a proxy that allows the site's hosts and refuses everything
  else, including DNS lookups, WebRTC and connections to services on your machine.
- **Only you can widen it.** When a page needs a host that is not allowed, the client can ask, and
  the answer comes from you.

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
