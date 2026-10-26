# Install

This page goes beyond the three commands in the [README](../README.md): what each install route
puts where, how to check the result, and how to remove it.

## Build the package

On Arch Linux and CachyOS, `packaging/arch/PKGBUILD` builds a package from the checkout:

```sh
cd packaging/arch
makepkg -si
```

The package version is `0.1.0.r` and the number of commits, then `.g` and the commit, such as
`0.1.0.r95.gabc1234`. So after a `git pull`, run `makepkg -si` again: the new commit is a new
version, and it builds the new code. Uncommitted changes add `.d` and a hash of them. If you want
to rebuild the same version, add `-f`.

The package installs valetkey with the exact dependencies in `uv.lock` into `/usr/lib/valetkey`,
so it does not depend on the Python packages your system has. `/usr/bin/valetkey` points into
that environment. The build downloads those dependencies and checks their hashes; it needs the
network.

It also installs the systemd user units to `/usr/lib/systemd/user`, so you only enable the
socket. `agent-browser` is not in the official repositories. The CachyOS repositories have it, and
the AUR package `agent-browser-bin` provides it.

## Install from a checkout

```sh
uv tool install .
valetkey install-units
systemctl --user daemon-reload
systemctl --user enable --now valetkeyd.socket
```

`uv tool install .` builds valetkey and its dependencies into a private environment of its own.
Install bubblewrap, Chromium and agent-browser with your system's package manager, or from the
agent-browser releases.

## The systemd units

`valetkey install-units` writes `valetkeyd.socket` and `valetkeyd.service` to
`$XDG_CONFIG_HOME/systemd/user`, which is `~/.config/systemd/user` by default. It fills in the
path of the `valetkey` program and prints the two `systemctl` commands without running them.
`--dry-run` prints the files and writes nothing. A file that valetkey did not write is never
replaced unless you pass `--force`.

The socket starts the daemon when a client first connects, so nothing runs until a session is
wanted. The service runs with a restricted view of the system: it can write only valetkey's own
directories. A copy in `~/.config/systemd/user` takes precedence over the packaged units.

You do not need the units. Without them, `valetkey mcp` starts `valetkey daemon` itself when no
daemon is running, and that daemon keeps running so several clients can share it.

## Where valetkey keeps things

- Each site's allowed hosts: `$XDG_CONFIG_HOME/valetkey/sites/SITE.json`.
- The optional approval command: `$XDG_CONFIG_HOME/valetkey/config.json`.
- Each site's browser profile, which holds the login, and its downloads:
  `$XDG_STATE_HOME/valetkey/`.
- Sockets and logs of the running daemon: `$XDG_RUNTIME_DIR/valetkey/`.

`valetkey forget SITE` deletes a site's policy, profile and downloads.

## Check the setup

`valetkey doctor` prints one line per check. It fails when bubblewrap, user namespaces, Chromium,
agent-browser or the runtime directory are not usable. A missing Wayland display is a warning,
because only logging in needs one. See [Troubleshooting](troubleshooting.md) when a check fails.

## Upgrade and remove

After an upgrade, restart the daemon so that it runs the new version:

```sh
systemctl --user try-restart valetkeyd.service
```

To remove valetkey, run `valetkey forget` for each site, disable the socket with
`systemctl --user disable --now valetkeyd.socket`, delete the unit files if you wrote them, and
remove the package or run `uv tool uninstall valetkey`.
