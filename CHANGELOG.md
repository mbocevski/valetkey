# Changelog

Changes that affect users of valetkey. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- The `valetkey` command, which prints its version and help.
- The `valetkey sites` command, which lists your sites, with `--json` for scripts.
- The `valetkey allow` and `valetkey deny` commands, which add or remove a host a site may reach.
- The `valetkey forget` command, which deletes a site's policy, login and downloads after asking.
- The `valetkey install-units` command, which writes the systemd user units for the daemon.
- The `valetkey doctor` command, which checks that bubblewrap, Chromium and agent-browser are ready.
