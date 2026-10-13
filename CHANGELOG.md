# Changelog

## Unreleased

- gluetun image, `ghcr.io/bastienpop/gluetun-cyberghost` (amd64, arm64, armv7): gluetun with `cyberghost-wg` inside, which registers the device on the first start and writes a fresh configuration on every start. With a `compose.yaml`, a Podman Quadlet unit and its own README (`gluetun/`).
- Docs: the README points gluetun users to the image.

## 0.1.0 – 2026-10-11

First public version.

- `login`, `countries`, `services`, `servers`, `conf` (with `-i` menus) and `logout`.
- Server types as in CyberGhost's apps: all, torrent, streaming (`--service 'Netflix UK'`), gaming and NoSpy.
- Pure-Python X25519: no dependency outside the standard library.
- `addKey` certificate checked against the CyberGhost root CA and the server's rack.
- `login` registers a new device when the previous one was removed from the account.
- Waits and tries again on HTTP 429 (rate limit) and while the network is down.
- Credentials remembered with `systemd-creds` when it is recent enough (256+, or 250+ as root).
- `--no-dns`, `--json`, `-v`, `logout --local`.
