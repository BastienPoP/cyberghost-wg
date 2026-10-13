# Changelog

## 0.2.1 – 2026-10-13

- gluetun image: the credentials can also be given as `CG_USERNAME` / `CG_PASSWORD` in `vpn.env` (not advised: `inspect` shows them; the container logs a note). The secrets still come first in the docs, and the entrypoint finds them by itself: `compose.yaml` mounts the `secrets/` folder, which may stay empty, and the units no longer set `CG_*_FILE`. gluetun no longer receives the credentials.
- gluetun image: a note on the throughput and CPU cost of rootless Podman.
- The image is republished as `latest` when a gluetun update is merged.

## 0.2.0 – 2026-10-13

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
