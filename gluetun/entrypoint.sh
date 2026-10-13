#!/bin/sh
# Generates a fresh CyberGhost WireGuard configuration, then starts gluetun.
# CyberGhost drops a key that no tunnel has used within about 5 minutes, so
# nothing is kept from one start to the next. If cyberghost-wg fails, the
# container exits and its restart policy tries again.
set -e

# First start: register a device on the account, with the credentials from
# CG_USERNAME_FILE / CG_PASSWORD_FILE (or CG_USERNAME / CG_PASSWORD). The state
# is kept in $CG_WG_STATE, which belongs on a volume.
[ -f "$CG_WG_STATE" ] || cyberghost-wg login --name "${CG_DEVICE_NAME:-gluetun}"

# cyberghost-wg reads CG_COUNTRY and CG_TYPE itself; the other settings become
# options when they are set.
cyberghost-wg conf -o /gluetun/wireguard/wg0.conf \
  ${CG_CITY:+--city "$CG_CITY"} \
  ${CG_SERVICE:+--service "$CG_SERVICE"} \
  ${CG_INSTANCE:+--instance "$CG_INSTANCE"}

exec /gluetun-entrypoint "$@"
