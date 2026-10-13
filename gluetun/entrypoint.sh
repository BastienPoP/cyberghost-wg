#!/bin/sh
# Generates a fresh CyberGhost WireGuard configuration, then starts gluetun.
# CyberGhost drops a key that no tunnel has used within about 5 minutes, so
# nothing is kept from one start to the next. If cyberghost-wg fails, the
# container exits and its restart policy tries again.
set -e

# Credentials: the secrets cg_username and cg_password (recommended), else
# the variables CG_USERNAME and CG_PASSWORD, which win when they are set.
if [ -z "$CG_USERNAME" ] && [ -z "$CG_USERNAME_FILE" ] && [ -f /run/secrets/cg_username ]; then
  export CG_USERNAME_FILE=/run/secrets/cg_username
fi
if [ -z "$CG_PASSWORD" ] && [ -z "$CG_PASSWORD_FILE" ] && [ -f /run/secrets/cg_password ]; then
  export CG_PASSWORD_FILE=/run/secrets/cg_password
fi
if [ -n "$CG_PASSWORD" ]; then
  echo "Note: the CyberGhost password comes from CG_PASSWORD, which 'inspect' shows; a secret is safer." >&2
fi

# First start: register a device on the account. The state is kept in
# $CG_WG_STATE, which belongs on a volume.
[ -f "$CG_WG_STATE" ] || cyberghost-wg login --name "${CG_DEVICE_NAME:-gluetun}"

# cyberghost-wg reads CG_COUNTRY and CG_TYPE itself; the other settings become
# options when they are set.
cyberghost-wg conf -o /gluetun/wireguard/wg0.conf \
  ${CG_CITY:+--city "$CG_CITY"} \
  ${CG_SERVICE:+--service "$CG_SERVICE"} \
  ${CG_INSTANCE:+--instance "$CG_INSTANCE"}

# gluetun does not need the credentials.
unset CG_USERNAME CG_PASSWORD
exec /gluetun-entrypoint "$@"
