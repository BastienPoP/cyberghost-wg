# gluetun with cyberghost-wg: every time the container starts, entrypoint.sh
# generates a fresh CyberGhost WireGuard configuration, then starts gluetun with
# its custom provider. Build from the repository root:
#   docker build -f gluetun/Dockerfile -t gluetun-cyberghost .
FROM ghcr.io/qdm12/gluetun:v3.41.3

RUN apk add --no-cache python3 \
 && mkdir -p /gluetun/wireguard /cyberghost-wg
COPY --chmod=755 cyberghost-wg /usr/local/bin/cyberghost-wg
COPY --chmod=755 gluetun/entrypoint.sh /cyberghost-entrypoint.sh

# The labels of the gluetun image would otherwise describe this one.
LABEL org.opencontainers.image.title="gluetun-cyberghost" \
      org.opencontainers.image.description="gluetun with a fresh CyberGhost WireGuard configuration on every start (cyberghost-wg)" \
      org.opencontainers.image.source="https://github.com/BastienPoP/cyberghost-wg" \
      org.opencontainers.image.url="https://github.com/BastienPoP/cyberghost-wg/tree/main/gluetun" \
      org.opencontainers.image.documentation="https://github.com/BastienPoP/cyberghost-wg/blob/main/gluetun/README.md" \
      org.opencontainers.image.licenses="MIT"

ENV VPN_SERVICE_PROVIDER=custom \
    VPN_TYPE=wireguard \
    CG_WG_STATE=/cyberghost-wg/state.json
ENTRYPOINT ["/cyberghost-entrypoint.sh"]
