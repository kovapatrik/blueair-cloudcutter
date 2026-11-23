# syntax=docker/dockerfile:1
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    BLUEAIR_CLOUDCUTTER_DOCKER=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates openssl \
      mosquitto mosquitto-clients bluez libnss-mdns \
      hostapd dnsmasq iproute2 iw rfkill iptables libpcap0.8 procps \
 && rm -rf /var/lib/apt/lists/*

# mDNS (.local) names are resolved through the host's Avahi socket, not the
# container's unicast DNS. The wrapper mounts /run/avahi-daemon when present.
RUN printf 'hosts: files mdns4_minimal [NOTFOUND=return] dns\n' > /etc/nsswitch.conf

# The lockfile is the reproducibility contract: a floating dependency version
# is exactly the class of breakage this image exists to prevent.
COPY --from=ghcr.io/astral-sh/uv:0.8.22 /uv /uvx /bin/

WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --locked --no-dev --extra aws --extra capture

ENV PATH="/app/.venv/bin:$PATH"

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD []
