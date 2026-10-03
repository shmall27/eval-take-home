FROM python:3.12-slim-bookworm

# Ordinary tooling a terminal/cyber agent would expect for recon, HTTP and
# hex-protocol work.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates iproute2 iputils-ping dnsutils netcat-openbsd jq nmap xxd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
