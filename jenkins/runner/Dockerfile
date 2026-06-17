FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends bash curl jq ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY dast-scan.sh /usr/local/bin/dast-scan.sh
RUN chmod +x /usr/local/bin/dast-scan.sh

WORKDIR /work
ENTRYPOINT ["/usr/local/bin/dast-scan.sh"]
