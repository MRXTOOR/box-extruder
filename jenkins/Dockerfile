# CI runner: curl + jq + dast-scan.sh for Jenkins pipelines and local docker run.
FROM alpine:3.20

RUN apk add --no-cache bash curl jq ca-certificates

COPY scripts/dast-scan.sh /opt/dast/dast-scan.sh
RUN sed -i 's/\r$//' /opt/dast/dast-scan.sh && chmod +x /opt/dast/dast-scan.sh

WORKDIR /work
ENTRYPOINT ["/opt/dast/dast-scan.sh"]
