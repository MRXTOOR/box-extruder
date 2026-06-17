FROM alpine:3.19

RUN apk add --no-cache bash curl jq ca-certificates

COPY dast-scan.sh /usr/local/bin/dast-scan.sh
RUN chmod +x /usr/local/bin/dast-scan.sh

WORKDIR /work
ENTRYPOINT ["/usr/local/bin/dast-scan.sh"]
