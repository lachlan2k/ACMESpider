# Runtime image for end-to-end tests. The binary is cross-compiled on the host (see run.sh) so the build
# doesn't have to re-download the whole module graph. curl is for the DNS-01 shim in dns-exec.sh.
FROM alpine:3
RUN apk add --no-cache curl ca-certificates && mkdir -p /data
# certmagic (ACMESpider's own TLS certificate) verifies pebble's HTTPS endpoint with the system roots
COPY pebble.minica.pem /usr/local/share/ca-certificates/pebble-minica.crt
RUN update-ca-certificates
COPY acmespider /app/acmespider
COPY dns-exec.sh /app/dns-exec.sh
ENV ACMESPIDER_STORAGE_PATH=/data
ENTRYPOINT ["/app/acmespider", "serve"]
