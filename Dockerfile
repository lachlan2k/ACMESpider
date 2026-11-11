# Builder
FROM golang:1.26 AS builder

WORKDIR /app

COPY go.sum go.mod .
RUN go mod download -x
COPY . .
# Optional: lego DNS provider (e.g. ionos) to build a single-provider binary.
ARG DNS_PROVIDER
RUN set -e; TAGS=; \
    if [ -n "$DNS_PROVIDER" ]; then \
      go run ./internal/cmd/gendns "$DNS_PROVIDER"; \
      TAGS=single_dns_provider; \
    fi; \
    go build -tags "$TAGS" -o acmespider cmd/main.go

# Runtime
FROM redhat/ubi9-minimal AS runtime
ARG DNS_PROVIDER

WORKDIR /app
COPY --from=builder /app/acmespider .

ENV ACMESPIDER_PORT=443
ENV ACMESPIDER_STORAGE_PATH=/data
ENV ACMESPIDER_DNS_PROVIDER=$DNS_PROVIDER

ENTRYPOINT [ "/app/acmespider", "serve" ]