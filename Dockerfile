# This Dockerfile is for building the API server

# Builder
FROM golang:1.21 AS builder

WORKDIR /app

RUN go build cmd/main.go -o acmespider

# Runtime
FROM redhat/ubi9-micro AS runtime

WORKDIR /app
COPY --from=builder /app/acmespider .

ENV ACMESPIDER_PORT=443

ENTRYPOINT [ "/app/acmespider", "serve" ]