# Builder
FROM golang:1.21 AS builder

WORKDIR /app

COPY go.sum go.mod .
RUN go mod download -x
COPY . .
RUN go build -o acmespider cmd/main.go

# Runtime
FROM redhat/ubi9-micro AS runtime

WORKDIR /app
COPY --from=builder /app/acmespider .

ENV ACMESPIDER_PORT=443
ENV ACMESPIDER_DB_PATH=/data/acmespider.db

ENTRYPOINT [ "/app/acmespider", "serve" ]