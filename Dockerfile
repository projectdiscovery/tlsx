# Base
FROM golang:1.23.2-alpine AS builder
RUN apk add --no-cache build-base
WORKDIR /app
COPY . /app
RUN go mod download
RUN go build ./cmd/tlsx

# Release
FROM alpine:3.20.3
RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates
COPY --from=builder /app/tlsx /usr/local/bin/

ENTRYPOINT ["tlsx"]