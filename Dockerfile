FROM alpine:3.21.2

LABEL org.opencontainers.image.authors="ProjectDiscovery"
LABEL org.opencontainers.image.description="A fast and configurable TLS grabber focused on TLS based data collection and analysis."
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.title="tlsx"
LABEL org.opencontainers.image.url="https://github.com/projectdiscovery/tlsx"

RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/tlsx /usr/local/bin/

ENTRYPOINT ["tlsx"]
