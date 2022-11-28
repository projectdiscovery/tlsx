FROM golang:1.18.2-alpine3.14 AS build-env
RUN apk add --no-cache build-base
RUN go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest

FROM alpine:3.17.0
RUN apk add --no-cache bind-tools ca-certificates
COPY --from=build-env /go/bin/tlsx /usr/local/bin/tlsx
ENTRYPOINT ["tlsx"]
