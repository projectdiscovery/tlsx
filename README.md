# tlsx

A fast and configurable TLS grabber focused on TLS based data collection.

## Installation

Installing tlsx is very easy, just run the below command.

```console
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
```

## Configuration

### Minimum and Maximum TLS Versions

Minimum and maximum TLS versions can be specified using `-min-version` and `-max-version` flags. The acceptable values for TLS version is specified below.

- ssl30
- tls10
- tls11
- tls12

## Acknowledgements

This program uses the [zcrypto](https://github.com/zmap/zcrypto) library from the zmap team.