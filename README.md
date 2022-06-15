<h1 align="center">
  TLSX
  <br>
</h1>



<p align="center">
<a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-_red.svg"></a>
<a href="https://goreportcard.com/badge/github.com/projectdiscovery/tlsx"><img src="https://goreportcard.com/badge/github.com/projectdiscovery/tlsx"></a>
<a href="https://github.com/projectdiscovery/tlsx/releases"><img src="https://img.shields.io/github/release/projectdiscovery/tlsx"></a>
<a href="https://twitter.com/pdiscoveryio"><img src="https://img.shields.io/twitter/follow/pdiscoveryio.svg?logo=twitter"></a>
<a href="https://discord.gg/projectdiscovery"><img src="https://img.shields.io/discord/695645237418131507.svg?logo=discord"></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#running-tlsx">Running tlsx</a> •
  <a href="#-notes">Notes</a> •
  <a href="https://discord.gg/projectdiscovery">Join Discord</a>
</p>


A fast and configurable TLS grabber focused on TLS based data collection.


# Features

 - Fast And fully configurable tls connection
 - Multiple mode for TLS Connection
 - Auto fallback connection for older TLS version
 - HOST, IP and CIDR range as input support
 - STD IN/OUT and TXT/JSON output support

## Installation

Installing tlsx is very easy, just run the below command.

```console
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
```

## Usage

```sh
tlsx -h
```

This will display help for the tool. Here are all the switches it supports.

```console
Usage:
  ./tlsx [flags]

Flags:
INPUT:
   -u, -host string[]  target host to scan (-u INPUT1,INPUT2)
   -l, -list string    target list to scan (-l INPUT_FILE)
   -p, -port string[]  target port to connect (default 443)

CONFIGURATIONS:
   -config string        path to the tlsx configuration file
   -timeout int          tls connection timeout in seconds (default 5)
   -c, -concurrency int  number of concurrent threads to process (default 300)
   -min-version string   minimum tls version to accept (tls10,tls11,tls12,tls13)
   -max-version string   maximum tls version to accept (tls10,tls11,tls12,tls13)
   -ps, -pre-handshake   enable pre-handshake tls connection (early termination) using ztls
   -ztls                 use zmap/zcrypto instead of crypto/tls for tls connection

OUTPUT:
   -o, -output string  file to write output to
   -j, -json           display json format output
   -v, -verbose        display verbose output
   -version            display project version
```

## Running tlsx

### TLS Probe

This will run the tool against all the dns host and ip in `hosts.txt` and returns host/ip that accepts tls connection on port 443

```
echo 173.0.84.0/24 | ./tlsx 
  

  _____ _    _____  __
 |_   _| |  / __\ \/ /
   | | | |__\__ \>  < 
   |_| |____|___/_/\_\	v0.0.1

		projectdiscovery.io

[WRN] Use with caution. You are responsible for your actions.
[WRN] Developers assume no liability and are not responsible for any misuse or damage.

173.0.84.69:443
173.0.84.67:443
173.0.84.68:443
173.0.84.66:443
173.0.84.76:443
173.0.84.70:443
173.0.84.72:443
```

## Configuration

### Minimum and Maximum TLS Versions

Minimum and maximum TLS versions can be specified using `-min-version` and `-max-version` flags. The acceptable values for TLS version is specified below.

- ssl30
- tls10
- tls11
- tls12

## Acknowledgements

This program optionally uses the [zcrypto](https://github.com/zmap/zcrypto) library from the zmap team.