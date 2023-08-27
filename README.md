<h1 align="center">
<img src="https://user-images.githubusercontent.com/8293321/174841003-01a62bad-2ecf-4874-89c4-efa53dd56884.png" width="200px">
<br>
</h1>


<p align="center">
<a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-_red.svg"></a>
<a href="https://goreportcard.com/badge/github.com/projectdiscovery/tlsx"><img src="https://goreportcard.com/badge/github.com/projectdiscovery/tlsx"></a>
<a href="https://pkg.go.dev/github.com/projectdiscovery/tlsx/pkg/tlsx"><img src="https://img.shields.io/badge/go-reference-blue"></a>
<a href="https://github.com/projectdiscovery/tlsx/releases"><img src="https://img.shields.io/github/release/projectdiscovery/tlsx"></a>
<a href="https://twitter.com/pdiscoveryio"><img src="https://img.shields.io/twitter/follow/pdiscoveryio.svg?logo=twitter"></a>
<a href="https://discord.gg/projectdiscovery"><img src="https://img.shields.io/discord/695645237418131507.svg?logo=discord"></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#running-tlsx">Running tlsx</a> •
  <a href="https://discord.gg/projectdiscovery">Join Discord</a>
</p>


A fast and configurable TLS grabber focused on TLS based **data collection and analysis**.


# Features

![image](https://user-images.githubusercontent.com/8293321/174847743-0e229545-2431-4b4c-9029-878f218ad0bc.png)

 - Fast And fully configurable TLS Connection
 - Multiple **Modes for TLS Connection**
 - Multiple **TLS probes**
 - **Auto TLS Fallback** for older TLS version
 - **Pre Handshake** TLS connection (early termination)
 - Customizable **Cipher / SNI / TLS** selection
 - **JARM/JA3** TLS Fingerprint
 - **TLS Misconfigurations**
 - **ASN,CIDR,IP,HOST,** and **URL** input
 - STD **IN/OUT** and **TXT/JSON** output


## Installation

tlsx requires **Go 1.20** to install successfully. To install, just run the below command or download pre-compiled binary from [release page](https://github.com/projectdiscovery/tlsx/releases).

```console
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
```

## Usage

```console
tlsx -h
```

This will display help for the tool. Here are all the switches it supports.

```console
TLSX is a tls data gathering and analysis toolkit.

Usage:
  tlsx [flags]

Flags:
INPUT:
   -u, -host string[]  target host to scan (-u INPUT1,INPUT2)
   -l, -list string    target list to scan (-l INPUT_FILE)
   -p, -port string[]  target port to connect (default 443)

SCAN-MODE:
   -sm, -scan-mode string     tls connection mode to use (ctls, ztls, openssl, auto) (default "auto")
   -ps, -pre-handshake        enable pre-handshake tls connection (early termination) using ztls
   -sa, -scan-all-ips         scan all ips for a host (default false)
   -iv, -ip-version string[]  ip version to use (4, 6) (default 4)

PROBES:
   -san                     display subject alternative names
   -cn                      display subject common names
   -so                      display subject organization name
   -tv, -tls-version        display used tls version
   -cipher                  display used cipher
   -hash string             display certificate fingerprint hashes (md5,sha1,sha256)
   -jarm                    display jarm fingerprint hash
   -ja3                     display ja3 fingerprint hash (using ztls)
   -wc, -wildcard-cert      display host with wildcard ssl certificate
   -tps, -probe-status      display tls probe status
   -ve, -version-enum       enumerate and display supported tls versions
   -ce, -cipher-enum        enumerate and display supported cipher
   -ct, -cipher-type value  ciphers types to enumerate. possible values: all/secure/insecure/weak (comma-separated) (default all)
   -ch, -client-hello       include client hello in json output (ztls mode only)
   -sh, -server-hello       include server hello in json output (ztls mode only)
   -se, -serial             display certificate serial number

MISCONFIGURATIONS:
   -ex, -expired      display host with host expired certificate
   -ss, -self-signed  display host with self-signed certificate
   -mm, -mismatched   display host with mismatched certificate
   -re, -revoked      display host with revoked certificate
   -un, -untrusted    display host with untrusted certificate

CONFIGURATIONS:
   -config string               path to the tlsx configuration file
   -r, -resolvers string[]      list of resolvers to use
   -cc, -cacert string          client certificate authority file
   -ci, -cipher-input string[]  ciphers to use with tls connection
   -sni string[]                tls sni hostname to use
   -rs, -random-sni             use random sni when empty
   -rps, -rev-ptr-sni           perform reverse PTR to retrieve SNI from IP
   -min-version string          minimum tls version to accept (ssl30,tls10,tls11,tls12,tls13)
   -max-version string          maximum tls version to accept (ssl30,tls10,tls11,tls12,tls13)
   -cert, -certificate          include certificates in json output (PEM format)
   -tc, -tls-chain              include certificates chain in json output
   -vc, -verify-cert            enable verification of server certificate
   -ob, -openssl-binary string  OpenSSL Binary Path
   -hf, -hardfail               strategy to use if encountered errors while checking revocation status

OPTIMIZATIONS:
   -c, -concurrency int  number of concurrent threads to process (default 300)
   -cec, -cipher-concurrency int  cipher enum concurrency for each target (default 10)
   -timeout int          tls connection timeout in seconds (default 5)
   -retry int            number of retries to perform for failures (default 3)
   -delay string         duration to wait between each connection per thread (eg: 200ms, 1s)

UPDATE:
   -up, -update                 update tlsx to latest version
   -duc, -disable-update-check  disable automatic tlsx update check

OUTPUT:
   -o, -output string  file to write output to
   -j, -json           display output in jsonline format
   -ro, -resp-only     display tls response only
   -silent             display silent output
   -nc, -no-color      disable colors in cli output
   -v, -verbose        display verbose output
   -version            display project version

DEBUG:
   -health-check, -hc  run diagnostic check up
```

## Using tlsx as library

Examples of using tlsx as library are provided in the [examples](examples/) folder.

## Running tlsx

### Input for tlsx

**tlsx** requires **ip** to make TLS connection and accept multiple format as listed below:

```bash
AS1449 # ASN input
173.0.84.0/24 # CIDR input
93.184.216.34 # IP input
example.com # DNS input
example.com:443 # DNS input with port
https://example.com:443 # URL input port
```

Input host can be provided using `-host / -u` flag, and multiple values can be provided using comma-separated input, similarly **file** input is supported using `-list / -l` flag.

Example of comma-separated host input: 

```console
$ tlsx -u 93.184.216.34,example.com,example.com:443,https://example.com:443 -silent
```

Example of file based host input:

```console
$ tlsx -list host_list.txt
```

**Port Input:**

**tlsx** connects on port **443** by default, which can be customized using `-port / -p` flag, single or multiple ports can be specified using comma sperated input or new line delimited file containing list of ports to connect. 


Example of comma-separated port input: 

```
$ tlsx -u hackerone.com -p 443,8443
```

Example of file based port input: 

```
$ tlsx -u hackerone.com -p port_list.txt
```

**Note:**

> When input host contains port in it, for example, `8.8.8.8:443` or `hackerone.com:8443`, port specified with host will be used to make TLS connection instead of default or one provided using `-port / -p` flag.

### TLS Probe (default run)

This will run the tool against the given CIDR range and returns hosts that accepts tls connection on port 443.

```console
$ echo 173.0.84.0/24 | tlsx 
  

  _____ _    _____  __
 |_   _| |  / __\ \/ /
   | | | |__\__ \>  < 
   |_| |____|___/_/\_\  v0.0.1

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

### SAN/CN Probe

TLS certificate contains DNS names under **subject alternative name** and **common name** field that can be extracted using `-san`, `-cn` flag.

```console
$ echo 173.0.84.0/24 | tlsx -san -cn -silent

173.0.84.104:443 [uptycspay.paypal.com]
173.0.84.104:443 [api-3t.paypal.com]
173.0.84.104:443 [api-m.paypal.com]
173.0.84.104:443 [payflowpro.paypal.com]
173.0.84.104:443 [pointofsale-s.paypal.com]
173.0.84.104:443 [svcs.paypal.com]
173.0.84.104:443 [uptycsven.paypal.com]
173.0.84.104:443 [api-aa.paypal.com]
173.0.84.104:443 [pilot-payflowpro.paypal.com]
173.0.84.104:443 [pointofsale.paypal.com]
173.0.84.104:443 [uptycshon.paypal.com]
173.0.84.104:443 [api.paypal.com]
173.0.84.104:443 [adjvendor.paypal.com]
173.0.84.104:443 [zootapi.paypal.com]
173.0.84.104:443 [api-aa-3t.paypal.com]
173.0.84.104:443 [uptycsize.paypal.com]
```

For ease of automation, optionally `-resp-only` flag can be used to list only dns names in CLI output.

```console
$ echo 173.0.84.0/24 | tlsx -san -cn -silent -resp-only

api-aa-3t.paypal.com
pilot-payflowpro.paypal.com
pointofsale-s.paypal.com
uptycshon.paypal.com
a.paypal.com
adjvendor.paypal.com
zootapi.paypal.com
api-aa.paypal.com
payflowpro.paypal.com
pointofsale.paypal.com
uptycspay.paypal.com
api-3t.paypal.com
uptycsize.paypal.com
api.paypal.com
api-m.paypal.com
svcs.paypal.com
uptycsven.paypal.com
uptycsven.paypal.com
a.paypal.com
api.paypal.com
pointofsale-s.paypal.com
pilot-payflowpro.paypal.com
```

**subdomains** obtained from TLS certificates can be further piped to other PD tools for further inspection, here is an example piping tls subdomains to **[dnsx](https://github.com/projectdiscovery/dnsx)** to filter passive subdomains and passing to **[httpx](https://github.com/projectdiscovery/httpx)** to list hosts running active web services.

```console
$ echo 173.0.84.0/24 | tlsx -san -cn -silent -resp-only | dnsx -silent | httpx

    __    __  __       _  __
   / /_  / /_/ /_____ | |/ /
  / __ \/ __/ __/ __ \|   /
 / / / / /_/ /_/ /_/ /   |
/_/ /_/\__/\__/ .___/_/|_|
             /_/              v1.2.2

    projectdiscovery.io

Use with caution. You are responsible for your actions.
Developers assume no liability and are not responsible for any misuse or damage.
https://api-m.paypal.com
https://uptycsize.paypal.com
https://api.paypal.com
https://uptycspay.paypal.com
https://svcs.paypal.com
https://adjvendor.paypal.com
https://uptycshap.paypal.com
https://uptycshon.paypal.com
https://pilot-payflowpro.paypal.com
https://slc-a-origin-pointofsale.paypal.com
https://uptycsven.paypal.com
https://api-aa.paypal.com
https://api-aa-3t.paypal.com
https://uptycsbrt.paypal.com
https://payflowpro.paypal.com
http://pointofsale-s.paypal.com
http://slc-b-origin-pointofsale.paypal.com
http://api-3t.paypal.com
http://zootapi.paypal.com
http://pointofsale.paypal.com
````

### TLS / Cipher Probe

```console
$ subfinder -d hackerone.com | tlsx -tls-version -cipher

mta-sts.hackerone.com:443 [TLS1.3] [TLS_AES_128_GCM_SHA256]
hackerone.com:443 [TLS1.3] [TLS_AES_128_GCM_SHA256]
api.hackerone.com:443 [TLS1.3] [TLS_AES_128_GCM_SHA256]
mta-sts.managed.hackerone.com:443 [TLS1.3] [TLS_AES_128_GCM_SHA256]
mta-sts.forwarding.hackerone.com:443 [TLS1.3] [TLS_AES_128_GCM_SHA256]
www.hackerone.com:443 [TLS1.3] [TLS_AES_128_GCM_SHA256]
support.hackerone.com:443 [TLS1.2] [TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]
```

# TLS Misconfiguration

### Expired / Self Signed / Mismatched / Revoked / Untrusted Certificate

A list of host can be provided to tlsx to detect **expired / self-signed / mismatched / revoked / untrusted** certificates.

```console
$ tlsx -l hosts.txt -expired -self-signed -mismatched -revoked -untrusted
  

  _____ _    _____  __
 |_   _| |  / __\ \/ /
   | | | |__\__ \>  < 
   |_| |____|___/_/\_\  v0.0.1

    projectdiscovery.io

[WRN] Use with caution. You are responsible for your actions.
[WRN] Developers assume no liability and are not responsible for any misuse or damage.

wrong.host.badssl.com:443 [mismatched]
self-signed.badssl.com:443 [self-signed]
expired.badssl.com:443 [expired]
revoked.badssl.com:443 [revoked]
untrusted-root.badssl.com:443 [untrusted]
```

### [JARM](https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a/) TLS Fingerprint

```console
$ echo hackerone.com | tlsx -jarm -silent

hackerone.com:443 [29d3dd00029d29d00042d43d00041d5de67cc9954cc85372523050f20b5007]
```

### [JA3](https://github.com/salesforce/ja3) TLS Fingerprint

```console
$ echo hackerone.com | tlsx -ja3 -silent

hackerone.com:443 [20c9baf81bfe96ff89722899e75d0190]
```

### JSON Output

**tlsx** does support multiple probe flags to query specific data, but all the information is always available in JSON format, for automation and post processing using `-json` output is most convenient option to use.

```console
echo example.com | tlsx -json -silent | jq .
```

```json
{
  "timestamp": "2022-08-22T21:22:59.799053+05:30",
  "host": "example.com",
  "ip": "93.184.216.34",
  "port": "443",
  "probe_status": true,
  "tls_version": "tls13",
  "cipher": "TLS_AES_256_GCM_SHA384",
  "not_before": "2022-03-14T00:00:00Z",
  "not_after": "2023-03-14T23:59:59Z",
  "subject_dn": "CN=www.example.org, O=Internet Corporation for Assigned Names and Numbers, L=Los Angeles, ST=California, C=US",
  "subject_cn": "www.example.org",
  "subject_org": [
    "Internet Corporation for Assigned Names and Numbers"
  ],
  "subject_an": [
    "www.example.org",
    "example.net",
    "example.edu",
    "example.com",
    "example.org",
    "www.example.com",
    "www.example.edu",
    "www.example.net"
  ],
  "issuer_dn": "CN=DigiCert TLS RSA SHA256 2020 CA1, O=DigiCert Inc, C=US",
  "issuer_cn": "DigiCert TLS RSA SHA256 2020 CA1",
  "issuer_org": [
    "DigiCert Inc"
  ],
  "fingerprint_hash": {
    "md5": "c5208a47259d540a6e3404dddb85af91",
    "sha1": "df81dfa6b61eafdffffe1a250240db5d2e6cee25",
    "sha256": "7f2fe8d6b18e9a47839256cd97938daa70e8515750298ddba2f3f4b8440113fc"
  },
  "tls_connection": "ctls",
  "sni": "example.com"
}
```

## Configuration

### Scan Mode

tlsx provides multiple modes to make TLS Connection -

- `auto` (automatic fallback to other modes upon failure) - **default**
- `ctls` (**[crypto/tls](https://github.com/golang/go/blob/master/src/crypto/tls/tls.go)**)
- `ztls` (**[zcrypto/tls](https://github.com/zmap/zcrypto)**)
- `openssl` (**[openssl](https://github.com/openssl/openssl)**)

Some pointers for the specific mode / library is highlighted in [linked discussions](https://github.com/projectdiscovery/tlsx/discussions/2), `auto` mode is supported to ensure the maximum coverage and scans for the hosts running older version of TLS by retrying the connection using `ztls` and `openssl` mode upon any connection error.

An example of using `ztls` mode to scan website using old / outdated TLS version.

```console
$ echo tls-v1-0.badssl.com | tlsx -port 1010 -sm ztls
  

  _____ _    _____  __
 |_   _| |  / __\ \/ /
   | | | |__\__ \>  < 
   |_| |____|___/_/\_\  v0.0.1

    projectdiscovery.io

[WRN] Use with caution. You are responsible for your actions.
[WRN] Developers assume no liability and are not responsible for any misuse or damage.

tls-v1-0.badssl.com:1010
```

### OpenSSL

To use the openssl connection mode, you will need to have openssl installed on your system. Most modern systems come with openssl pre-installed, but if it is not present on your system, you can install it manually. You can check if openssl is installed by running the command `openssl version`. If openssl is installed, this command will display the version number.

<table>
<tr>
<td>

### Pre-Handshake (Early Termination)

**tlsx** supports terminating SSL connection early which leads to faster scanning and less connection request (disconnecting after TLS `serverhello` and certificate data is gathered).

For more detail, please refer to [Hunting-Certificates-And-Servers](https://github.com/erbbysam/Hunting-Certificates-And-Servers/blob/master/Hunting%20Certificates%20%26%20Servers.pdf) by [@erbbysam](https://twitter.com/erbbysam)

An example of using `-pre-handshake` mode:

```console
$ tlsx -u example.com -pre-handshake 
  

  _____ _    _____  __
 |_   _| |  / __\ \/ /
   | | | |__\__ \>  < 
   |_| |____|___/_/\_\  v0.0.1

    projectdiscovery.io

[WRN] Use with caution. You are responsible for your actions.
[WRN] Developers assume no liability and are not responsible for any misuse or damage.

example.com:443
```

> **Note**:

> **pre-handshake** mode utilizes `ztls` (**zcrypto/tls**) which also means the support is limited till `TLS v1.2` as `TLS v1.3` is not supported by `ztls` library.

</table>
</tr>
</td>

### TLS Version

**Minimum** and **Maximum** TLS versions can be specified using `-min-version` and `-max-version` flags, as default these value are set by underlying used library.

The acceptable values for TLS version is specified below.

- `ssl30`
- `tls10`
- `tls11`
- `tls12`
- `tls13`

Here is an example using `max-version` to scan for hosts supporting an older version of TLS, i.e **TLS v1.0**

```console
$ tlsx -u example.com -max-version tls10
  

  _____ _    _____  __
 |_   _| |  / __\ \/ /
   | | | |__\__ \>  < 
   |_| |____|___/_/\_\  v0.0.1

    projectdiscovery.io

[WRN] Use with caution. You are responsible for your actions.
[WRN] Developers assume no liability and are not responsible for any misuse or damage.
example.com:443
```

### Custom Cipher

Supported custom cipher can provided using `-cipher-input / -ci` flag, supported cipher list for each mode is available at [wiki page](https://github.com/projectdiscovery/tlsx/wiki/Ciphers).

```console
$ tlsx -u example.com -ci TLS_AES_256_GCM_SHA384 -cipher
```

```console
$ tlsx -u example.com -ci cipher_list.txt -cipher
```

## Acknowledgements

This program optionally uses:

- [zcrypto](https://github.com/zmap/zcrypto) library from the zmap team.
- [cfssl](https://github.com/cloudflare/cfssl) library from the cloudflare team
- cipher data from [ciphersuite.info](https://ciphersuite.info) for ciphersuite classification

--------

<div align="center">

tlsx is made with ❤️ by the [projectdiscovery](https://projectdiscovery.io) team and distributed under [MIT License](LICENSE).


<a href="https://discord.gg/projectdiscovery"><img src="https://raw.githubusercontent.com/projectdiscovery/nuclei-burp-plugin/main/static/join-discord.png" width="300" alt="Join Discord"></a>

</div>
