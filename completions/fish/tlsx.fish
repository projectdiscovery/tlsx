# tlsx shell completions

# Input
complete -c tlsx -s u -d 'Target host to scan' -r
complete -c tlsx -o host -d 'Target host to scan' -r
complete -c tlsx -s l -d 'Target list file' -r
complete -c tlsx -o list -d 'Target list file' -r
complete -c tlsx -s p -d 'Target port to connect' -r
complete -c tlsx -o port -d 'Target port to connect' -r

# Scan mode
complete -c tlsx -o sm -d 'TLS connection mode' -r -f -a 'ctls ztls openssl auto'
complete -c tlsx -o scan-mode -d 'TLS connection mode' -r -f -a 'ctls ztls openssl auto'
complete -c tlsx -o ps -d 'Enable pre-handshake TLS connection'
complete -c tlsx -o pre-handshake -d 'Enable pre-handshake TLS connection'
complete -c tlsx -o sa -d 'Scan all IPs for a host'
complete -c tlsx -o scan-all-ips -d 'Scan all IPs for a host'
complete -c tlsx -o iv -d 'IP versions to use' -r -f -a '4 6'
complete -c tlsx -o ip-version -d 'IP versions to use' -r -f -a '4 6'

# Probes
complete -c tlsx -o san -d 'Display subject alternative names'
complete -c tlsx -o cn -d 'Display subject common names'
complete -c tlsx -o so -d 'Display subject organization name'
complete -c tlsx -o tv -d 'Display used TLS version'
complete -c tlsx -o tls-version -d 'Display used TLS version'
complete -c tlsx -o cipher -d 'Display used cipher'
complete -c tlsx -o hash -d 'Certificate fingerprint hashes' -r -f -a 'md5 sha1 sha256'
complete -c tlsx -o jarm -d 'Display JARM fingerprint'
complete -c tlsx -o ja3 -d 'Display JA3 fingerprint'
complete -c tlsx -o ja3s -d 'Display JA3S fingerprint'
complete -c tlsx -o wc -d 'Display wildcard certificate hosts'
complete -c tlsx -o wildcard-cert -d 'Display wildcard certificate hosts'
complete -c tlsx -o tps -d 'Display TLS probe status'
complete -c tlsx -o probe-status -d 'Display TLS probe status'
complete -c tlsx -o ve -d 'Enumerate supported TLS versions'
complete -c tlsx -o version-enum -d 'Enumerate supported TLS versions'
complete -c tlsx -o ce -d 'Enumerate supported ciphers'
complete -c tlsx -o cipher-enum -d 'Enumerate supported ciphers'
complete -c tlsx -o ct -d 'Cipher types' -r -f -a 'all secure insecure weak'
complete -c tlsx -o cipher-type -d 'Cipher types' -r -f -a 'all secure insecure weak'
complete -c tlsx -o ch -d 'Include client hello in JSON output'
complete -c tlsx -o client-hello -d 'Include client hello in JSON output'
complete -c tlsx -o sh -d 'Include server hello in JSON output'
complete -c tlsx -o server-hello -d 'Include server hello in JSON output'
complete -c tlsx -o se -d 'Display certificate serial number'
complete -c tlsx -o serial -d 'Display certificate serial number'

# Certificate transparency logs
complete -c tlsx -o ctl -d 'Enable CT logs streaming mode'
complete -c tlsx -o ct-logs -d 'Enable CT logs streaming mode'
complete -c tlsx -o cb -d 'Start CT log streaming from index 0'
complete -c tlsx -o ctl-beginning -d 'Start CT log streaming from index 0'
complete -c tlsx -o cti -d 'Custom CT log start index' -r
complete -c tlsx -o ctl-index -d 'Custom CT log start index' -r

# Misconfigurations
complete -c tlsx -o ex -d 'Display expired certificates'
complete -c tlsx -o expired -d 'Display expired certificates'
complete -c tlsx -o ss -d 'Display self-signed certificates'
complete -c tlsx -o self-signed -d 'Display self-signed certificates'
complete -c tlsx -o mm -d 'Display mismatched certificates'
complete -c tlsx -o mismatched -d 'Display mismatched certificates'
complete -c tlsx -o re -d 'Display revoked certificates'
complete -c tlsx -o revoked -d 'Display revoked certificates'
complete -c tlsx -o un -d 'Display untrusted certificates'
complete -c tlsx -o untrusted -d 'Display untrusted certificates'

# Configuration
complete -c tlsx -o config -d 'Configuration file' -r
complete -c tlsx -s r -d 'Resolvers to use' -r
complete -c tlsx -o resolvers -d 'Resolvers to use' -r
complete -c tlsx -o cc -d 'Client CA certificate file' -r
complete -c tlsx -o cacert -d 'Client CA certificate file' -r
complete -c tlsx -o ci -d 'Ciphers to use' -r
complete -c tlsx -o cipher-input -d 'Ciphers to use' -r
complete -c tlsx -o tg -d 'TLS key-exchange groups' -r
complete -c tlsx -o tls-groups -d 'TLS key-exchange groups' -r
complete -c tlsx -o sni -d 'SNI hostname' -r
complete -c tlsx -o rs -d 'Use random SNI when empty'
complete -c tlsx -o random-sni -d 'Use random SNI when empty'
complete -c tlsx -o rps -d 'Use reverse PTR for SNI'
complete -c tlsx -o rev-ptr-sni -d 'Use reverse PTR for SNI'
complete -c tlsx -o min-version -d 'Minimum TLS version' -r -f -a 'ssl30 tls10 tls11 tls12 tls13'
complete -c tlsx -o max-version -d 'Maximum TLS version' -r -f -a 'ssl30 tls10 tls11 tls12 tls13'
complete -c tlsx -o cert -d 'Include certificates in JSON output'
complete -c tlsx -o certificate -d 'Include certificates in JSON output'
complete -c tlsx -o tc -d 'Include certificate chain in JSON output'
complete -c tlsx -o tls-chain -d 'Include certificate chain in JSON output'
complete -c tlsx -o vc -d 'Verify server certificate'
complete -c tlsx -o verify-cert -d 'Verify server certificate'
complete -c tlsx -o ob -d 'OpenSSL binary path' -r
complete -c tlsx -o openssl-binary -d 'OpenSSL binary path' -r
complete -c tlsx -o hf -d 'Treat revocation check errors as revoked'
complete -c tlsx -o hardfail -d 'Treat revocation check errors as revoked'
complete -c tlsx -o proxy -d 'SOCKS5 proxy' -r

# Optimizations
complete -c tlsx -s c -d 'Concurrent threads' -r
complete -c tlsx -o concurrency -d 'Concurrent threads' -r
complete -c tlsx -o cec -d 'Cipher enumeration concurrency' -r
complete -c tlsx -o cipher-concurrency -d 'Cipher enumeration concurrency' -r
complete -c tlsx -o timeout -d 'TLS connection timeout in seconds' -r
complete -c tlsx -o retry -d 'Number of retries' -r
complete -c tlsx -o delay -d 'Delay between connections' -r

# Update
complete -c tlsx -o up -d 'Update tlsx'
complete -c tlsx -o update -d 'Update tlsx'
complete -c tlsx -o duc -d 'Disable automatic update check'
complete -c tlsx -o disable-update-check -d 'Disable automatic update check'

# Output
complete -c tlsx -s o -d 'Output file' -r
complete -c tlsx -o output -d 'Output file' -r
complete -c tlsx -s j -d 'JSON output'
complete -c tlsx -o json -d 'JSON output'
complete -c tlsx -o dns -d 'Display DNS data'
complete -c tlsx -o ro -d 'Display response only'
complete -c tlsx -o resp-only -d 'Display response only'
complete -c tlsx -o silent -d 'Silent mode'
complete -c tlsx -o nc -d 'Disable color'
complete -c tlsx -o no-color -d 'Disable color'
complete -c tlsx -s v -d 'Verbose output'
complete -c tlsx -o verbose -d 'Verbose output'
complete -c tlsx -o version -d 'Show version'

# PDCP
complete -c tlsx -o pd -d 'Upload results to PDCP dashboard'
complete -c tlsx -o dashboard -d 'Upload results to PDCP dashboard'
complete -c tlsx -o pdu -d 'Upload output file to PDCP dashboard' -r
complete -c tlsx -o dashboard-upload -d 'Upload output file to PDCP dashboard' -r
complete -c tlsx -o auth -d 'PDCP API key' -r
complete -c tlsx -o tid -d 'PDCP team ID' -r
complete -c tlsx -o team-id -d 'PDCP team ID' -r
complete -c tlsx -o aid -d 'Existing PDCP asset ID' -r
complete -c tlsx -o asset-id -d 'Existing PDCP asset ID' -r
complete -c tlsx -o aname -d 'PDCP asset group name' -r
complete -c tlsx -o asset-name -d 'PDCP asset group name' -r

# Debug
complete -c tlsx -o health-check -d 'Run diagnostic check'
complete -c tlsx -o hc -d 'Run diagnostic check'
