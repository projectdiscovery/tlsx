package ja3

import (
    "crypto/md5"
    "encoding/hex"
    "sort"
    "strconv"

    "github.com/zmap/zcrypto/tls"
)

const (
	dashByte  = byte(45)
	commaByte = byte(44)

	// GREASE values
	// The bitmask covers all GREASE values
	greaseBitmask uint16 = 0x0F0F
)

// TLS extension numbers
const (
	extensionServerName           uint16 = 0
	extensionStatusRequest        uint16 = 5
	extensionSupportedCurves      uint16 = 10
	extensionSupportedPoints      uint16 = 11
	extensionSignatureAlgorithms  uint16 = 13
	extensionALPN                 uint16 = 16
	extensionExtendedMasterSecret uint16 = 23
	extensionSessionTicket        uint16 = 35
	extensionNextProtoNeg         uint16 = 13172 // not IANA assigned
	extensionRenegotiationInfo    uint16 = 0xff01
	extensionExtendedRandom       uint16 = 0x0028 // not IANA assigned
	extensionSCT                  uint16 = 18
	extensionHeartbeat            uint16 = 15
)


// GetJa3SHash returns the JA3 fingerprint hash of the tls client hello.
func GetJa3Hash(serverHello *tls.ServerHello, clientHello *tls.ClientHello) string {
    byteString := make([]byte, 0)

    // Version
    tlsVersion := strconv.FormatUint(uint64(serverHello.Version), 10)
//  fmt.Printf("TLS Version (Decimal): %s\n", tlsVersion)
    byteString = append(byteString, []byte(tlsVersion)...)

    byteString = append(byteString, commaByte)

    // Chosen Cipher Suite
    cipherBytes := strconv.AppendUint(nil, uint64(serverHello.CipherSuite), 10)
//  fmt.Printf("Chosen Cipher Suite (Bytes): %v\n", cipherBytes)
    byteString = append(byteString, cipherBytes...)

    byteString = append(byteString, commaByte)

    // Collect extensions
    extensions := make([]uint16, 0)

    // Append the ALPN extension if present
    if len(serverHello.AlpnProtocol) > 0 {
        extensions = append(extensions, extensionALPN)
    }

    // Append other extensions based on serverHello flags
    if serverHello.OcspStapling {
        extensions = append(extensions, extensionStatusRequest)
    }
    if serverHello.TicketSupported {
        extensions = append(extensions, extensionSessionTicket)
    }
    if serverHello.SecureRenegotiation {
        extensions = append(extensions, extensionRenegotiationInfo)
    }
    if serverHello.HeartbeatSupported {
        extensions = append(extensions, extensionHeartbeat)
    }
    if serverHello.ExtendedMasterSecret {
        extensions = append(extensions, extensionExtendedMasterSecret)
    }
    if len(serverHello.ExtendedRandom) > 0 {
        extensions = append(extensions, extensionExtendedRandom)
    }

    // Sort extensions
    sort.Slice(extensions, func(i, j int) bool {
        return extensions[i] < extensions[j]
    })

    // Append sorted extensions to byteString
    for _, exType := range extensions {
        byteString = appendExtension(byteString, exType)
    }

    // Remove trailing comma if present
    if len(byteString) > 0 && byteString[len(byteString)-1] == dashByte {
        byteString = byteString[:len(byteString)-1]
    }


//  fmt.Println("Fingerprint before hashing:", string(byteString))

    // Hash and return the byteString
    h := md5.Sum(byteString)
    return hex.EncodeToString(h[:])
}

func appendExtension(byteString []byte, exType uint16) []byte {
    // Ignore any GREASE extensions
    if exType&greaseBitmask != 0x0A0A {
        byteString = strconv.AppendUint(byteString, uint64(exType), 10)
        byteString = append(byteString, dashByte)
    }
    return byteString
}
