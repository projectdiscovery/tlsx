package ja3

import (
	"crypto/md5"
	"encoding/hex"
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

// GetJa3Hash computes the JA3 fingerprint hash from a TLS ClientHello message.
// It structures the fingerprint as: SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
func GetJa3Hash(clientHello *tls.ClientHello) string {
	byteString := make([]byte, 0)

	// Version
	byteString = strconv.AppendUint(byteString, uint64(clientHello.Version), 10)
	byteString = append(byteString, commaByte)

	// Cipher Suites
	if len(clientHello.CipherSuites) != 0 {
		for _, val := range clientHello.CipherSuites {
			byteString = strconv.AppendUint(byteString, uint64(val), 10)
			byteString = append(byteString, dashByte)
		}
		// Replace last dash with a comma
		byteString[len(byteString)-1] = commaByte
	} else {
		byteString = append(byteString, commaByte)
	}

	// Extensions
	if len(clientHello.ServerName) > 0 {
		byteString = appendExtension(byteString, extensionServerName)
	}

	if clientHello.NextProtoNeg {
		byteString = appendExtension(byteString, extensionNextProtoNeg)
	}

	if clientHello.OcspStapling {
		byteString = appendExtension(byteString, extensionStatusRequest)
	}

	if len(clientHello.SupportedCurves) > 0 {
		byteString = appendExtension(byteString, extensionSupportedCurves)
	}

	if len(clientHello.SupportedPoints) > 0 {
		byteString = appendExtension(byteString, extensionSupportedPoints)
	}

	if clientHello.TicketSupported {
		byteString = appendExtension(byteString, extensionSessionTicket)
	}

	if len(clientHello.SignatureAndHashes) > 0 {
		byteString = appendExtension(byteString, extensionSignatureAlgorithms)
	}

	if clientHello.SecureRenegotiation {
		byteString = appendExtension(byteString, extensionRenegotiationInfo)
	}

	if len(clientHello.AlpnProtocols) > 0 {
		byteString = appendExtension(byteString, extensionALPN)
	}

	if clientHello.HeartbeatSupported {
		byteString = appendExtension(byteString, extensionHeartbeat)
	}

	if len(clientHello.ExtendedRandom) > 0 {
		byteString = appendExtension(byteString, extensionExtendedRandom)
	}

	if clientHello.ExtendedMasterSecret {
		byteString = appendExtension(byteString, extensionExtendedMasterSecret)
	}

	if clientHello.SctEnabled {
		byteString = appendExtension(byteString, extensionSCT)
	}

	if len(clientHello.UnknownExtensions) > 0 {
		for _, ext := range clientHello.UnknownExtensions {
			exType := uint16(ext[0])<<8 | uint16(ext[1])
			byteString = appendExtension(byteString, exType)
		}
	}
	// If dash found replace it with a comma
	if byteString[len(byteString)-1] == dashByte {
		byteString[len(byteString)-1] = commaByte
	} else {
		// else add a comma (no extension present)
		byteString = append(byteString, commaByte)
	}

	// Suppported Elliptic Curves
	if len(clientHello.SupportedCurves) > 0 {
		for _, val := range clientHello.SupportedCurves {
			byteString = strconv.AppendUint(byteString, uint64(val), 10)
			byteString = append(byteString, dashByte)
		}
		// Replace last dash with a comma
		byteString[len(byteString)-1] = commaByte
	} else {
		byteString = append(byteString, commaByte)
	}

	// Elliptic Curve Point Formats
	if len(clientHello.SupportedPoints) > 0 {
		for _, val := range clientHello.SupportedPoints {
			byteString = strconv.AppendUint(byteString, uint64(val), 10)
			byteString = append(byteString, dashByte)
		}
		// Remove last dash
		byteString = byteString[:len(byteString)-1]
	}

	h := md5.Sum(byteString)
	return hex.EncodeToString(h[:])
}

// GetJa3sHash computes the JA3S fingerprint hash from a TLS ServerHello message.
// JA3S is the server-side counterpart to JA3, profiling how servers react to client hellos in SSL/TLS communication.
// It structures the fingerprint as: SSLVersion,Cipher,SSLExtension.
func GetJa3sHash(serverHello *tls.ServerHello) string {
	// NOTE: The original JA3S implementation only uses the extensions that are present,
	// as demonstrated in the Python implementation at salesforce/ja3 (https://github.com/salesforce/ja3/blob/421dd4f3616b533e6971bb700289c6bb8355e707/python/ja3s.py#L39).
	// Keep an eye on updates in the ZCrypto library for potential inclusion of additional fields in the future.
	// For current implementation details, see: https://github.com/zmap/zcrypto/blob/master/tls/tls_handshake.go#L56

	byteString := make([]byte, 0)

	// Version
	byteString = strconv.AppendUint(byteString, uint64(serverHello.Version), 10)
	byteString = append(byteString, commaByte)

	// Cipher Suites
	if len(serverHello.CipherSuite.Bytes()) != 0 {
		byteString = strconv.AppendUint(byteString, uint64(serverHello.CipherSuite), 10)
		byteString = append(byteString, commaByte)
	} else {
		byteString = append(byteString, commaByte)
	}

	// Extensions
	if serverHello.NextProtoNeg {
		byteString = appendExtension(byteString, extensionNextProtoNeg)
	}

	if serverHello.OcspStapling {
		byteString = appendExtension(byteString, extensionStatusRequest)
	}

	if serverHello.TicketSupported {
		byteString = appendExtension(byteString, extensionSessionTicket)
	}

	if serverHello.SecureRenegotiation {
		byteString = appendExtension(byteString, extensionRenegotiationInfo)
	}

	if serverHello.HeartbeatSupported {
		byteString = appendExtension(byteString, extensionHeartbeat)
	}

	if len(serverHello.ExtendedRandom) > 0 {
		byteString = appendExtension(byteString, extensionExtendedRandom)
	}

	if serverHello.ExtendedMasterSecret {
		byteString = appendExtension(byteString, extensionExtendedMasterSecret)
	}

	if len(serverHello.UnknownExtensions) > 0 {
		for _, ext := range serverHello.UnknownExtensions {
			exType := uint16(ext[0])<<8 | uint16(ext[1])
			byteString = appendExtension(byteString, exType)
		}
	}
	// If dash found replace it with a comma
	if byteString[len(byteString)-1] == dashByte {
		byteString[len(byteString)-1] = commaByte
	} else {
		// else add a comma (no extension present)
		byteString = append(byteString, commaByte)
	}

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
