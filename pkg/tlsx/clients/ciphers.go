package clients

import (
	"strings"

	"github.com/projectdiscovery/tlsx/assets"
)

// CipherSecLevel
type CipherSecLevel uint

const (
	All CipherSecLevel = iota //Default
	Weak
	Insecure
	Secure
	Unknown
)

// GetCiphersWithLevel returns list of ciphers that have given secLevel
func GetCiphersWithLevel(cipherList []string, SecLevel ...CipherSecLevel) []string {
	toEnumerate := []string{}
	if len(SecLevel) == 0 {
		// when no seclevel is given returns all
		return cipherList
	}
	for _, level := range SecLevel {
		switch level {
		case All:
			return cipherList
		case Weak:
			toEnumerate = append(toEnumerate, IntersectStringSlices(cipherList, assets.GetWeakCipherSuites())...)
		case Insecure:
			toEnumerate = append(toEnumerate, IntersectStringSlices(cipherList, assets.GetInSecureCipherSuites())...)
		case Secure:
			toEnumerate = append(toEnumerate, IntersectStringSlices(cipherList, assets.GetSecureCipherSuites())...)
		}
	}
	return toEnumerate
}

// GetCipherLevel returns security level of given cipher
func GetCipherLevel(cipherName string) CipherSecLevel {
	for k, v := range assets.CipherSecLevel {
		if strings.EqualFold(k, cipherName) {
			switch v {
			case "Recommended":
				return Secure
			case "Secure":
				return Secure
			case "Insecure":
				return Insecure
			case "Weak":
				return Weak
			}
		}
	}
	return Unknown
}
