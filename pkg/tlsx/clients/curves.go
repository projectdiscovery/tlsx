package clients

import (
	"crypto/tls"
	"strconv"
	"strings"

	errorutil "github.com/projectdiscovery/utils/errors"
)

const (
	// Additional TLS Supported Groups (KEMs) defined as CurveID values for compatibility
	SecP256r1MLKEM768  tls.CurveID = 4587
	SecP384r1MLKEM1024 tls.CurveID = 4589
	MLKEM1024          tls.CurveID = 514
)

// SupportedTLSGroups contains all canonical TLS key-exchange group names supported by ctls.
var SupportedTLSGroups = []string{
	"X25519MLKEM768",
	"X25519",
	"CurveP256",
	"CurveP384",
	"CurveP521",
	"SecP256r1MLKEM768",
	"SecP384r1MLKEM1024",
	"MLKEM1024",
}

// canonicalCurveMap maps normalized strings (lowercase, alphanumeric only) to tls.CurveID
var canonicalCurveMap = map[string]tls.CurveID{
	// Canonical and common names
	"x25519mlkem768":     tls.X25519MLKEM768,
	"x25519":             tls.X25519,
	"curvep256":          tls.CurveP256,
	"p256":               tls.CurveP256,
	"secp256r1":          tls.CurveP256,
	"prime256v1":         tls.CurveP256,
	"curvep384":          tls.CurveP384,
	"p384":               tls.CurveP384,
	"secp384r1":          tls.CurveP384,
	"curvep521":          tls.CurveP521,
	"p521":               tls.CurveP521,
	"secp521r1":          tls.CurveP521,
	"secp256r1mlkem768":  SecP256r1MLKEM768,
	"p256mlkem768":       SecP256r1MLKEM768,
	"secp384r1mlkem1024": SecP384r1MLKEM1024,
	"p384mlkem1024":      SecP384r1MLKEM1024,
	"mlkem1024":          MLKEM1024,

	// Numeric codepoint string representations
	"23":   tls.CurveP256,
	"24":   tls.CurveP384,
	"25":   tls.CurveP521,
	"29":   tls.X25519,
	"514":  MLKEM1024,
	"4587": SecP256r1MLKEM768,
	"4588": tls.X25519MLKEM768,
	"4589": SecP384r1MLKEM1024,
}

// normalizeGroupName strips dashes, underscores, and lowercase the string
func normalizeGroupName(name string) string {
	r := strings.NewReplacer("-", "", "_", "", " ", "")
	return strings.ToLower(r.Replace(strings.TrimSpace(name)))
}

// ToCurveIDs parses an ordered list of group names or numeric codepoints into []tls.CurveID.
// It preserves the input order and rejects any unrecognized group names.
func ToCurveIDs(items []string) ([]tls.CurveID, error) {
	if len(items) == 0 {
		return nil, nil
	}
	var curves []tls.CurveID
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		normalized := normalizeGroupName(trimmed)
		curveID, ok := canonicalCurveMap[normalized]
		if !ok {
			// Check if it's a numeric ID that maps to a known CurveID
			if id, err := strconv.ParseUint(trimmed, 10, 16); err == nil {
				candidate := tls.CurveID(id)
				switch candidate {
				case tls.CurveP256, tls.CurveP384, tls.CurveP521, tls.X25519,
					MLKEM1024, SecP256r1MLKEM768, tls.X25519MLKEM768, SecP384r1MLKEM1024:
					curveID = candidate
					ok = true
				}
			}
		}
		if !ok {
			return nil, errorutil.NewWithTag("ctls", "unsupported tls group: %s", trimmed)
		}
		curves = append(curves, curveID)
	}
	return curves, nil
}

// CurveIDToName returns the canonical name of a CurveID
func CurveIDToName(c tls.CurveID) string {
	switch c {
	case tls.X25519MLKEM768:
		return "X25519MLKEM768"
	case tls.X25519:
		return "X25519"
	case tls.CurveP256:
		return "CurveP256"
	case tls.CurveP384:
		return "CurveP384"
	case tls.CurveP521:
		return "CurveP521"
	case SecP256r1MLKEM768:
		return "SecP256r1MLKEM768"
	case SecP384r1MLKEM1024:
		return "SecP384r1MLKEM1024"
	case MLKEM1024:
		return "MLKEM1024"
	default:
		return c.String()
	}
}

// CurveIDsToNames converts a slice of tls.CurveID to their canonical string representations.
func CurveIDsToNames(curves []tls.CurveID) []string {
	if len(curves) == 0 {
		return nil
	}
	names := make([]string, 0, len(curves))
	for _, c := range curves {
		names = append(names, CurveIDToName(c))
	}
	return names
}
