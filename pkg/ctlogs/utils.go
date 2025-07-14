package ctlogs

import "strings"

// FormatSourceID converts a CT log source description to a stable, human-friendly
// identifier consisting of lowercase characters and underscores.
//
// Examples:
//
//	"Google 'Xenon2025h2'"  -> "google_xenon2025h2"
//	"Cloudflare-Nimbus2026" -> "cloudflare_nimbus2026"
func FormatSourceID(sourceName string) string {
	id := strings.ToLower(sourceName)
	id = strings.ReplaceAll(id, "'", "")
	id = strings.ReplaceAll(id, " ", "_")
	id = strings.ReplaceAll(id, "-", "_")
	return id
}
