package proxy

import "strings"

// noiseHeaders lists transport/proxy plumbing headers that carry no
// application-meaningful signal for reverse-engineering purposes. Keys are
// lowercase; StripNoiseHeaders matches case-insensitively.
var noiseHeaders = map[string]struct{}{
	"accept-encoding":     {},
	"connection":          {},
	"proxy-connection":    {},
	"proxy-authorization": {},
	"te":                  {},
	"trailer":             {},
	"transfer-encoding":   {},
	"upgrade":             {},
	"keep-alive":          {},
	"x-forwarded-for":     {},
	"x-forwarded-proto":   {},
}

// StripNoiseHeaders returns a copy of headers with transport-level noise
// headers removed (accept-encoding, connection, proxy-connection,
// proxy-authorization, te, trailer, transfer-encoding, upgrade, keep-alive,
// x-forwarded-for, x-forwarded-proto). Matching is case-insensitive; all
// other headers are kept with their original key casing and value.
func StripNoiseHeaders(headers map[string]string) map[string]string {
	clean := make(map[string]string, len(headers))
	for k, v := range headers {
		if _, isNoise := noiseHeaders[strings.ToLower(k)]; !isNoise {
			clean[k] = v
		}
	}
	return clean
}
