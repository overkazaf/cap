package agent

import (
	"encoding/json"
	"net/url"
	"regexp"
	"sort"

	"github.com/overkazaf/cap/internal/types"
)

// signKeyPatterns are case-insensitive regexes matching parameter names
// commonly used for request signing, timestamp/nonce-based replay
// protection, or app/secret identification.
var signKeyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^sign(ature)?$`),
	regexp.MustCompile(`(?i)^(time_?stamp|ts|_t)$`),
	regexp.MustCompile(`(?i)^nonce$`),
	regexp.MustCompile(`(?i)^token$`),
	regexp.MustCompile(`(?i)^hmac$`),
	regexp.MustCompile(`(?i)^hash$`),
	regexp.MustCompile(`(?i)^digest$`),
	regexp.MustCompile(`(?i)^app_?key$`),
	regexp.MustCompile(`(?i)^secret$`),
}

// DetectSignParams heuristically identifies signature/timestamp/nonce
// parameter names carried by a flow. It inspects, in order:
//
//   - the flow's URL query parameters
//   - the flow's request body, if it parses as a JSON object (keys)
//   - the flow's request body, if it parses as form-encoded data (keys)
//
// The returned slice contains the distinct matching parameter names
// (original casing preserved, de-duplicated, sorted) or nil if none were
// found.
func DetectSignParams(flow *types.Flow) []string {
	if flow == nil {
		return nil
	}

	seen := make(map[string]bool)

	if u, err := url.Parse(flow.URL); err == nil {
		for key := range u.Query() {
			if isSignKey(key) {
				seen[key] = true
			}
		}
	}

	if len(flow.ReqBody) > 0 {
		var bodyMap map[string]json.RawMessage
		if err := json.Unmarshal(flow.ReqBody, &bodyMap); err == nil {
			for key := range bodyMap {
				if isSignKey(key) {
					seen[key] = true
				}
			}
		} else if vals, err := url.ParseQuery(string(flow.ReqBody)); err == nil {
			for key := range vals {
				if isSignKey(key) {
					seen[key] = true
				}
			}
		}
	}

	if len(seen) == 0 {
		return nil
	}

	result := make([]string, 0, len(seen))
	for k := range seen {
		result = append(result, k)
	}
	sort.Strings(result)
	return result
}

// isSignKey reports whether key matches one of the known sign/timestamp/
// nonce parameter name patterns.
func isSignKey(key string) bool {
	for _, p := range signKeyPatterns {
		if p.MatchString(key) {
			return true
		}
	}
	return false
}
