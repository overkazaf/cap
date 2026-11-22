package redaction

import (
	"encoding/json"
	"net/url"
	"strings"
	"unicode"
)

const Placeholder = "[REDACTED]"

var sensitiveHeaderNames = map[string]struct{}{
	"authorization":       {},
	"proxy-authorization": {},
	"cookie":              {},
	"set-cookie":          {},
	"x-api-key":           {},
	"x-auth-token":        {},
	"x-access-token":      {},
	"x-session-token":     {},
	"x-csrf-token":        {},
	"x-xsrf-token":        {},
}

var sensitiveQueryKeys = map[string]struct{}{
	"access_token": {}, "api_key": {}, "apikey": {}, "auth": {}, "authorization": {},
	"client_secret": {}, "password": {}, "passwd": {}, "secret": {}, "session_id": {},
	"sessionid": {}, "signature": {}, "sig": {}, "token": {},
}

// Headers returns a copy with sensitive header values replaced. Key casing is
// preserved so clients can still inspect request shape.
func Headers(headers map[string]string) map[string]string {
	if headers == nil {
		return nil
	}
	result := make(map[string]string, len(headers))
	for key, value := range headers {
		if IsSensitiveHeader(key) {
			result[key] = Placeholder
		} else {
			result[key] = value
		}
	}
	return result
}

func IsSensitiveHeader(key string) bool {
	_, exists := sensitiveHeaderNames[strings.ToLower(strings.TrimSpace(key))]
	return exists
}

// URL redacts sensitive query parameters while preserving other URL fields.
// Invalid URLs are returned unchanged.
func URL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	values := parsed.Query()
	changed := false
	for key, vals := range values {
		if !IsSensitiveQueryKey(key) {
			continue
		}
		for index := range vals {
			vals[index] = Placeholder
		}
		changed = true
	}
	if !changed {
		return rawURL
	}
	parsed.RawQuery = values.Encode()
	return parsed.String()
}

func IsSensitiveQueryKey(key string) bool {
	canonical := strings.ToLower(strings.TrimSpace(key))
	_, exists := sensitiveQueryKeys[canonical]
	return exists
}

// Body redacts sensitive values in JSON without altering unrelated bytes.
// It succeeds for any valid JSON top-level value. Invalid JSON is returned
// unchanged and marked ok=false.
func Body(body []byte) (result []byte, ok bool) {
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		return body, false
	}
	redacted := redactValue(value)
	encoded, err := json.Marshal(redacted)
	if err != nil {
		return body, false
	}
	return encoded, true
}

func redactValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if isSensitiveBodyKey(key) {
				if _, complex := child.(map[string]any); complex {
					continue
				}
				if _, complex := child.([]any); complex {
					continue
				}
				typed[key] = Placeholder
			} else {
				typed[key] = redactValue(child)
			}
		}
		return typed
	case []any:
		for index, child := range typed {
			typed[index] = redactValue(child)
		}
		return typed
	default:
		return value
	}
}

func isSensitiveBodyKey(key string) bool {
	canonical := strings.Builder{}
	for _, char := range strings.ToLower(key) {
		if unicode.IsLetter(char) || unicode.IsDigit(char) {
			canonical.WriteRune(char)
		}
	}
	_, exists := sensitiveQueryKeys[canonical.String()]
	return exists
}
