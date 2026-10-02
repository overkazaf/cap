// Package agent produces compact JSONL output of captured flows, optimized
// for consumption by an LLM / coding agent rather than a human terminal:
// short field names, noise headers stripped, large bodies truncated, and
// likely sign/timestamp/nonce parameters called out explicitly.
package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/overkazaf/cap/internal/types"
)

// defaultMaxBodySize is used when FormatOptions.MaxBodySize is not set.
const defaultMaxBodySize = 4096

// truncatedSuffix is appended to any body that had to be cut short.
const truncatedSuffix = "...[truncated]"

// FormatOptions controls how Format renders flows into compact JSONL.
type FormatOptions struct {
	// MaxBodySize is the maximum number of characters of a request/response
	// body to inline before truncating. Zero (the default) uses 4096.
	MaxBodySize int
}

// compactFlow is the on-the-wire shape written for each JSONL line. Field
// names are intentionally short to minimize token usage when the output is
// consumed by an LLM / coding agent.
type compactFlow struct {
	TS         int64             `json:"ts"`
	Method     string            `json:"method"`
	URL        string            `json:"url"`
	ReqHeaders map[string]string `json:"req_headers,omitempty"`
	ReqBody    any               `json:"req_body,omitempty"`
	Status     int               `json:"status"`
	RespBody   any               `json:"resp_body,omitempty"`
	LatencyMs  int64             `json:"latency_ms"`
	Tags       []string          `json:"tags,omitempty"`
	SignParams []string          `json:"sign_params,omitempty"`
	SourceRef  *types.SourceRef  `json:"source_ref,omitempty"`
	BodyHash   string            `json:"body_hash,omitempty"`
}

// noiseHeaders lists request/response headers that carry no signal for
// reverse-engineering purposes (hop-by-hop / proxy plumbing) and are
// stripped from agent-oriented output. Implemented locally — rather than
// imported from internal/proxy — so this package has no dependency on it.
var noiseHeaders = map[string]bool{
	"accept-encoding":     true,
	"connection":          true,
	"proxy-connection":    true,
	"proxy-authorization": true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
	"keep-alive":          true,
	"x-forwarded-for":     true,
	"x-forwarded-proto":   true,
}

// stripNoiseHeaders returns a copy of headers with noise headers removed.
// Matching is case-insensitive. A nil/empty input yields a nil output so
// the field can be omitted via `omitempty`.
func stripNoiseHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	clean := make(map[string]string, len(headers))
	for k, v := range headers {
		if !noiseHeaders[strings.ToLower(k)] {
			clean[k] = v
		}
	}
	if len(clean) == 0 {
		return nil
	}
	return clean
}

// Format renders flows as JSONL — one compact JSON object per line,
// newline-separated — optimized for an LLM / coding agent: noise headers
// are stripped, bodies are parsed into inline JSON (or truncated) to stay
// within budget, and sign/timestamp/nonce parameters are auto-detected
// whenever a flow doesn't already carry them.
func Format(flows []*types.Flow, opts FormatOptions) ([]byte, error) {
	maxBodySize := opts.MaxBodySize
	if maxBodySize <= 0 {
		maxBodySize = defaultMaxBodySize
	}

	var buf strings.Builder
	for _, f := range flows {
		if f == nil {
			continue
		}

		signParams := f.SignParams
		if len(signParams) == 0 {
			signParams = DetectSignParams(f)
		}

		reqBody, _ := compactBody(f.ReqBody, maxBodySize)
		respBody, respTruncated := compactBody(f.RespBody, maxBodySize)

		cf := compactFlow{
			TS:         f.Timestamp.Unix(),
			Method:     f.Method,
			URL:        f.URL,
			ReqHeaders: stripNoiseHeaders(f.ReqHeaders),
			ReqBody:    reqBody,
			Status:     f.Status,
			RespBody:   respBody,
			LatencyMs:  f.LatencyMs,
			Tags:       f.Tags,
			SignParams: signParams,
			SourceRef:  f.SourceRef,
		}

		if respTruncated {
			cf.BodyHash = bodyHash(f.RespBody)
		}

		line, err := json.Marshal(cf)
		if err != nil {
			return nil, err
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	return []byte(buf.String()), nil
}

// compactBody converts a raw body into a value suitable for inline JSON
// encoding. Valid JSON is parsed into `any` so it nests directly into the
// output without double-escaping; anything else — or valid JSON that
// doesn't fit within maxSize — is rendered as a string, truncated to
// maxSize characters with a truncation marker appended if needed.
//
// It reports whether the body had to be truncated, which callers use to
// decide whether a body_hash should accompany the value.
func compactBody(body []byte, maxSize int) (value any, truncated bool) {
	if len(body) == 0 {
		return nil, false
	}

	var parsed any
	if err := json.Unmarshal(body, &parsed); err == nil {
		if compact, err := json.Marshal(parsed); err == nil && len(compact) <= maxSize {
			return parsed, false
		}
		// Valid JSON, but too large to inline as-is: fall through to the
		// truncated-string representation below.
	}

	s := string(body)
	if len(s) > maxSize {
		return s[:maxSize] + truncatedSuffix, true
	}
	return s, false
}

// bodyHash returns a short content fingerprint for body: the first 8 bytes
// of its SHA-256 digest, hex-encoded.
func bodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:8])
}
