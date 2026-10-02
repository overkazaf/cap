// Package sign infers how a captured HTTP request's signature-shaped
// parameters (sign, hash, hmac, token, digest, ...) were likely generated:
// which hash/HMAC algorithm produced a value of that length and encoding,
// and which of the request's other parameters (timestamp, nonce, appkey,
// ...) probably fed into it.
//
// It builds on internal/export/agent's heuristic parameter detection and
// adds length/encoding fingerprinting (analyze.go), a library of known
// signature recipes some of which can be positively confirmed against a
// real flow (patterns.go), and a brute-force secret/algorithm search
// (verify.go).
package sign

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/overkazaf/cap/internal/export/agent"
	"github.com/overkazaf/cap/internal/types"
)

// Analysis is the per-parameter result of inspecting one sign-like request
// parameter: what it looks like (length/encoding), what could have produced
// it (PossibleAlgs), and what it was probably computed from (InputGuess).
type Analysis struct {
	ParamName    string   `json:"param_name"`    // e.g. "sign"
	Value        string   `json:"value"`         // the actual sign value from the request
	Length       int      `json:"length"`        // character length
	Encoding     string   `json:"encoding"`      // "hex", "base64", "numeric", "unknown"
	PossibleAlgs []string `json:"possible_algs"` // e.g. ["MD5", "HMAC-MD5"] based on length + encoding
	InputGuess   string   `json:"input_guess"`   // guessed input pattern, e.g. "sorted_params + secret"
	Confidence   float64  `json:"confidence"`    // 0.0 - 1.0
}

// signValuePatterns matches parameter names that are plausibly a signature
// VALUE itself (something to fingerprint by length/encoding) -- as opposed
// to a companion parameter like ts/nonce/appkey that merely feeds into one.
var signValuePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^sign(ature)?$`),
	regexp.MustCompile(`(?i)^hash$`),
	regexp.MustCompile(`(?i)^hmac$`),
	regexp.MustCompile(`(?i)^token$`),
	regexp.MustCompile(`(?i)^digest$`),
}

// Companion-parameter patterns used to build InputGuess. Mirrors the
// naming conventions in internal/export/agent's signKeyPatterns.
var (
	tsKeyPattern    = regexp.MustCompile(`(?i)^(time_?stamp|ts|_t)$`)
	nonceKeyPattern = regexp.MustCompile(`(?i)^nonce$`)
	appKeyPattern   = regexp.MustCompile(`(?i)^app_?key$`)
	tokenKeyPattern = regexp.MustCompile(`(?i)^token$`)
)

// AnalyzeSingle examines one flow and returns an Analysis for every
// sign-like parameter it carries (sorted by parameter name). A flow with no
// recognizable signature parameter yields an empty slice.
func AnalyzeSingle(flow *types.Flow) []Analysis {
	if flow == nil {
		return nil
	}

	params := extractAllParams(flow)
	candidates := agent.DetectSignParams(flow)

	var results []Analysis
	for _, name := range candidates {
		if !matchesAny(signValuePatterns, name) {
			// ts/nonce/appkey/secret are companions, not signatures
			// themselves -- they feed guessInput below instead.
			continue
		}
		value, ok := params[name]
		if !ok || value == "" {
			continue
		}

		encoding := detectEncoding(value)
		length := len(value)
		algs := possibleAlgorithms(length, encoding)

		guess, boost := guessInput(params, name)
		confidence := 0.2
		if len(algs) > 0 {
			confidence = 0.5
		}
		confidence += boost

		if p := confirmedPattern(flow, value); p != nil {
			guess = p.Name
			confidence = 0.95
			if len(algs) == 0 {
				algs = []string{p.Name}
			}
		}

		results = append(results, Analysis{
			ParamName:    name,
			Value:        value,
			Length:       length,
			Encoding:     encoding,
			PossibleAlgs: algs,
			InputGuess:   guess,
			Confidence:   clamp01(confidence),
		})
	}

	sort.Slice(results, func(i, j int) bool { return results[i].ParamName < results[j].ParamName })
	return results
}

// sample pairs one flow's Analysis of a given sign parameter with that
// flow's full parameter map, so AnalyzeSign can cross-reference multiple
// requests.
type sample struct {
	analysis Analysis
	params   map[string]string
}

// AnalyzeSign runs AnalyzeSingle across every flow and merges the results
// per sign parameter name, using agreement (or disagreement) across
// requests to refine confidence and the input guess:
//
//   - a sign length that stays constant across flows raises confidence
//     (strong evidence of a deterministic fixed-width hash/HMAC)
//   - companion parameters that change value in lockstep with the sign
//     (present in every flow, but never the same value twice) are called
//     out in InputGuess as likely contributors
//   - simple timing/nonce patterns (a monotonically increasing timestamp,
//     a nonce that's unique per request) are called out as well
func AnalyzeSign(flows []*types.Flow) []Analysis {
	groups := make(map[string][]sample)
	var order []string

	for _, f := range flows {
		if f == nil {
			continue
		}
		params := extractAllParams(f)
		for _, a := range AnalyzeSingle(f) {
			if _, ok := groups[a.ParamName]; !ok {
				order = append(order, a.ParamName)
			}
			groups[a.ParamName] = append(groups[a.ParamName], sample{analysis: a, params: params})
		}
	}

	results := make([]Analysis, 0, len(order))
	for _, name := range order {
		results = append(results, mergeSamples(name, groups[name]))
	}
	return results
}

// mergeSamples combines every flow's Analysis of a single sign parameter
// into one representative Analysis, boosting confidence and refining
// InputGuess based on cross-flow agreement. See AnalyzeSign for the rules
// applied.
func mergeSamples(name string, samples []sample) Analysis {
	merged := samples[0].analysis
	if len(samples) < 2 {
		return merged
	}

	lengthConsistent := true
	signVaries := false
	for _, s := range samples[1:] {
		if s.analysis.Length != merged.Length {
			lengthConsistent = false
		}
		if s.analysis.Value != merged.Value {
			signVaries = true
		}
	}

	if lengthConsistent {
		merged.Confidence += 0.2
	}

	if signVaries {
		if varying := varyingParams(samples, name); len(varying) > 0 {
			merged.InputGuess += " (varies with: " + strings.Join(varying, ", ") + ")"
			merged.Confidence += 0.1 * float64(len(varying))
		}
	}

	if note := timingPatternNote(samples); note != "" {
		merged.InputGuess += " [" + note + "]"
	}

	merged.Confidence = clamp01(merged.Confidence)
	return merged
}

// varyingParams reports which companion parameter names (excluding the
// sign parameter itself) are present in every sample yet take on more than
// one distinct value across them -- i.e. they change from request to
// request just like the sign does, making them likely sign inputs.
func varyingParams(samples []sample, signName string) []string {
	counts := make(map[string]int)
	distinct := make(map[string]map[string]bool)

	for _, s := range samples {
		for k, v := range s.params {
			if k == signName {
				continue
			}
			counts[k]++
			if distinct[k] == nil {
				distinct[k] = make(map[string]bool)
			}
			distinct[k][v] = true
		}
	}

	var varying []string
	for k, count := range counts {
		if count == len(samples) && len(distinct[k]) > 1 {
			varying = append(varying, k)
		}
	}
	sort.Strings(varying)
	return varying
}

// timingPatternNote looks for two common companion-parameter shapes across
// samples: a timestamp-like value that only ever increases, and a
// nonce-like value that's unique on every request. It returns a short,
// human-readable note describing whatever it finds (possibly empty).
func timingPatternNote(samples []sample) string {
	var notes []string

	if key, values, ok := collectByPattern(samples, tsKeyPattern); ok {
		if allNumeric(values) && isNondecreasing(values) {
			notes = append(notes, key+" increments across requests")
		}
	}
	if key, values, ok := collectByPattern(samples, nonceKeyPattern); ok {
		if allUnique(values) {
			notes = append(notes, key+" is unique per request")
		}
	}

	return strings.Join(notes, "; ")
}

// collectByPattern returns the per-sample value of the first parameter
// name matching pattern, provided every sample has exactly one such
// parameter; ok is false if any sample lacks a match.
func collectByPattern(samples []sample, pattern *regexp.Regexp) (key string, values []string, ok bool) {
	values = make([]string, 0, len(samples))
	for _, s := range samples {
		found := false
		for k, v := range s.params {
			if pattern.MatchString(k) {
				key = k
				values = append(values, v)
				found = true
				break
			}
		}
		if !found {
			return "", nil, false
		}
	}
	return key, values, true
}

func allNumeric(values []string) bool {
	for _, v := range values {
		if !isAllDigits(v) {
			return false
		}
	}
	return true
}

func isNondecreasing(values []string) bool {
	for i := 1; i < len(values); i++ {
		prev, errPrev := strconv.ParseInt(values[i-1], 10, 64)
		cur, errCur := strconv.ParseInt(values[i], 10, 64)
		if errPrev != nil || errCur != nil || cur < prev {
			return false
		}
	}
	return true
}

func allUnique(values []string) bool {
	seen := make(map[string]bool, len(values))
	for _, v := range values {
		if seen[v] {
			return false
		}
		seen[v] = true
	}
	return true
}

// guessInput builds a human-readable guess of what signParamName's value
// was computed from, based on which companion parameters are present
// alongside it, plus a confidence boost reflecting how many such signals
// were found (each known companion narrows down the input shape).
func guessInput(params map[string]string, signParamName string) (guess string, confidenceBoost float64) {
	var hasTs, hasNonce, hasAppKey bool
	for k := range params {
		if k == signParamName {
			continue
		}
		switch {
		case tsKeyPattern.MatchString(k):
			hasTs = true
		case nonceKeyPattern.MatchString(k):
			hasNonce = true
		case appKeyPattern.MatchString(k):
			hasAppKey = true
		}
	}

	parts := []string{"sorted_params"}
	if hasTs {
		parts = append(parts, "ts")
		confidenceBoost += 0.15
	}
	if hasNonce {
		parts = append(parts, "nonce")
		confidenceBoost += 0.15
	}
	if hasAppKey {
		parts = append(parts, "appkey")
		confidenceBoost += 0.2
	} else {
		parts = append(parts, "secret")
	}

	return strings.Join(parts, " + "), confidenceBoost
}

// detectEncoding classifies value's textual encoding. Pure-digit strings
// are reported as "numeric" even though digits are technically valid hex
// characters too -- numeric is the more specific, more informative
// classification for e.g. a decimal checksum or raw timestamp-derived
// value, and real hex-encoded hashes essentially always contain at least
// one a-f letter in practice.
func detectEncoding(value string) string {
	switch {
	case value == "":
		return "unknown"
	case isAllDigits(value):
		return "numeric"
	case isHexString(value):
		return "hex"
	case isBase64String(value):
		return "base64"
	default:
		return "unknown"
	}
}

var (
	allDigitsRe   = regexp.MustCompile(`^[0-9]+$`)
	hexRe         = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	base64CharsRe = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
)

func isAllDigits(s string) bool { return allDigitsRe.MatchString(s) }

func isHexString(s string) bool { return hexRe.MatchString(s) }

// isBase64String reports whether s is plausibly standard base64: the right
// alphabet, a length that's a multiple of 4, and it actually decodes.
// Checked after isHexString so that short all-hex-alphabet strings (which
// also happen to satisfy the base64 charset and length-%4 constraints)
// are classified as "hex" first, matching how real hash digests are
// produced (hex.EncodeToString is far more common than coincidentally
// hex-alphabet-only base64 output).
func isBase64String(s string) bool {
	if len(s) == 0 || len(s)%4 != 0 || !base64CharsRe.MatchString(s) {
		return false
	}
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

// possibleAlgorithms maps a value's length and encoding to the hash/HMAC
// algorithms that could plausibly have produced output of that shape.
// Both the plain and HMAC-keyed variant of each algorithm are listed since
// they share the same output length -- the keyed vs. unkeyed question has
// to be resolved by other means (see guessInput / TryVerify).
func possibleAlgorithms(length int, encoding string) []string {
	switch encoding {
	case "hex":
		switch length {
		case 32:
			return []string{"MD5", "HMAC-MD5"}
		case 40:
			return []string{"SHA1", "HMAC-SHA1"}
		case 64:
			return []string{"SHA256", "HMAC-SHA256"}
		case 128:
			return []string{"SHA512", "HMAC-SHA512"}
		}
	case "base64":
		switch length {
		case 24:
			return []string{"MD5", "HMAC-MD5"}
		case 28:
			return []string{"SHA1", "HMAC-SHA1"}
		case 44:
			return []string{"SHA256", "HMAC-SHA256"}
		case 88:
			return []string{"SHA512", "HMAC-SHA512"}
		}
	}
	return nil
}

// matchesAny reports whether s matches any of patterns.
func matchesAny(patterns []*regexp.Regexp, s string) bool {
	for _, p := range patterns {
		if p.MatchString(s) {
			return true
		}
	}
	return false
}

// extractAllParams gathers every parameter name/value pair a flow carries,
// from both its URL query string and its request body (parsed as JSON, or
// else as form-encoded data) -- mirroring agent.DetectSignParams's own
// param-discovery logic so the two stay consistent. Only the first value
// of a repeated query/form key is kept, which is sufficient for the
// flat key=value shape signature schemes use in practice.
func extractAllParams(flow *types.Flow) map[string]string {
	params := make(map[string]string)
	if flow == nil {
		return params
	}

	if u, err := url.Parse(flow.URL); err == nil {
		for key, vals := range u.Query() {
			if len(vals) > 0 {
				params[key] = vals[0]
			}
		}
	}

	if len(flow.ReqBody) > 0 {
		var bodyMap map[string]json.RawMessage
		if err := json.Unmarshal(flow.ReqBody, &bodyMap); err == nil {
			for key, raw := range bodyMap {
				params[key] = rawValueToString(raw)
			}
		} else if vals, err := url.ParseQuery(string(flow.ReqBody)); err == nil && len(vals) > 0 {
			for key, v := range vals {
				if len(v) > 0 {
					params[key] = v[0]
				}
			}
		}
	}

	return params
}

// rawValueToString converts one top-level JSON value into its most natural
// string form: JSON strings are unquoted; everything else (numbers, bools,
// null, nested objects/arrays) falls back to its literal JSON text.
func rawValueToString(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return strings.TrimSpace(string(raw))
}

// sortedParamsString renders params as "key=value" pairs joined with "&",
// sorted by key, excluding any parameter whose value equals excludeValue --
// this is how callers omit the sign parameter itself from the string being
// hashed without needing to know its name, only its value. It is the
// building block for both the known-pattern checks in patterns.go and the
// brute-force search in verify.go.
func sortedParamsString(params map[string]string, excludeValue string) string {
	keys := make([]string, 0, len(params))
	for k, v := range params {
		if v == excludeValue {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+params[k])
	}
	return strings.Join(parts, "&")
}

// clamp01 clamps x to the closed interval [0, 1].
func clamp01(x float64) float64 {
	switch {
	case x < 0:
		return 0
	case x > 1:
		return 1
	default:
		return x
	}
}
