package sign

import (
	"strings"

	"github.com/overkazaf/cap/internal/types"
)

// VerifyResult is the outcome of TryVerify's brute-force search for the
// recipe that produced one sign parameter's value.
type VerifyResult struct {
	Algorithm string `json:"algorithm"` // e.g. "MD5", "HMAC-SHA256"
	Input     string `json:"input"`     // the exact string that was hashed
	Secret    string `json:"secret"`    // the secret/key guess that worked, if one was needed
	Verified  bool   `json:"verified"`  // true only if a candidate recipe reproduced the value
}

// plainHashCandidates are tried, in order, against every unkeyed input
// TryVerify builds.
var plainHashCandidates = []struct {
	algorithm string
	hash      func(string) string
}{
	{"MD5", md5Hex},
	{"SHA1", sha1Hex},
	{"SHA256", sha256Hex},
	{"SHA512", sha512Hex},
}

// hmacHashCandidates are tried, in order, against every (key, message) pair
// TryVerify builds once it has a candidate key.
var hmacHashCandidates = []struct {
	algorithm string
	hash      func(key, msg string) string
}{
	{"HMAC-MD5", hmacMD5Hex},
	{"HMAC-SHA1", hmacSHA1Hex},
	{"HMAC-SHA256", hmacSHA256Hex},
	{"HMAC-SHA512", hmacSHA512Hex},
}

// commonSecrets lists the literal secret/suffix guesses TryVerify tries,
// roughly in the order real-world APIs seem to favor.
var commonSecrets = []string{"key", "secret", "appkey", "secretkey", "apikey", "password"}

// TryVerify attempts to reverse-engineer how flow's paramName value was
// generated, by brute-forcing a short, well-known list of recipes, cheapest
// and most common first:
//
//  1. hash(sorted_params) with no secret at all
//  2. hash(sorted_params <+/prefix/glued-with-key=> commonSecret), for a
//     handful of common literal secret guesses plus one derived from the
//     request host
//  3. HMAC variants keyed by an appkey/app_key or token param, if the flow
//     has one (trying every such param found, in case more than one is
//     present)
//
// It returns as soon as the first recipe reproduces the observed value.
// The result is never nil -- when nothing matches, Verified is simply
// false -- so callers don't need a nil check before reading its fields.
func TryVerify(flow *types.Flow, paramName string) *VerifyResult {
	result := &VerifyResult{}
	if flow == nil || paramName == "" {
		return result
	}

	params := extractAllParams(flow)
	signValue, ok := params[paramName]
	if !ok || signValue == "" {
		return result
	}

	baseInput := sortedParamsString(params, signValue)

	if r := tryPlainHashes(baseInput, signValue); r != nil {
		return r
	}

	for _, secret := range secretGuesses(flow) {
		candidates := []string{
			baseInput + secret,
			secret + baseInput,
			baseInput + "&key=" + secret,
			baseInput + "&secret=" + secret,
		}
		for _, input := range candidates {
			if r := tryPlainHashes(input, signValue); r != nil {
				r.Secret = secret
				return r
			}
		}
	}

	for _, key := range hmacKeyCandidates(params) {
		for _, c := range hmacHashCandidates {
			if strings.EqualFold(c.hash(key, baseInput), signValue) {
				return &VerifyResult{Algorithm: c.algorithm, Input: baseInput, Secret: key, Verified: true}
			}
		}
	}

	return result
}

// tryPlainHashes hashes input with every algorithm in plainHashCandidates
// and returns a Verified result for the first one matching signValue, or
// nil if none do.
func tryPlainHashes(input, signValue string) *VerifyResult {
	for _, c := range plainHashCandidates {
		if strings.EqualFold(c.hash(input), signValue) {
			return &VerifyResult{Algorithm: c.algorithm, Input: input, Verified: true}
		}
	}
	return nil
}

// secretGuesses returns the literal secret values TryVerify tries: a
// handful of common ones, plus the first label of the request host (e.g.
// "api" from "api.example.com", after stripping a leading "www."/"api."),
// since real APIs occasionally reuse a recognizable name as their sign
// secret.
func secretGuesses(flow *types.Flow) []string {
	guesses := append([]string(nil), commonSecrets...)
	if flow.Host != "" {
		host := strings.TrimPrefix(strings.TrimPrefix(flow.Host, "www."), "api.")
		if parts := strings.Split(host, "."); len(parts) > 0 && parts[0] != "" {
			guesses = append(guesses, parts[0])
		}
	}
	return guesses
}

// hmacKeyCandidates returns the values of every parameter that looks like
// an app key or token -- the usual places a real HMAC secret shows up
// in-band, in practice.
func hmacKeyCandidates(params map[string]string) []string {
	var keys []string
	for k, v := range params {
		if v == "" {
			continue
		}
		if appKeyPattern.MatchString(k) || tokenKeyPattern.MatchString(k) {
			keys = append(keys, v)
		}
	}
	return keys
}
