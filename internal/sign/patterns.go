package sign

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"strings"

	"github.com/overkazaf/cap/internal/types"
)

// Pattern describes one known (or hypothesized) signature-generation
// recipe: the output length and text encoding it produces, and optionally
// a verifier that can confirm whether a given flow's value was actually
// produced that way.
type Pattern struct {
	Name     string
	Length   int
	Encoding string
	// Check, when non-nil, recomputes the signature from flow's other
	// parameters and reports whether it reproduces signValue exactly.
	Check func(flow *types.Flow, signValue string) bool
}

// KnownPatterns enumerates the signature recipes this package recognizes,
// starting with the ones it can positively confirm (non-nil Check) and
// followed by length/encoding-only guesses that merely narrow down
// PossibleAlgs (see possibleAlgorithms). "MD5(sorted_params)" in particular
// -- no secret, no glue beyond "&" -- is a surprisingly common convention
// across Chinese app APIs.
var KnownPatterns = []Pattern{
	{Name: "MD5(sorted_params)", Length: 32, Encoding: "hex", Check: checkMD5Sorted},
	{Name: "SHA1(sorted_params)", Length: 40, Encoding: "hex", Check: checkSHA1Sorted},
	{Name: "SHA256(sorted_params)", Length: 64, Encoding: "hex", Check: checkSHA256Sorted},

	{Name: "MD5", Length: 32, Encoding: "hex", Check: nil},
	{Name: "HMAC-MD5", Length: 32, Encoding: "hex", Check: nil},
	{Name: "SHA1", Length: 40, Encoding: "hex", Check: nil},
	{Name: "SHA1(params+secret)", Length: 40, Encoding: "hex", Check: nil},
	{Name: "HMAC-SHA1", Length: 40, Encoding: "hex", Check: nil},
	{Name: "SHA256", Length: 64, Encoding: "hex", Check: nil},
	{Name: "HMAC-SHA256", Length: 64, Encoding: "hex", Check: nil},
	{Name: "SHA512", Length: 128, Encoding: "hex", Check: nil},
	{Name: "HMAC-SHA512", Length: 128, Encoding: "hex", Check: nil},

	{Name: "MD5(base64)", Length: 24, Encoding: "base64", Check: nil},
	{Name: "SHA1(base64)", Length: 28, Encoding: "base64", Check: nil},
	{Name: "SHA256(base64)", Length: 44, Encoding: "base64", Check: nil},
	{Name: "SHA512(base64)", Length: 88, Encoding: "base64", Check: nil},
}

// checkMD5Sorted reports whether signValue equals MD5 of flow's other
// parameters rendered as sorted "key=value" pairs joined by "&" (the sign
// parameter itself is excluded by value, not by name, since Check isn't
// told which key held signValue).
func checkMD5Sorted(flow *types.Flow, signValue string) bool {
	return checkSortedHash(flow, signValue, md5Hex)
}

func checkSHA1Sorted(flow *types.Flow, signValue string) bool {
	return checkSortedHash(flow, signValue, sha1Hex)
}

func checkSHA256Sorted(flow *types.Flow, signValue string) bool {
	return checkSortedHash(flow, signValue, sha256Hex)
}

func checkSortedHash(flow *types.Flow, signValue string, hashFn func(string) string) bool {
	if flow == nil || signValue == "" {
		return false
	}
	params := extractAllParams(flow)
	input := sortedParamsString(params, signValue)
	return strings.EqualFold(hashFn(input), signValue)
}

// confirmedPattern returns the first KnownPatterns entry whose Check
// positively confirms value against flow, restricted to patterns whose
// declared Length/Encoding match value's -- or nil if none apply/match.
func confirmedPattern(flow *types.Flow, value string) *Pattern {
	length := len(value)
	encoding := detectEncoding(value)
	for i := range KnownPatterns {
		p := &KnownPatterns[i]
		if p.Check == nil || p.Length != length || p.Encoding != encoding {
			continue
		}
		if p.Check(flow, value) {
			return p
		}
	}
	return nil
}

// --- shared hash/HMAC helpers (also used by verify.go) ---

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func sha1Hex(s string) string {
	sum := sha1.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func sha512Hex(s string) string {
	sum := sha512.Sum512([]byte(s))
	return hex.EncodeToString(sum[:])
}

func hmacHex(newHash func() hash.Hash, key, msg string) string {
	mac := hmac.New(newHash, []byte(key))
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

func hmacMD5Hex(key, msg string) string    { return hmacHex(md5.New, key, msg) }
func hmacSHA1Hex(key, msg string) string   { return hmacHex(sha1.New, key, msg) }
func hmacSHA256Hex(key, msg string) string { return hmacHex(sha256.New, key, msg) }
func hmacSHA512Hex(key, msg string) string { return hmacHex(sha512.New, key, msg) }
