package sign_test

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"

	"github.com/overkazaf/cap/internal/sign"
	"github.com/overkazaf/cap/internal/types"
)

// newFlow builds a minimal GET flow whose URL query string carries params.
// Using net/url to assemble the query string (rather than hand-built
// concatenation) ensures values needing escaping -- e.g. base64 signatures
// containing '+', '/' or '=' -- round-trip correctly.
func newFlow(host string, params map[string]string) *types.Flow {
	u := url.URL{Scheme: "https", Host: host, Path: "/api"}
	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return &types.Flow{
		Method: "GET",
		URL:    u.String(),
		Host:   host,
	}
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func findKnownPattern(t *testing.T, name string) sign.Pattern {
	t.Helper()
	for _, p := range sign.KnownPatterns {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("no KnownPatterns entry named %q", name)
	return sign.Pattern{}
}

func TestAnalyzeSingleMD5(t *testing.T) {
	// A realistic "MD5 of sorted params" signature, modeled on the common
	// Chinese-app-API convention: sign = MD5("appid=..&t2=..&ver=..").
	input := "appid=3116&t2=1790937633&ver=11180"
	sum := md5.Sum([]byte(input))
	signValue := hex.EncodeToString(sum[:])

	flow := newFlow("api.example.com", map[string]string{
		"appid": "3116",
		"t2":    "1790937633",
		"ver":   "11180",
		"sign":  signValue,
	})

	analyses := sign.AnalyzeSingle(flow)
	if len(analyses) != 1 {
		t.Fatalf("AnalyzeSingle returned %d analyses, want 1: %+v", len(analyses), analyses)
	}

	a := analyses[0]
	if a.ParamName != "sign" {
		t.Errorf("ParamName = %q, want %q", a.ParamName, "sign")
	}
	if a.Value != signValue {
		t.Errorf("Value = %q, want %q", a.Value, signValue)
	}
	if a.Length != 32 {
		t.Errorf("Length = %d, want 32", a.Length)
	}
	if a.Encoding != "hex" {
		t.Errorf("Encoding = %q, want %q", a.Encoding, "hex")
	}
	if !containsString(a.PossibleAlgs, "MD5") {
		t.Errorf("PossibleAlgs = %v, want it to contain %q", a.PossibleAlgs, "MD5")
	}
	if a.Confidence <= 0 {
		t.Errorf("Confidence = %v, want > 0", a.Confidence)
	}
}

func TestAnalyzeSingleSHA256(t *testing.T) {
	sum := sha256.Sum256([]byte("unit-test-sha256-fixture"))
	signValue := hex.EncodeToString(sum[:])

	flow := newFlow("api.example.com", map[string]string{
		"appid": "9001",
		"sign":  signValue,
	})

	analyses := sign.AnalyzeSingle(flow)
	if len(analyses) != 1 {
		t.Fatalf("AnalyzeSingle returned %d analyses, want 1: %+v", len(analyses), analyses)
	}

	a := analyses[0]
	if a.Length != 64 {
		t.Errorf("Length = %d, want 64", a.Length)
	}
	if a.Encoding != "hex" {
		t.Errorf("Encoding = %q, want %q", a.Encoding, "hex")
	}
	if !containsString(a.PossibleAlgs, "SHA256") {
		t.Errorf("PossibleAlgs = %v, want it to contain %q", a.PossibleAlgs, "SHA256")
	}
	if a.Confidence <= 0 {
		t.Errorf("Confidence = %v, want > 0", a.Confidence)
	}
}

func TestEncodingDetection(t *testing.T) {
	md5Sum := md5.Sum([]byte("encoding-detection-hex-fixture"))
	hexValue := hex.EncodeToString(md5Sum[:])

	sha256Sum := sha256.Sum256([]byte("encoding-detection-base64-fixture"))
	base64Value := base64.StdEncoding.EncodeToString(sha256Sum[:])

	numericValue := "48102936574810293657"

	cases := []struct {
		name         string
		value        string
		wantEncoding string
	}{
		{"hex", hexValue, "hex"},
		{"base64", base64Value, "base64"},
		{"numeric", numericValue, "numeric"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flow := newFlow("api.example.com", map[string]string{
				"sign": tc.value,
			})

			analyses := sign.AnalyzeSingle(flow)
			if len(analyses) != 1 {
				t.Fatalf("AnalyzeSingle returned %d analyses, want 1: %+v", len(analyses), analyses)
			}
			if analyses[0].Encoding != tc.wantEncoding {
				t.Errorf("Encoding = %q, want %q (value=%q)", analyses[0].Encoding, tc.wantEncoding, tc.value)
			}
		})
	}
}

func TestAnalyzeMultipleFlows(t *testing.T) {
	// Each flow's sign is deliberately NOT a real MD5(sorted_params) match --
	// this test is about cross-flow heuristics (length consistency, and
	// companion params that vary in lockstep with the sign), not pattern
	// confirmation (that's TestCheckMD5Sorted's job).
	mkFlow := func(ts, nonce string) *types.Flow {
		h := md5.Sum([]byte("flow-signature-" + ts + "-" + nonce))
		signValue := hex.EncodeToString(h[:])
		return newFlow("api.example.com", map[string]string{
			"appid": "3116",
			"t2":    ts,
			"nonce": nonce,
			"sign":  signValue,
		})
	}

	flows := []*types.Flow{
		mkFlow("1790937633", "n1"),
		mkFlow("1790937634", "n2"),
		mkFlow("1790937635", "n3"),
	}

	results := sign.AnalyzeSign(flows)
	if len(results) != 1 {
		t.Fatalf("AnalyzeSign returned %d results, want 1: %+v", len(results), results)
	}

	r := results[0]
	if r.ParamName != "sign" {
		t.Fatalf("ParamName = %q, want %q", r.ParamName, "sign")
	}

	single := sign.AnalyzeSingle(flows[0])
	if len(single) != 1 {
		t.Fatalf("sanity check: AnalyzeSingle(flows[0]) returned %d analyses, want 1", len(single))
	}

	if r.Confidence <= single[0].Confidence {
		t.Errorf("multi-flow Confidence = %v, want > single-flow Confidence %v (consistent length across flows should raise confidence)", r.Confidence, single[0].Confidence)
	}
	if r.Confidence > 1.0 {
		t.Errorf("Confidence = %v, want <= 1.0", r.Confidence)
	}

	if !strings.Contains(r.InputGuess, "t2") && !strings.Contains(r.InputGuess, "nonce") {
		t.Errorf("InputGuess = %q, want it to call out a companion param that varies with the sign (t2/nonce)", r.InputGuess)
	}
}

func TestCheckMD5Sorted(t *testing.T) {
	input := "appid=3116&t2=1790937633&ver=11180"
	sum := md5.Sum([]byte(input))
	signValue := hex.EncodeToString(sum[:])

	flow := newFlow("api.example.com", map[string]string{
		"appid": "3116",
		"t2":    "1790937633",
		"ver":   "11180",
		"sign":  signValue,
	})

	pattern := findKnownPattern(t, "MD5(sorted_params)")
	if pattern.Check == nil {
		t.Fatal("MD5(sorted_params) pattern has a nil Check function")
	}
	if !pattern.Check(flow, signValue) {
		t.Errorf("Check(flow, %q) = false, want true for a genuine MD5(sorted_params) signature", signValue)
	}
	if pattern.Check(flow, "0000000000000000000000000000000") {
		t.Errorf("Check(flow, bogus value) = true, want false")
	}

	// The same detection should surface through the higher-level
	// AnalyzeSingle API: a confirmed pattern match should drive both the
	// InputGuess and a high Confidence.
	analyses := sign.AnalyzeSingle(flow)
	if len(analyses) != 1 {
		t.Fatalf("AnalyzeSingle returned %d analyses, want 1", len(analyses))
	}
	if analyses[0].InputGuess != "MD5(sorted_params)" {
		t.Errorf("InputGuess = %q, want %q", analyses[0].InputGuess, "MD5(sorted_params)")
	}
	if analyses[0].Confidence < 0.9 {
		t.Errorf("Confidence = %v, want >= 0.9 for a confirmed pattern match", analyses[0].Confidence)
	}
}

func TestTryVerify(t *testing.T) {
	t.Run("NoSecret", func(t *testing.T) {
		input := "appid=3116&t2=1790937633&ver=11180"
		sum := md5.Sum([]byte(input))
		signValue := hex.EncodeToString(sum[:])

		flow := newFlow("api.example.com", map[string]string{
			"appid": "3116",
			"t2":    "1790937633",
			"ver":   "11180",
			"sign":  signValue,
		})

		result := sign.TryVerify(flow, "sign")
		if result == nil || !result.Verified {
			t.Fatalf("TryVerify did not crack a plain MD5(sorted_params) signature: %+v", result)
		}
		if result.Algorithm != "MD5" {
			t.Errorf("Algorithm = %q, want %q", result.Algorithm, "MD5")
		}
		if result.Input != input {
			t.Errorf("Input = %q, want %q", result.Input, input)
		}
		if result.Secret != "" {
			t.Errorf("Secret = %q, want empty (no secret needed)", result.Secret)
		}
	})

	t.Run("WithSecretSuffix", func(t *testing.T) {
		base := "appid=3116&t2=1790937633"
		sum := md5.Sum([]byte(base + "key"))
		signValue := hex.EncodeToString(sum[:])

		flow := newFlow("api.example.com", map[string]string{
			"appid": "3116",
			"t2":    "1790937633",
			"sign":  signValue,
		})

		result := sign.TryVerify(flow, "sign")
		if result == nil || !result.Verified {
			t.Fatalf("TryVerify did not crack MD5(sorted_params+secret): %+v", result)
		}
		if result.Secret != "key" {
			t.Errorf("Secret = %q, want %q", result.Secret, "key")
		}
	})

	t.Run("HMACWithAppKey", func(t *testing.T) {
		base := "appkey=abc123secretkey&t2=1790937633"
		mac := hmac.New(sha256.New, []byte("abc123secretkey"))
		mac.Write([]byte(base))
		signValue := hex.EncodeToString(mac.Sum(nil))

		flow := newFlow("api.example.com", map[string]string{
			"appkey": "abc123secretkey",
			"t2":     "1790937633",
			"sign":   signValue,
		})

		result := sign.TryVerify(flow, "sign")
		if result == nil || !result.Verified {
			t.Fatalf("TryVerify did not crack HMAC-SHA256 keyed by appkey: %+v", result)
		}
		if result.Algorithm != "HMAC-SHA256" {
			t.Errorf("Algorithm = %q, want %q", result.Algorithm, "HMAC-SHA256")
		}
		if result.Secret != "abc123secretkey" {
			t.Errorf("Secret = %q, want %q", result.Secret, "abc123secretkey")
		}
	})

	t.Run("NoMatch", func(t *testing.T) {
		flow := newFlow("api.example.com", map[string]string{
			"appid": "3116",
			"sign":  "ffffffffffffffffffffffffffffffff",
		})

		result := sign.TryVerify(flow, "sign")
		if result == nil {
			t.Fatal("TryVerify returned nil, want a non-nil VerifyResult with Verified == false")
		}
		if result.Verified {
			t.Errorf("Verified = true, want false for an unguessable signature: %+v", result)
		}
	})
}
