package tlskit

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
)

type tlsProfileDef struct {
	id                string
	name              string
	description       string
	platform          string
	minVersion        uint16
	maxVersion        uint16
	tls13CipherSuites []uint16
	cipherSuites      []uint16
	curvePreferences  []tls.CurveID
	alpn              []string
	extensions        []uint16 // modeled TLS ClientHello extension IDs for deterministic JA3 summary
	pointFormats      []uint8
	headerOrder       []string
	defaultHeaders    map[string]string
	notes             []string
}

var curatedProfiles = []tlsProfileDef{
	{
		id:          "go_default",
		name:        "Go Default (crypto/tls)",
		description: "Standard Go net/http TLS 1.2/1.3 client configuration with HTTP/2 support.",
		platform:    "generic",
		minVersion:  tls.VersionTLS12,
		maxVersion:  tls.VersionTLS13,
		tls13CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		cipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		curvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
		alpn:             []string{"h2", "http/1.1"},
		extensions:       []uint16{0, 5, 10, 11, 13, 16, 18, 23, 43, 45, 51, 65281},
		pointFormats:     []uint8{0},
		headerOrder:      []string{"Host", "User-Agent", "Accept-Encoding"},
		defaultHeaders: map[string]string{
			"User-Agent":      "Go-http-client/2.0",
			"Accept-Encoding": "gzip",
		},
	},
	{
		id:          "chrome_131",
		name:        "Chrome 131 (Desktop)",
		description: "Chromium 131 BoringSSL-aligned TLS 1.2/1.3 suite order, X25519/P-256/P-384 curves, ALPN h2, and Chrome client-hint header profile.",
		platform:    "desktop",
		minVersion:  tls.VersionTLS12,
		maxVersion:  tls.VersionTLS13,
		tls13CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		cipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		curvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
		alpn:             []string{"h2", "http/1.1"},
		extensions:       []uint16{0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513},
		pointFormats:     []uint8{0},
		headerOrder: []string{
			"Host",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
			"Upgrade-Insecure-Requests",
			"User-Agent",
			"Accept",
			"Sec-Fetch-Site",
			"Sec-Fetch-Mode",
			"Sec-Fetch-User",
			"Sec-Fetch-Dest",
			"Accept-Encoding",
			"Accept-Language",
		},
		defaultHeaders: map[string]string{
			"sec-ch-ua":                 `"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"macOS"`,
			"Upgrade-Insecure-Requests": "1",
			"User-Agent":                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
		},
		notes: []string{"Go stdlib crypto/tls does not emit GREASE values; use curl-impersonate when full wire-level Chrome ClientHello parity is needed."},
	},
	{
		id:          "safari_17",
		name:        "Safari 17 (macOS / WebKit)",
		description: "Apple Security/BoringSSL-aligned Safari 17 profile prioritizing ECDSA AES-256/128-GCM and ChaCha20 with X25519/P-256/P-384/P-521 curves.",
		platform:    "desktop",
		minVersion:  tls.VersionTLS12,
		maxVersion:  tls.VersionTLS13,
		tls13CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		cipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		curvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521},
		alpn:             []string{"h2", "http/1.1"},
		extensions:       []uint16{0, 23, 65281, 10, 11, 16, 5, 13, 18, 51, 45, 43, 27},
		pointFormats:     []uint8{0},
		headerOrder: []string{
			"Host",
			"Accept",
			"Sec-Fetch-Site",
			"Sec-Fetch-Mode",
			"User-Agent",
			"Accept-Language",
			"Sec-Fetch-Dest",
			"Accept-Encoding",
		},
		defaultHeaders: map[string]string{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Sec-Fetch-Site":  "none",
			"Sec-Fetch-Mode":  "navigate",
			"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
			"Accept-Language": "en-US,en;q=0.9",
			"Sec-Fetch-Dest":  "document",
			"Accept-Encoding": "gzip, deflate, br",
		},
	},
	{
		id:          "firefox_132",
		name:        "Firefox 132 (NSS)",
		description: "Mozilla NSS-aligned Firefox 132 profile preferring AES-128-GCM and ChaCha20 before AES-256-GCM with X25519/P-256/P-384/P-521 curves.",
		platform:    "desktop",
		minVersion:  tls.VersionTLS12,
		maxVersion:  tls.VersionTLS13,
		tls13CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
		},
		cipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
		curvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521},
		alpn:             []string{"h2", "http/1.1"},
		extensions:       []uint16{0, 23, 65281, 10, 11, 35, 16, 5, 34, 51, 43, 13, 45, 28, 21},
		pointFormats:     []uint8{0},
		headerOrder: []string{
			"Host",
			"User-Agent",
			"Accept",
			"Accept-Language",
			"Accept-Encoding",
			"Upgrade-Insecure-Requests",
			"Sec-Fetch-Dest",
			"Sec-Fetch-Mode",
			"Sec-Fetch-Site",
			"Sec-Fetch-User",
			"TE",
		},
		defaultHeaders: map[string]string{
			"User-Agent":                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language":           "en-US,en;q=0.5",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Upgrade-Insecure-Requests": "1",
			"Sec-Fetch-Dest":            "document",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-User":            "?1",
			"TE":                        "trailers",
		},
	},
	{
		id:          "okhttp_android",
		name:        "OkHttp 4 (Android / Conscrypt)",
		description: "Android Conscrypt/OkHttp 4 MODERN_TLS profile with TLS 1.2/1.3, X25519/P-256/P-384 curves, ALPN h2/http/1.1, and minimal mobile headers.",
		platform:    "android",
		minVersion:  tls.VersionTLS12,
		maxVersion:  tls.VersionTLS13,
		tls13CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		cipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		curvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
		alpn:             []string{"h2", "http/1.1"},
		extensions:       []uint16{0, 23, 65281, 10, 11, 35, 16, 5, 13, 51, 45, 43},
		pointFormats:     []uint8{0},
		headerOrder:      []string{"Host", "Connection", "Accept-Encoding", "User-Agent"},
		defaultHeaders: map[string]string{
			"Connection":      "Keep-Alive",
			"Accept-Encoding": "gzip",
			"User-Agent":      "okhttp/4.12.0",
		},
	},
	{
		id:          "ios_cfnetwork",
		name:        "iOS CFNetwork (URLSession)",
		description: "Apple iOS NSURLSession / CFNetwork TLS 1.2/1.3 profile with ECDSA-first AEAD order, X25519/P-256/P-384 curves, and native iOS headers.",
		platform:    "ios",
		minVersion:  tls.VersionTLS12,
		maxVersion:  tls.VersionTLS13,
		tls13CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		cipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		curvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
		alpn:             []string{"h2", "http/1.1"},
		extensions:       []uint16{0, 23, 65281, 10, 11, 16, 5, 13, 51, 45, 43, 27},
		pointFormats:     []uint8{0},
		headerOrder:      []string{"Host", "Accept", "User-Agent", "Accept-Language", "Accept-Encoding", "Connection"},
		defaultHeaders: map[string]string{
			"Accept":          "*/*",
			"User-Agent":      "CFNetwork/1498.700.2 Darwin/23.6.0",
			"Accept-Language": "en-US,en;q=0.9",
			"Accept-Encoding": "gzip, deflate, br",
			"Connection":      "keep-alive",
		},
	},
}

// ListTLSProfiles returns deep copies of all 6 curated TLS / HTTP2 client
// profiles in canonical order.
func ListTLSProfiles() []TLSProfileSpec {
	out := make([]TLSProfileSpec, 0, len(curatedProfiles))
	for i := range curatedProfiles {
		out = append(out, toTLSProfileSpec(&curatedProfiles[i]))
	}
	return out
}

// GetTLSProfile looks up a curated TLS profile by ID (empty defaults to
// "go_default"). Returns a deep copy.
func GetTLSProfile(profileID string) (*TLSProfileSpec, error) {
	def, err := lookupProfileDef(profileID)
	if err != nil {
		return nil, err
	}
	spec := toTLSProfileSpec(def)
	return &spec, nil
}

// BuildTLSConfig builds a configured *tls.Config matching the selected curated
// profile. If certPath and keyPath are provided, the PEM client certificate and
// key pair are validated and attached for mutual TLS (mTLS).
func BuildTLSConfig(profileID string, insecureSkipVerify bool, certPath, keyPath string) (*tls.Config, error) {
	def, err := lookupProfileDef(profileID)
	if err != nil {
		return nil, err
	}

	cfg := &tls.Config{
		MinVersion:         def.minVersion,
		MaxVersion:         def.maxVersion,
		CipherSuites:       slices.Clone(def.cipherSuites),
		CurvePreferences:   slices.Clone(def.curvePreferences),
		NextProtos:         slices.Clone(def.alpn),
		InsecureSkipVerify: insecureSkipVerify, //nolint:gosec // explicit caller opt-in for local proxy/self-signed targets
	}

	certPath = strings.TrimSpace(certPath)
	keyPath = strings.TrimSpace(keyPath)
	if certPath != "" || keyPath != "" {
		res, cert, valErr := validateAndLoadMTLSKeyPair(certPath, keyPath)
		if valErr != nil {
			return nil, valErr
		}
		if res.Expired {
			return nil, fmt.Errorf("tlskit: mTLS client certificate %q is expired", certPath)
		}
		if res.NotYetValid {
			return nil, fmt.Errorf("tlskit: mTLS client certificate %q is not yet valid", certPath)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	return cfg, nil
}

// ComputeProfileJA3Summary computes a deterministic JA3-formatted string and
// lowercase hex MD5 digest summarizing the profile's TLS ClientHello
// parameters. An empty profileID defaults to "go_default". Returns nil for an
// unknown profile ID.
func ComputeProfileJA3Summary(profileID string) *JA3Summary {
	def, err := lookupProfileDef(profileID)
	if err != nil {
		return nil
	}
	return computeJA3ForDef(def)
}

func computeJA3ForDef(def *tlsProfileDef) *JA3Summary {
	// RFC 8446: TLS 1.3 ClientHello still carries legacy_version 0x0303 (771).
	clientHelloVersion := def.minVersion
	if clientHelloVersion == 0 {
		clientHelloVersion = tls.VersionTLS12
	}

	allCiphers := make([]uint16, 0, len(def.tls13CipherSuites)+len(def.cipherSuites))
	allCiphers = append(allCiphers, def.tls13CipherSuites...)
	allCiphers = append(allCiphers, def.cipherSuites...)

	curves := make([]uint16, 0, len(def.curvePreferences))
	for _, c := range def.curvePreferences {
		curves = append(curves, uint16(c))
	}

	pointFormats := make([]uint16, 0, len(def.pointFormats))
	for _, pf := range def.pointFormats {
		pointFormats = append(pointFormats, uint16(pf))
	}

	ja3Str := strings.Join([]string{
		strconv.Itoa(int(clientHelloVersion)),
		joinUint16Dash(allCiphers),
		joinUint16Dash(def.extensions),
		joinUint16Dash(curves),
		joinUint16Dash(pointFormats),
	}, ",")

	sum := md5.Sum([]byte(ja3Str))
	return &JA3Summary{
		ProfileID:   def.id,
		JA3String:   ja3Str,
		JA3Hash:     hex.EncodeToString(sum[:]),
		TLSVersion:  clientHelloVersion,
		CipherCount: len(allCiphers),
		CurveCount:  len(curves),
	}
}

func lookupProfileDef(profileID string) (*tlsProfileDef, error) {
	id := strings.ToLower(strings.TrimSpace(profileID))
	if id == "" {
		id = "go_default"
	}
	for i := range curatedProfiles {
		if curatedProfiles[i].id == id {
			return &curatedProfiles[i], nil
		}
	}
	ids := make([]string, 0, len(curatedProfiles))
	for i := range curatedProfiles {
		ids = append(ids, curatedProfiles[i].id)
	}
	return nil, fmt.Errorf("tlskit: unknown TLS profile %q (available: %s)", profileID, strings.Join(ids, ", "))
}

func toTLSProfileSpec(def *tlsProfileDef) TLSProfileSpec {
	cipherNames := make([]string, 0, len(def.cipherSuites))
	for _, id := range def.cipherSuites {
		cipherNames = append(cipherNames, tls.CipherSuiteName(id))
	}
	curveNames := make([]string, 0, len(def.curvePreferences))
	for _, c := range def.curvePreferences {
		curveNames = append(curveNames, curveName(c))
	}
	return TLSProfileSpec{
		ID:                def.id,
		Name:              def.name,
		Description:       def.description,
		Platform:          def.platform,
		MinVersion:        def.minVersion,
		MaxVersion:        def.maxVersion,
		MinVersionName:    tlsVersionName(def.minVersion),
		MaxVersionName:    tlsVersionName(def.maxVersion),
		CipherSuites:      slices.Clone(def.cipherSuites),
		CipherSuiteNames:  cipherNames,
		TLS13CipherSuites: slices.Clone(def.tls13CipherSuites),
		CurvePreferences:  slices.Clone(def.curvePreferences),
		CurveNames:        curveNames,
		ALPN:              slices.Clone(def.alpn),
		HeaderOrder:       slices.Clone(def.headerOrder),
		DefaultHeaders:    maps.Clone(def.defaultHeaders),
		JA3:               computeJA3ForDef(def),
		Notes:             slices.Clone(def.notes),
	}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func curveName(c tls.CurveID) string {
	switch c {
	case tls.X25519:
		return "X25519"
	case tls.CurveP256:
		return "P256"
	case tls.CurveP384:
		return "P384"
	case tls.CurveP521:
		return "P521"
	default:
		return c.String()
	}
}

func joinUint16Dash(vals []uint16) string {
	if len(vals) == 0 {
		return ""
	}
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, "-")
}

// --- Host curl-impersonate probing ---

var curlImpersonatePatterns = []string{
	"curl_chrome*",
	"curl_safari*",
	"curl_ff*",
	"curl-impersonate-chrome",
	"curl-impersonate-ff",
	"curl-impersonate",
}

// DetectCurlImpersonate probes the host PATH for optional curl-impersonate
// binaries (curl_chrome*, curl_safari*, curl_ff*, curl-impersonate-chrome,
// curl-impersonate-ff, curl-impersonate).
func DetectCurlImpersonate() CurlImpersonateInfo {
	dirs := filepath.SplitList(os.Getenv("PATH"))
	info := detectCurlImpersonateInDirs(dirs)
	// Also consult exec.LookPath for canonical names in case the platform
	// resolves extra standard locations.
	seen := make(map[string]bool, len(info.Binaries))
	for _, b := range info.Binaries {
		seen[b.Name] = true
	}
	for _, name := range []string{"curl-impersonate-chrome", "curl-impersonate-ff", "curl-impersonate"} {
		if seen[name] {
			continue
		}
		if p, err := exec.LookPath(name); err == nil && p != "" {
			seen[name] = true
			info.Binaries = append(info.Binaries, CurlImpersonateBinary{
				Name:   name,
				Path:   p,
				Family: classifyCurlImpersonateFamily(name),
			})
		}
	}
	finalizeCurlImpersonateInfo(&info)
	return info
}

func detectCurlImpersonateInDirs(dirs []string) CurlImpersonateInfo {
	info := CurlImpersonateInfo{
		Binaries:         []CurlImpersonateBinary{},
		SearchedPatterns: slices.Clone(curlImpersonatePatterns),
	}
	seenName := make(map[string]bool)

	for _, dir := range dirs {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, ent := range entries {
			name := ent.Name()
			if !matchesCurlImpersonateName(name) {
				continue
			}
			fullPath := filepath.Join(dir, name)
			if !isExecutableFile(fullPath) {
				continue
			}
			key := strings.ToLower(name)
			if seenName[key] {
				continue
			}
			seenName[key] = true
			info.Binaries = append(info.Binaries, CurlImpersonateBinary{
				Name:   name,
				Path:   fullPath,
				Family: classifyCurlImpersonateFamily(name),
			})
		}
	}

	finalizeCurlImpersonateInfo(&info)
	return info
}

func finalizeCurlImpersonateInfo(info *CurlImpersonateInfo) {
	sort.Slice(info.Binaries, func(i, j int) bool {
		return info.Binaries[i].Name < info.Binaries[j].Name
	})
	if len(info.Binaries) > 0 {
		info.Available = true
		info.PrimaryBinary = info.Binaries[0].Path
		// Prefer curl_chrome* or curl-impersonate-chrome as primary if present.
		for _, b := range info.Binaries {
			if b.Family == "chrome" {
				info.PrimaryBinary = b.Path
				break
			}
		}
		info.InstallHint = ""
	} else {
		info.Available = false
		info.PrimaryBinary = ""
		info.InstallHint = "Install optional curl-impersonate binaries (e.g. curl_chrome131, curl_safari17, curl_ff132) onto PATH for wire-level browser TLS fingerprint parity."
	}
}

func matchesCurlImpersonateName(name string) bool {
	low := strings.ToLower(name)
	low = strings.TrimSuffix(low, ".exe")
	low = strings.TrimSuffix(low, ".bat")
	low = strings.TrimSuffix(low, ".cmd")
	switch {
	case low == "curl-impersonate",
		low == "curl-impersonate-chrome",
		low == "curl-impersonate-ff",
		strings.HasPrefix(low, "curl_chrome"),
		strings.HasPrefix(low, "curl_safari"),
		strings.HasPrefix(low, "curl_ff"),
		strings.HasPrefix(low, "curl_edge"):
		return true
	default:
		return false
	}
}

func classifyCurlImpersonateFamily(name string) string {
	low := strings.ToLower(name)
	switch {
	case strings.Contains(low, "chrome"):
		return "chrome"
	case strings.Contains(low, "safari"):
		return "safari"
	case strings.Contains(low, "ff") || strings.Contains(low, "firefox"):
		return "firefox"
	case strings.Contains(low, "edge"):
		return "edge"
	default:
		return "generic"
	}
}

func isExecutableFile(p string) bool {
	st, err := os.Stat(p)
	if err != nil || st.IsDir() {
		return false
	}
	if runtime.GOOS == "windows" {
		ext := strings.ToLower(filepath.Ext(p))
		return ext == ".exe" || ext == ".bat" || ext == ".cmd"
	}
	return st.Mode()&0o111 != 0
}
