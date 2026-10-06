package unpin

import (
	"path/filepath"
	"strings"
)

// AppFingerprint describes the frameworks, pinning libraries, and
// security characteristics detected in an Android app. It drives
// CodeShare search keyword generation.
type AppFingerprint struct {
	Package    string   `json:"package"`
	Frameworks []string `json:"frameworks"` // e.g. "flutter", "react-native", "xamarin"
	Pinning    []string `json:"pinning"`    // e.g. "okhttp3", "trustkit", "conscrypt"
	Security   []string `json:"security"`   // e.g. "root-detection", "frida-detection"
	Tags       []string `json:"tags"`       // combined search tags for CodeShare
}

// soFrameworkMap maps SO file basenames to framework identifiers.
var soFrameworkMap = map[string]string{
	"libflutter.so":          "flutter",
	"libapp.so":              "flutter",
	"libreactnativejni.so":   "react-native",
	"libhermes.so":           "react-native",
	"libjsc.so":              "react-native",
	"libmono.so":             "xamarin",
	"libmonodroid.so":        "xamarin",
	"libxamarin-app.so":      "xamarin",
	"libunity.so":            "unity",
	"libil2cpp.so":           "unity",
	"libcocos2dcpp.so":       "cocos2d",
	"libcordova.so":          "cordova",
	"libweexcore.so":         "weex",
	"libweexjsc.so":          "weex",
}

// classPinningMap maps class name substrings (lowercased) to pinning library tags.
var classPinningMap = map[string]string{
	"okhttp3.certificatepinner":                             "okhttp3",
	"okhttp3.internal.tls.certificatechaincleanerimpls":     "okhttp3",
	"com.datatheorem.android.trustkit":                      "trustkit",
	"com.android.org.conscrypt":                             "conscrypt",
	"org.conscrypt":                                         "conscrypt",
	"appcelerator.https.pinningtrustmanager":                "appcelerator",
	"nl.xservices.plugins.sslcertificatechecker":            "cordova-ssl",
	"io.flutter.embedding":                                  "flutter",
	"com.facebook.react":                                    "react-native",
	"org.apache.http.conn.ssl":                              "apache-http",
	"android.security.net.config.networksecurityconfig":     "network-security-config",
	"com.scottyab.rootbeer":                                 "root-detection",
	"com.noshufou.android.su":                               "root-detection",
}

// classSecurityMap maps class name substrings to security feature tags.
var classSecurityMap = map[string]string{
	"fridadetect":       "frida-detection",
	"antifrida":         "frida-detection",
	"rootbeer":          "root-detection",
	"rootdetect":        "root-detection",
	"safetynet":         "safetynet",
	"playintegrity":     "play-integrity",
	"emulatordetect":    "emulator-detection",
	"tamperdetect":      "tamper-detection",
	"integritycheck":    "integrity-check",
	"debugdetect":       "debug-detection",
	"xposeddetect":      "xposed-detection",
}

// FingerprintFromSOFiles builds framework tags from a list of SO file paths
// (as found in APK zip entries like "lib/arm64-v8a/libflutter.so").
func FingerprintFromSOFiles(soFiles []string) []string {
	seen := make(map[string]bool)
	var frameworks []string
	for _, path := range soFiles {
		base := strings.ToLower(filepath.Base(path))
		if fw, ok := soFrameworkMap[base]; ok && !seen[fw] {
			seen[fw] = true
			frameworks = append(frameworks, fw)
		}
	}
	return frameworks
}

// FingerprintFromClasses scans class/string references for pinning
// libraries and security features.
func FingerprintFromClasses(classes []string) (pinning, security []string) {
	seenPin := make(map[string]bool)
	seenSec := make(map[string]bool)

	for _, cls := range classes {
		lower := strings.ToLower(cls)
		for pattern, tag := range classPinningMap {
			if strings.Contains(lower, pattern) && !seenPin[tag] {
				seenPin[tag] = true
				pinning = append(pinning, tag)
			}
		}
		for pattern, tag := range classSecurityMap {
			if strings.Contains(lower, pattern) && !seenSec[tag] {
				seenSec[tag] = true
				security = append(security, tag)
			}
		}
	}
	return
}

// BuildFingerprint constructs an AppFingerprint from APK analysis data.
// soFiles are the in-APK paths (e.g. from trace.APKInfo.SOFiles),
// classes are class names or DEX strings that may reference pinning/security libs.
func BuildFingerprint(pkg string, soFiles, classes []string) *AppFingerprint {
	fp := &AppFingerprint{Package: pkg}
	fp.Frameworks = FingerprintFromSOFiles(soFiles)
	fp.Pinning, fp.Security = FingerprintFromClasses(classes)
	fp.Tags = buildSearchTags(fp)
	return fp
}

// buildSearchTags generates CodeShare search keywords from the fingerprint.
func buildSearchTags(fp *AppFingerprint) []string {
	var tags []string

	// Framework-specific SSL bypass tags
	for _, fw := range fp.Frameworks {
		switch fw {
		case "flutter":
			tags = append(tags, "flutter ssl pinning", "flutter bypass")
		case "react-native":
			tags = append(tags, "react native ssl", "okhttp pinning")
		case "xamarin":
			tags = append(tags, "xamarin ssl", "mono ssl pinning")
		case "unity":
			tags = append(tags, "unity ssl", "il2cpp")
		case "cordova":
			tags = append(tags, "cordova ssl", "phonegap ssl")
		default:
			tags = append(tags, fw+" ssl")
		}
	}

	// Pinning library specific tags
	for _, pin := range fp.Pinning {
		switch pin {
		case "okhttp3":
			tags = append(tags, "okhttp pinning", "certificatepinner")
		case "trustkit":
			tags = append(tags, "trustkit bypass")
		case "conscrypt":
			tags = append(tags, "conscrypt ssl")
		default:
			tags = append(tags, pin+" pinning")
		}
	}

	// Security bypass tags
	for _, sec := range fp.Security {
		switch sec {
		case "root-detection":
			tags = append(tags, "root detection bypass", "rootbeer bypass")
		case "frida-detection":
			tags = append(tags, "frida detection bypass", "anti-frida")
		case "safetynet":
			tags = append(tags, "safetynet bypass")
		case "play-integrity":
			tags = append(tags, "play integrity bypass")
		default:
			tags = append(tags, sec+" bypass")
		}
	}

	// Always include generic SSL unpinning as fallback
	if len(tags) == 0 {
		tags = append(tags, "ssl pinning bypass", "universal ssl unpinning")
	}

	return tags
}

// TopSearchQueries returns the most promising CodeShare search queries
// for this fingerprint, deduplicated and limited to n.
func (fp *AppFingerprint) TopSearchQueries(n int) []string {
	seen := make(map[string]bool)
	var queries []string
	for _, tag := range fp.Tags {
		if !seen[tag] {
			seen[tag] = true
			queries = append(queries, tag)
		}
		if len(queries) >= n {
			break
		}
	}
	return queries
}
