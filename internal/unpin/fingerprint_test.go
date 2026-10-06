package unpin

import (
	"testing"
)

func TestFingerprintFromSOFiles(t *testing.T) {
	tests := []struct {
		name    string
		soFiles []string
		want    []string
	}{
		{
			name:    "flutter app",
			soFiles: []string{"lib/arm64-v8a/libflutter.so", "lib/arm64-v8a/libapp.so"},
			want:    []string{"flutter"},
		},
		{
			name:    "react native app",
			soFiles: []string{"lib/arm64-v8a/libreactnativejni.so", "lib/arm64-v8a/libhermes.so"},
			want:    []string{"react-native"},
		},
		{
			name:    "xamarin app",
			soFiles: []string{"lib/arm64-v8a/libmono.so", "lib/arm64-v8a/libxamarin-app.so"},
			want:    []string{"xamarin"},
		},
		{
			name:    "unity app",
			soFiles: []string{"lib/arm64-v8a/libunity.so", "lib/arm64-v8a/libil2cpp.so"},
			want:    []string{"unity"},
		},
		{
			name:    "native app no framework",
			soFiles: []string{"lib/arm64-v8a/libnative.so"},
			want:    nil,
		},
		{
			name:    "empty",
			soFiles: nil,
			want:    nil,
		},
		{
			name:    "case insensitive paths",
			soFiles: []string{"lib/arm64-v8a/libFlutter.so"},
			want:    []string{"flutter"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FingerprintFromSOFiles(tt.soFiles)
			if len(got) != len(tt.want) {
				t.Errorf("FingerprintFromSOFiles() = %v, want %v", got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("FingerprintFromSOFiles()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestFingerprintFromClasses(t *testing.T) {
	classes := []string{
		"okhttp3.CertificatePinner",
		"com.datatheorem.android.trustkit.TrustKit",
		"com.scottyab.rootbeer.RootBeer",
		"com.example.FridaDetector",
	}

	pinning, security := FingerprintFromClasses(classes)

	assertContains(t, pinning, "okhttp3", "pinning")
	assertContains(t, pinning, "trustkit", "pinning")
	assertContains(t, security, "root-detection", "security")
	assertContains(t, security, "frida-detection", "security")
}

func TestFingerprintFromClassesEmpty(t *testing.T) {
	pinning, security := FingerprintFromClasses(nil)
	if len(pinning) != 0 || len(security) != 0 {
		t.Errorf("expected empty results, got pinning=%v security=%v", pinning, security)
	}
}

func TestBuildFingerprint(t *testing.T) {
	fp := BuildFingerprint("com.example.app",
		[]string{"lib/arm64-v8a/libflutter.so"},
		[]string{"okhttp3.CertificatePinner"},
	)

	if fp.Package != "com.example.app" {
		t.Errorf("Package = %q", fp.Package)
	}
	assertContains(t, fp.Frameworks, "flutter", "frameworks")
	assertContains(t, fp.Pinning, "okhttp3", "pinning")
	if len(fp.Tags) == 0 {
		t.Error("expected non-empty Tags")
	}
}

func TestBuildFingerprintFallbackTags(t *testing.T) {
	fp := BuildFingerprint("com.example.app", nil, nil)
	if len(fp.Tags) == 0 {
		t.Error("expected fallback tags for unknown app")
	}
	assertContains(t, fp.Tags, "ssl pinning bypass", "fallback tags")
}

func TestTopSearchQueries(t *testing.T) {
	fp := BuildFingerprint("com.test",
		[]string{"lib/arm64-v8a/libflutter.so"},
		[]string{"okhttp3.CertificatePinner", "com.scottyab.rootbeer.RootBeer"},
	)

	queries := fp.TopSearchQueries(3)
	if len(queries) > 3 {
		t.Errorf("TopSearchQueries(3) returned %d queries", len(queries))
	}
	if len(queries) == 0 {
		t.Error("expected at least one query")
	}
	// Should not have duplicates
	seen := make(map[string]bool)
	for _, q := range queries {
		if seen[q] {
			t.Errorf("duplicate query: %q", q)
		}
		seen[q] = true
	}
}

func assertContains(t *testing.T, slice []string, item, label string) {
	t.Helper()
	for _, s := range slice {
		if s == item {
			return
		}
	}
	t.Errorf("%s %v does not contain %q", label, slice, item)
}
