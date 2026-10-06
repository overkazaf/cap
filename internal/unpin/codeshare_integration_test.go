package unpin

import (
	"os"
	"strings"
	"testing"
)

// Integration tests against live codeshare.frida.re.
// Run with: go test -run Integration -v

func skipIfNoNetwork(t *testing.T) {
	if os.Getenv("CAP_SKIP_NETWORK") != "" {
		t.Skip("CAP_SKIP_NETWORK set, skipping network tests")
	}
}

func TestIntegrationSearch(t *testing.T) {
	skipIfNoNetwork(t)

	client := NewCodeShareClient()
	results, err := client.Search("ssl pinning")
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected results for 'ssl pinning', got 0")
	}

	t.Logf("Found %d results for 'ssl pinning'", len(results))
	for i, r := range results {
		if i >= 3 {
			break
		}
		t.Logf("  [%d] %s (slug=%s, author=%s)", i+1, r.Title, r.Slug, r.Author)

		// Validate structure
		if r.Slug == "" {
			t.Errorf("result %d has empty slug", i)
		}
		if !strings.HasPrefix(r.Slug, "/@") {
			t.Errorf("result %d slug %q doesn't start with /@", i, r.Slug)
		}
		if r.URL == "" {
			t.Errorf("result %d has empty URL", i)
		}
	}
}

func TestIntegrationSearchEmpty(t *testing.T) {
	skipIfNoNetwork(t)

	client := NewCodeShareClient()
	results, err := client.Search("xyznonexistent12345abcdef")
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results for nonsense query, got %d", len(results))
	}
}

func TestIntegrationBrowse(t *testing.T) {
	skipIfNoNetwork(t)

	client := NewCodeShareClient()
	results, err := client.Browse(1)
	if err != nil {
		t.Fatalf("Browse failed: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected entries on browse page 1, got 0")
	}

	t.Logf("Browse page 1: %d entries", len(results))
	for i, r := range results {
		if i >= 3 {
			break
		}
		t.Logf("  [%d] %s (likes=%s, views=%s)", i+1, r.Title, r.Likes, r.Views)
	}
}

func TestIntegrationFetchScript(t *testing.T) {
	skipIfNoNetwork(t)

	// First search to find a real slug
	client := NewCodeShareClient()
	results, err := client.Search("ssl pinning")
	if err != nil || len(results) == 0 {
		t.Skip("no search results to fetch")
	}

	slug := results[0].Slug
	t.Logf("Fetching script: %s", slug)

	script, err := client.FetchScript(slug)
	if err != nil {
		t.Fatalf("FetchScript(%s) failed: %v", slug, err)
	}

	if script.Source == "" {
		t.Error("fetched script has empty source")
	} else {
		lines := strings.Count(script.Source, "\n") + 1
		t.Logf("Script source: %d lines, title=%q", lines, script.Title)

		// Should look like JavaScript
		src := script.Source
		looksLikeJS := strings.Contains(src, "function") ||
			strings.Contains(src, "var ") ||
			strings.Contains(src, "const ") ||
			strings.Contains(src, "Java.perform") ||
			strings.Contains(src, "Interceptor") ||
			strings.Contains(src, "console.log")
		if !looksLikeJS {
			t.Logf("WARNING: source doesn't look like JS (first 200 chars): %s", truncateStr(src, 200))
		}
	}
}

func TestIntegrationDownloadScript(t *testing.T) {
	skipIfNoNetwork(t)

	client := NewCodeShareClient()
	results, err := client.Search("ssl pinning")
	if err != nil || len(results) == 0 {
		t.Skip("no search results to download")
	}

	slug := results[0].Slug
	dir := t.TempDir()

	path, err := DownloadScript(slug, dir)
	if err != nil {
		t.Fatalf("DownloadScript failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("downloaded file not found: %v", err)
	}
	if info.Size() == 0 {
		t.Error("downloaded file is empty")
	}
	t.Logf("Downloaded to %s (%d bytes)", path, info.Size())

	// Verify content
	data, _ := os.ReadFile(path)
	if len(data) == 0 {
		t.Error("file content is empty")
	}
}

func TestIntegrationSearchForApp(t *testing.T) {
	skipIfNoNetwork(t)

	fp := BuildFingerprint("com.test.app",
		[]string{"lib/arm64-v8a/libflutter.so"},
		[]string{"okhttp3.CertificatePinner"},
	)

	t.Logf("Fingerprint: frameworks=%v, pinning=%v, tags=%v",
		fp.Frameworks, fp.Pinning, fp.Tags)

	results, err := SearchForApp(fp)
	if err != nil {
		t.Fatalf("SearchForApp failed: %v", err)
	}

	t.Logf("SearchForApp returned %d deduplicated results", len(results))
	for i, r := range results {
		if i >= 5 {
			break
		}
		t.Logf("  [%d] %s (%s)", i+1, r.Title, r.Slug)
	}

	// Should find at least something for flutter+okhttp
	if len(results) == 0 {
		t.Log("WARNING: 0 results for flutter+okhttp fingerprint — CodeShare may be down or have changed")
	}
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
