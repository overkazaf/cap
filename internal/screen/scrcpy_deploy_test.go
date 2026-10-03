package screen

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withFakeRunAdb substitutes runAdb (the seam IsScrcpyDeployed/
// DownloadScrcpyServer/DeployScrcpyServer and ScrcpyServer call through)
// for the duration of the test, restoring the original afterward.
func withFakeRunAdb(t *testing.T, fn func(serial string, args ...string) (string, error)) {
	t.Helper()
	orig := runAdb
	runAdb = fn
	t.Cleanup(func() { runAdb = orig })
}

// withFakeDownload substitutes downloadFile (the seam DownloadScrcpyServer
// calls through on a cache miss) for the duration of the test, restoring
// the original afterward.
func withFakeDownload(t *testing.T, fn func(url, dest string) error) {
	t.Helper()
	orig := downloadFile
	downloadFile = fn
	t.Cleanup(func() { downloadFile = orig })
}

// ---- isDeployedOutput (pure parsing, the core of TestIsScrcpyDeployed) ----

func TestIsDeployedOutput(t *testing.T) {
	tests := []struct {
		name string
		out  string
		err  error
		want bool
	}{
		{"clean path on stdout", "/data/local/tmp/scrcpy-server.jar\n", nil, true},
		{"path with no trailing newline", "/data/local/tmp/scrcpy-server.jar", nil, true},
		{"empty output, no error", "", nil, false},
		{"whitespace-only output", "   \n\t", nil, false},
		{"adb/shell reported an error", "", errors.New("exit status 1"), false},
		{"shell leaked a not-found message despite redirect", "ls: /data/local/tmp/scrcpy-server.jar: No such file or directory\n", nil, false},
		{"non-empty output but also an error", "/data/local/tmp/scrcpy-server.jar\n", errors.New("exit status 1"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDeployedOutput(tt.out, tt.err); got != tt.want {
				t.Errorf("isDeployedOutput(%q, %v) = %v, want %v", tt.out, tt.err, got, tt.want)
			}
		})
	}
}

func TestIsScrcpyDeployed(t *testing.T) {
	t.Run("deployed", func(t *testing.T) {
		var gotSerial string
		var gotArgs []string
		withFakeRunAdb(t, func(serial string, args ...string) (string, error) {
			gotSerial = serial
			gotArgs = args
			return "/data/local/tmp/scrcpy-server.jar\n", nil
		})

		if !IsScrcpyDeployed("dev-1") {
			t.Error("IsScrcpyDeployed() = false, want true")
		}
		if gotSerial != "dev-1" {
			t.Errorf("runAdb serial = %q, want %q", gotSerial, "dev-1")
		}
		if len(gotArgs) < 2 || gotArgs[0] != "shell" || !strings.Contains(gotArgs[1], scrcpyServerDeviceFile) {
			t.Errorf("runAdb args = %v, want a \"shell\" command referencing %s", gotArgs, scrcpyServerDeviceFile)
		}
	})

	t.Run("not deployed", func(t *testing.T) {
		withFakeRunAdb(t, func(serial string, args ...string) (string, error) {
			return "", errors.New("exit status 1")
		})
		if IsScrcpyDeployed("") {
			t.Error("IsScrcpyDeployed() = true, want false")
		}
	})
}

// ---- DefaultCacheDir ----

func TestDefaultCacheDir(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("os.UserHomeDir() unavailable: %v", err)
	}
	got, err := DefaultCacheDir()
	if err != nil {
		t.Fatalf("DefaultCacheDir() error = %v, want nil", err)
	}
	want := filepath.Join(home, ".cap")
	if got != want {
		t.Errorf("DefaultCacheDir() = %q, want %q", got, want)
	}
}

// ---- DownloadScrcpyServer ----

func TestDownloadScrcpyServer_CacheHit(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, scrcpyServerCacheFile)
	if err := os.WriteFile(dest, []byte("already-cached"), 0o644); err != nil {
		t.Fatalf("seed cache file: %v", err)
	}

	called := false
	withFakeDownload(t, func(url, dest string) error {
		called = true
		return nil
	})

	got, err := DownloadScrcpyServer(dir)
	if err != nil {
		t.Fatalf("DownloadScrcpyServer() error = %v, want nil", err)
	}
	if got != dest {
		t.Errorf("DownloadScrcpyServer() = %q, want %q", got, dest)
	}
	if called {
		t.Error("downloadFile was called on a cache hit; want it skipped")
	}
}

func TestDownloadScrcpyServer_CacheMiss(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, scrcpyServerCacheFile)

	var gotURL, gotDest string
	withFakeDownload(t, func(url, dest string) error {
		gotURL, gotDest = url, dest
		return os.WriteFile(dest, []byte("downloaded-bytes"), 0o644)
	})

	got, err := DownloadScrcpyServer(dir)
	if err != nil {
		t.Fatalf("DownloadScrcpyServer() error = %v, want nil", err)
	}
	if got != dest {
		t.Errorf("DownloadScrcpyServer() = %q, want %q", got, dest)
	}
	if gotURL != scrcpyServerDownloadURL {
		t.Errorf("downloadFile url = %q, want %q", gotURL, scrcpyServerDownloadURL)
	}
	if gotDest != dest {
		t.Errorf("downloadFile dest = %q, want %q", gotDest, dest)
	}
	data, err := os.ReadFile(dest)
	if err != nil || string(data) != "downloaded-bytes" {
		t.Errorf("cached file content = %q, %v, want %q, nil", data, err, "downloaded-bytes")
	}
}

func TestDownloadScrcpyServer_TreatsEmptyFileAsNotCached(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, scrcpyServerCacheFile)
	if err := os.WriteFile(dest, nil, 0o644); err != nil { // zero-byte file: e.g. a previous crash mid-download
		t.Fatalf("seed empty cache file: %v", err)
	}

	called := false
	withFakeDownload(t, func(url, dest string) error {
		called = true
		return os.WriteFile(dest, []byte("re-downloaded"), 0o644)
	})

	if _, err := DownloadScrcpyServer(dir); err != nil {
		t.Fatalf("DownloadScrcpyServer() error = %v, want nil", err)
	}
	if !called {
		t.Error("downloadFile was not called for an empty cached file; want a re-download")
	}
}

func TestDownloadScrcpyServer_PropagatesDownloadError(t *testing.T) {
	dir := t.TempDir()
	wantErr := errors.New("network exploded")
	withFakeDownload(t, func(url, dest string) error {
		return wantErr
	})

	_, err := DownloadScrcpyServer(dir)
	if !errors.Is(err, wantErr) {
		t.Fatalf("DownloadScrcpyServer() error = %v, want wrapping %v", err, wantErr)
	}
}

// TestDownloadFile_SavesBodyToDest exercises the real downloadFile
// implementation (not a fake) against a local httptest server, so the
// actual HTTP-fetch-and-write-to-disk code path gets coverage without
// depending on GitHub or the network.
func TestDownloadFile_SavesBodyToDest(t *testing.T) {
	const body = "fake scrcpy-server jar bytes"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "out.jar")
	if err := downloadFile(srv.URL, dest); err != nil {
		t.Fatalf("downloadFile() error = %v, want nil", err)
	}

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if string(got) != body {
		t.Errorf("downloaded content = %q, want %q", got, body)
	}
	// The temp-file-then-rename strategy shouldn't leave the intermediate
	// file behind on success.
	if _, err := os.Stat(dest + ".download"); !os.IsNotExist(err) {
		t.Errorf("leftover temp file %s.download, stat err = %v", dest, err)
	}
}

func TestDownloadFile_PropagatesHTTPErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "out.jar")
	if err := downloadFile(srv.URL, dest); err == nil {
		t.Fatal("downloadFile() with a 404 response: want error, got nil")
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Errorf("downloadFile() left a file behind on HTTP error: stat err = %v", err)
	}
}

// ---- DeployScrcpyServer ----

func TestDeployScrcpyServer_AlreadyDeployed(t *testing.T) {
	downloadCalled := false
	withFakeDownload(t, func(url, dest string) error {
		downloadCalled = true
		return nil
	})
	withFakeRunAdb(t, func(serial string, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "push" {
			t.Fatalf("runAdb called with push, want no push when already deployed; args=%v", args)
		}
		return "/data/local/tmp/scrcpy-server.jar\n", nil // the `ls` check succeeds
	})

	if err := DeployScrcpyServer("dev-1", t.TempDir()); err != nil {
		t.Fatalf("DeployScrcpyServer() error = %v, want nil", err)
	}
	if downloadCalled {
		t.Error("DownloadScrcpyServer path was hit even though the device already has the server")
	}
}

func TestDeployScrcpyServer_DeploysWhenMissing(t *testing.T) {
	dir := t.TempDir()
	withFakeDownload(t, func(url, dest string) error {
		return os.WriteFile(dest, []byte("jar-bytes"), 0o644)
	})

	var pushArgs []string
	var pushSerial string
	withFakeRunAdb(t, func(serial string, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "push" {
			pushSerial = serial
			pushArgs = args
			return "", nil
		}
		return "", errors.New("exit status 1") // the `ls` check: not deployed yet
	})

	if err := DeployScrcpyServer("dev-1", dir); err != nil {
		t.Fatalf("DeployScrcpyServer() error = %v, want nil", err)
	}
	if pushSerial != "dev-1" {
		t.Errorf("adb push serial = %q, want %q", pushSerial, "dev-1")
	}
	wantJar := filepath.Join(dir, scrcpyServerCacheFile)
	if len(pushArgs) != 3 || pushArgs[1] != wantJar || pushArgs[2] != scrcpyServerDeviceFile {
		t.Errorf("adb push args = %v, want [push %s %s]", pushArgs, wantJar, scrcpyServerDeviceFile)
	}
}

func TestDeployScrcpyServer_PropagatesDownloadError(t *testing.T) {
	wantErr := errors.New("network exploded")
	withFakeDownload(t, func(url, dest string) error {
		return wantErr
	})
	pushCalled := false
	withFakeRunAdb(t, func(serial string, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "push" {
			pushCalled = true
		}
		return "", errors.New("exit status 1")
	})

	err := DeployScrcpyServer("", t.TempDir())
	if !errors.Is(err, wantErr) {
		t.Fatalf("DeployScrcpyServer() error = %v, want wrapping %v", err, wantErr)
	}
	if pushCalled {
		t.Error("adb push was attempted despite a download failure")
	}
}

func TestDeployScrcpyServer_PropagatesPushError(t *testing.T) {
	dir := t.TempDir()
	withFakeDownload(t, func(url, dest string) error {
		return os.WriteFile(dest, []byte("jar-bytes"), 0o644)
	})
	wantErr := errors.New("device offline")
	withFakeRunAdb(t, func(serial string, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "push" {
			return "", wantErr
		}
		return "", errors.New("exit status 1")
	})

	err := DeployScrcpyServer("", dir)
	if !errors.Is(err, wantErr) {
		t.Fatalf("DeployScrcpyServer() error = %v, want wrapping %v", err, wantErr)
	}
}

// Sanity check that the download URL constant actually looks like a v3.1
// scrcpy-server release asset, since nothing else in the test suite
// touches the real GitHub URL.
func TestScrcpyServerDownloadURL(t *testing.T) {
	want := "https://github.com/Genymobile/scrcpy/releases/download/v3.1/scrcpy-server-v3.1"
	if scrcpyServerDownloadURL != want {
		t.Errorf("scrcpyServerDownloadURL = %q, want %q", scrcpyServerDownloadURL, want)
	}
}
