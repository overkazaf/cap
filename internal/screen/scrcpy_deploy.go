package screen

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	// scrcpyServerDeviceDir is the writable, world-readable directory on
	// the device cap pushes scrcpy-server.jar into and runs it from. This
	// is the same location the upstream scrcpy client uses.
	scrcpyServerDeviceDir = "/data/local/tmp"

	// scrcpyServerDeviceFile is the full on-device path to the deployed
	// jar, and the value passed as CLASSPATH when starting the server (see
	// scrcpyServerArgs in scrcpy.go).
	scrcpyServerDeviceFile = scrcpyServerDeviceDir + "/scrcpy-server.jar"

	// scrcpyServerCacheFile is the cached jar's filename inside whatever
	// cache directory is passed to DeployScrcpyServer/DownloadScrcpyServer.
	scrcpyServerCacheFile = "scrcpy-server.jar"

	// scrcpyServerDownloadURL is where DownloadScrcpyServer fetches the
	// jar from when it's not already cached locally. It must match the
	// server version the Server class is invoked with (see ScrcpyVersion
	// in scrcpy.go) — the wire protocol isn't guaranteed compatible across
	// scrcpy-server versions.
	scrcpyServerDownloadURL = "https://github.com/Genymobile/scrcpy/releases/download/v3.1/scrcpy-server-v3.1"
)

// runAdb runs `adb [-s serial] args...` and returns its combined
// stdout+stderr. It's a package-level var (rather than calling
// exec.Command directly) so tests can substitute a fake and exercise the
// parsing/control-flow logic in this file without a real adb binary or
// device attached.
var runAdb = func(serial string, args ...string) (string, error) {
	full := make([]string, 0, len(args)+2)
	if serial != "" {
		full = append(full, "-s", serial)
	}
	full = append(full, args...)

	out, err := exec.Command("adb", full...).CombinedOutput()
	return string(out), err
}

// wrapAdbErr wraps err from a runAdb call with action for context, folding
// in out (adb's combined stdout+stderr) when non-empty. err alone is
// typically just "exit status 1" — next to useless for diagnosing a real
// failure (device disconnected, out of space, permission denied, ...)
// without the actual adb output that explains it.
func wrapAdbErr(action string, out string, err error) error {
	out = strings.TrimSpace(out)
	if out == "" {
		return fmt.Errorf("%s: %w", action, err)
	}
	return fmt.Errorf("%s: %w (output: %s)", action, err, out)
}

// DefaultCacheDir returns the directory cap caches downloaded tool
// binaries in (currently just scrcpy-server.jar): ~/.cap. It does not
// create the directory; DownloadScrcpyServer does that.
func DefaultCacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("scrcpy: resolve home directory: %w", err)
	}
	return filepath.Join(home, ".cap"), nil
}

// IsScrcpyDeployed reports whether scrcpy-server.jar is already present on
// the device named by serial (empty lets adb pick its default device).
func IsScrcpyDeployed(serial string) bool {
	out, err := runAdb(serial, "shell", fmt.Sprintf("ls %s 2>/dev/null", scrcpyServerDeviceFile))
	return isDeployedOutput(out, err)
}

// isDeployedOutput parses the result of the `ls` check run by
// IsScrcpyDeployed. It's split out from IsScrcpyDeployed so the parsing
// logic can be unit tested with canned adb output, without adb or a
// device.
func isDeployedOutput(out string, err error) bool {
	if err != nil {
		return false
	}
	out = strings.TrimSpace(out)
	if out == "" {
		return false
	}
	// Defend against shells that don't honor the `2>/dev/null` redirect
	// and instead report the failure on stdout: that text must not be
	// mistaken for a path.
	if strings.Contains(out, "No such file") {
		return false
	}
	return strings.Contains(out, "scrcpy-server.jar")
}

// httpClient performs the HTTP GET in the default downloadFile
// implementation. A bounded timeout keeps a stalled connection from
// hanging Start() forever.
var httpClient = &http.Client{Timeout: 60 * time.Second}

// downloadFile fetches url and writes its body to dest. It's a
// package-level var (rather than a plain function) so tests can
// substitute a fake and exercise DownloadScrcpyServer's
// caching/plumbing logic without hitting the network.
var downloadFile = func(url, dest string) error {
	resp, err := httpClient.Get(url)
	if err != nil {
		return fmt.Errorf("scrcpy: download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("scrcpy: download %s: unexpected status %s", url, resp.Status)
	}

	// Download to a temp file and rename into place atomically, so a
	// failed/interrupted download never leaves a corrupt file at dest for
	// a later call to mistake for a good cache hit.
	tmp := dest + ".download"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("scrcpy: create %s: %w", tmp, err)
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("scrcpy: write %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("scrcpy: close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, dest); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("scrcpy: rename %s -> %s: %w", tmp, dest, err)
	}
	return nil
}

// DownloadScrcpyServer ensures scrcpy-server.jar exists in cacheDir,
// downloading it from GitHub releases if it isn't already cached, and
// returns the full path to the cached jar.
func DownloadScrcpyServer(cacheDir string) (string, error) {
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", fmt.Errorf("scrcpy: create cache dir %s: %w", cacheDir, err)
	}
	dest := filepath.Join(cacheDir, scrcpyServerCacheFile)

	if info, err := os.Stat(dest); err == nil && info.Size() > 0 {
		return dest, nil
	}

	if err := downloadFile(scrcpyServerDownloadURL, dest); err != nil {
		return "", err
	}
	return dest, nil
}

// DeployScrcpyServer ensures scrcpy-server.jar is present on the device
// named by serial (empty lets adb pick its default device), downloading
// and caching it in cacheDir first if it isn't already cached on disk. It
// is a no-op if the server is already deployed on the device.
func DeployScrcpyServer(serial string, cacheDir string) error {
	if IsScrcpyDeployed(serial) {
		return nil
	}

	jar, err := DownloadScrcpyServer(cacheDir)
	if err != nil {
		return err
	}

	if out, err := runAdb(serial, "push", jar, scrcpyServerDeviceFile); err != nil {
		return wrapAdbErr(fmt.Sprintf("scrcpy: adb push %s -> %s", jar, scrcpyServerDeviceFile), out, err)
	}
	return nil
}
