package trace

import (
	"context"
	"os/exec"
	"sync"
	"time"
)

// ToolsStatus reports the availability, resolved path, and version of the
// external CLI tools DeepTrace can leverage (adb, jadx, radare2). Pure-Go
// APK/Manifest/DEX analysis works even when jadx and r2 are absent.
type ToolsStatus struct {
	ADB         bool   `json:"adb"`
	ADBPath     string `json:"adb_path,omitempty"`
	ADBVersion  string `json:"adb_version,omitempty"`
	Jadx        bool   `json:"jadx"`
	JadxPath    string `json:"jadx_path,omitempty"`
	JadxVersion string `json:"jadx_version,omitempty"`
	R2          bool   `json:"r2"`
	R2Path      string `json:"r2_path,omitempty"`
	R2Version   string `json:"r2_version,omitempty"`
}

// CheckTools probes adb, jadx, and r2 in parallel and returns their
// availability, resolved paths, and version banners.
func CheckTools(opts Options) ToolsStatus {
	return CheckToolsContext(context.Background(), opts)
}

// CheckToolsContext probes adb, jadx, and r2 in parallel respecting ctx.
func CheckToolsContext(ctx context.Context, opts Options) ToolsStatus {
	adbBin := opts.ADBPath
	if adbBin == "" {
		adbBin = "adb"
	}
	jadxBin := opts.JadxPath
	if jadxBin == "" {
		jadxBin = "jadx"
	}
	r2Bin := opts.R2Path
	if r2Bin == "" {
		r2Bin = "r2"
	}

	var status ToolsStatus
	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		resolved := resolveToolPath(adbBin)
		if ver, ok := toolVersionContext(ctx, resolved, defaultToolCheckTimeout, "version"); ok {
			status.ADB = true
			status.ADBPath = resolved
			status.ADBVersion = ver
		}
	}()

	go func() {
		defer wg.Done()
		resolved := resolveToolPath(jadxBin)
		if ver, ok := toolVersionContext(ctx, resolved, defaultToolCheckTimeout, "--version"); ok {
			status.Jadx = true
			status.JadxPath = resolved
			status.JadxVersion = ver
		}
	}()

	go func() {
		defer wg.Done()
		resolved := resolveToolPath(r2Bin)
		if ver, ok := toolVersionContext(ctx, resolved, defaultToolCheckTimeout, "-v"); ok {
			status.R2 = true
			status.R2Path = resolved
			status.R2Version = ver
		}
	}()

	wg.Wait()
	return status
}

func resolveToolPath(bin string) string {
	if bin == "" {
		return ""
	}
	if p, err := exec.LookPath(bin); err == nil {
		return p
	}
	return bin
}

func toolVersionContext(parent context.Context, path string, timeout time.Duration, args ...string) (string, bool) {
	if path == "" {
		return "", false
	}
	if timeout <= 0 {
		timeout = defaultToolCheckTimeout
	}
	if parent == nil {
		parent = context.Background()
	}

	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, path, args...)
	boundCommandWait(cmd, timeout)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", false
	}
	return firstLine(stringsTrimSpace(string(out))), true
}

func stringsTrimSpace(s string) string {
	// Tiny helper avoiding extra imports if needed; delegates cleanly.
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\t' || s[start] == '\r' || s[start] == '\n') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\r' || s[end-1] == '\n') {
		end--
	}
	return s[start:end]
}
