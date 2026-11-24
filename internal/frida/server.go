package frida

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/overkazaf/cap/internal/android"
	"github.com/overkazaf/cap/internal/config"
)

const (
	githubLatestReleaseURL = "https://api.github.com/repos/frida/frida/releases/latest"
	githubDownloadBaseURL  = "https://github.com/frida/frida/releases/download"
)

var safeRemoteNameRe = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// MapABIToFridaArch translates Android `ro.product.cpu.abi` to Frida's release arch token.
func MapABIToFridaArch(abi string) string {
	switch strings.ToLower(strings.TrimSpace(abi)) {
	case "arm64-v8a", "arm64", "aarch64":
		return "arm64"
	case "armeabi-v7a", "armeabi", "arm":
		return "arm"
	case "x86_64", "amd64":
		return "x86_64"
	case "x86", "i386", "i686":
		return "x86"
	default:
		return ""
	}
}

// SanitizeRemoteName validates and normalizes a device binary name (e.g. "frida-server" or stealth "hluda-srv").
func SanitizeRemoteName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return DefaultRemoteName, nil
	}
	name = filepath.Base(name)
	if !safeRemoteNameRe.MatchString(name) || name == "." || name == ".." {
		return "", fmt.Errorf("invalid remote binary name %q (allowed: a-z, A-Z, 0-9, ., _, -)", name)
	}
	return name, nil
}

// CheckServer probes an Android device in a single batched ADB shell roundtrip
// for ABI, root access, installed frida-server binaries, running PID/version,
// and port forwarding status.
func CheckServer(serial string, port int, hostVersion string) (*ServerStatus, error) {
	if port <= 0 || port > 65535 {
		port = DefaultPort
	}
	resolved, err := android.GetDeviceSerial(serial)
	if err != nil {
		return &ServerStatus{
			Serial:       serial,
			Connected:    false,
			Port:         port,
			HostVersion:  hostVersion,
			VersionMatch: VersionMatchUnknown,
			Error:        err.Error(),
		}, nil
	}

	probeScript := strings.Join([]string{
		`echo "ABI=$(getprop ro.product.cpu.abi)"`,
		`echo "ROOT=$(su -c id 2>/dev/null || true)"`,
		`echo "PS_START"`,
		`ps -A -o PID,NAME,ARGS 2>/dev/null | grep -E "frida|hluda|florida" | grep -v grep || ps 2>/dev/null | grep -E "frida|hluda|florida" | grep -v grep || true`,
		`echo "PS_END"`,
		`echo "BINS_START"`,
		`ls -1 /data/local/tmp/frida-server* /data/local/tmp/hluda* /data/local/tmp/cap-frida* 2>/dev/null || true`,
		`echo "BINS_END"`,
		fmt.Sprintf(`echo "PORT_CHECK=$(ss -tlnp 2>/dev/null | grep ':%d ' || netstat -tlnp 2>/dev/null | grep ':%d ' || true)"`, port, port),
	}, "; ")

	out, shellErr := android.AdbShell(resolved, probeScript)
	if shellErr != nil && strings.TrimSpace(out) == "" {
		return nil, fmt.Errorf("probe device %s: %w", resolved, shellErr)
	}

	st := parseServerProbeOutput(resolved, out, port, hostVersion)

	// Probe binary version if we found a binary on device
	if st.BinaryPath != "" {
		verOut, _ := android.AdbShell(resolved, fmt.Sprintf("%s --version 2>/dev/null || true", shellSingleQuote(st.BinaryPath)))
		if v := extractVersionString(verOut); v != "" {
			st.ServerVersion = v
		}
	}

	// Check adb forward --list for port
	fwdOut, _ := android.AdbCmd(resolved, "forward", "--list")
	if strings.Contains(fwdOut, fmt.Sprintf("tcp:%d", port)) {
		st.Forwarded = true
		st.RemoteEndpoint = fmt.Sprintf("127.0.0.1:%d", port)
	}

	st.VersionMatch = CompareVersions(hostVersion, st.ServerVersion)
	return st, nil
}

func parseServerProbeOutput(serial, out string, port int, hostVersion string) *ServerStatus {
	st := &ServerStatus{
		Serial:       serial,
		Connected:    true,
		Port:         port,
		HostVersion:  hostVersion,
		VersionMatch: VersionMatchUnknown,
	}

	section := ""
	for _, rawLine := range strings.Split(out, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "ABI="):
			st.DeviceABI = strings.TrimSpace(strings.TrimPrefix(line, "ABI="))
			st.FridaArch = MapABIToFridaArch(st.DeviceABI)
		case strings.HasPrefix(line, "ROOT="):
			st.Rooted = strings.Contains(line, "uid=0")
		case line == "PS_START":
			section = "ps"
		case line == "PS_END":
			section = ""
		case line == "BINS_START":
			section = "bins"
		case line == "BINS_END":
			section = ""
		case strings.HasPrefix(line, "PORT_CHECK="):
			val := strings.TrimSpace(strings.TrimPrefix(line, "PORT_CHECK="))
			if val != "" && !st.Running {
				// A server (possibly custom-named) is listening on the target port
				st.Running = true
				st.ListenAddr = fmt.Sprintf("127.0.0.1:%d", port)
			}
		case section == "ps":
			if strings.Contains(line, "grep") || strings.Contains(line, "sh -c") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 && !st.Running {
				// `ps -A -o PID,NAME,ARGS` has PID at [0]; legacy `ps` has USER at [0], PID at [1]
				pidIdx := 0
				if _, err := strconv.Atoi(fields[0]); err != nil && len(fields) >= 2 {
					pidIdx = 1
				}
				if _, err := strconv.Atoi(fields[pidIdx]); err == nil {
					st.Running = true
					st.PID = fields[pidIdx]
					if pidIdx+1 < len(fields) {
						st.ProcessName = fields[pidIdx+1]
					}
					// Extract listen address if `-l host:port` was passed
					for i := 0; i < len(fields)-1; i++ {
						if fields[i] == "-l" || fields[i] == "--listen" {
							st.ListenAddr = fields[i+1]
							if idx := strings.LastIndex(st.ListenAddr, ":"); idx >= 0 {
								if p, pErr := strconv.Atoi(st.ListenAddr[idx+1:]); pErr == nil && p > 0 {
									st.Port = p
								}
							}
						}
					}
				}
			}
		case section == "bins":
			if strings.Contains(line, "No such") || !strings.HasPrefix(line, "/") {
				continue
			}
			st.AllBinaries = append(st.AllBinaries, line)
		}
	}

	if len(st.AllBinaries) > 0 {
		// Prefer exact /data/local/tmp/frida-server, otherwise first discovered binary
		chosen := st.AllBinaries[0]
		for _, b := range st.AllBinaries {
			if filepath.Base(b) == DefaultRemoteName {
				chosen = b
				break
			}
		}
		st.BinaryPath = chosen
		st.BinaryName = filepath.Base(chosen)
	}
	if st.Running && st.ListenAddr == "" {
		st.ListenAddr = fmt.Sprintf("127.0.0.1:%d", st.Port)
	}
	return st
}

// StartServer launches frida-server on a rooted Android device with optional
// custom port and adb forward setup.
func StartServer(opts StartServerOptions) (*ServerStatus, error) {
	resolved, err := android.GetDeviceSerial(opts.Serial)
	if err != nil {
		return nil, err
	}
	port := opts.Port
	if port <= 0 || port > 65535 {
		port = DefaultPort
	}
	listenHost := strings.TrimSpace(opts.ListenHost)
	if listenHost == "" {
		listenHost = "0.0.0.0"
	}

	binPath := strings.TrimSpace(opts.BinaryPath)
	if binPath == "" {
		st, _ := CheckServer(resolved, port, opts.HostVersion)
		if st != nil && st.BinaryPath != "" {
			binPath = st.BinaryPath
		} else {
			binPath = DefaultRemoteDir + "/" + DefaultRemoteName
		}
	}

	// Verify binary exists on device
	checkOut, _ := android.AdbShell(resolved, fmt.Sprintf("test -f %s && echo OK", shellSingleQuote(binPath)))
	if !strings.Contains(checkOut, "OK") {
		return nil, fmt.Errorf("frida-server binary not found on device at %s — deploy it first", binPath)
	}

	// Ensure executable permission & launch detached as root
	listenArg := ""
	if port != DefaultPort || listenHost != "127.0.0.1" {
		listenArg = fmt.Sprintf(" -l %s:%d", listenHost, port)
	}
	cmd := fmt.Sprintf("chmod 755 %s && nohup %s%s -D </dev/null >/dev/null 2>&1 &",
		shellSingleQuote(binPath), shellSingleQuote(binPath), listenArg)

	if _, err := android.SuShell(resolved, cmd); err != nil {
		return nil, fmt.Errorf("start frida-server via su: %w", err)
	}

	if opts.ForwardPort || port != DefaultPort {
		_, _ = android.AdbCmd(resolved, "forward", fmt.Sprintf("tcp:%d", port), fmt.Sprintf("tcp:%d", port))
	}

	// Wait briefly for daemon startup
	time.Sleep(600 * time.Millisecond)
	return CheckServer(resolved, port, opts.HostVersion)
}

// StopServer terminates any running frida-server (or stealth-renamed server) on device.
func StopServer(serial, binaryName string, port int, hostVersion string) (*ServerStatus, error) {
	resolved, err := android.GetDeviceSerial(serial)
	if err != nil {
		return nil, err
	}
	if port <= 0 || port > 65535 {
		port = DefaultPort
	}

	names := []string{"frida-server"}
	if clean, err := SanitizeRemoteName(binaryName); err == nil && clean != "" && clean != "frida-server" {
		names = append(names, clean)
	}

	var killCmds []string
	for _, n := range names {
		q := shellSingleQuote(n)
		killCmds = append(killCmds, fmt.Sprintf("pkill -9 -f %s 2>/dev/null || killall -9 %s 2>/dev/null || true", q, q))
	}
	// Also catch any process with frida-server in cmdline
	killCmds = append(killCmds, `for p in $(pidof frida-server 2>/dev/null); do kill -9 $p 2>/dev/null || true; done`)
	_, _ = android.SuShell(resolved, strings.Join(killCmds, "; "))

	// Clean up port forwarding for non-default or forwarded port
	_, _ = android.AdbCmd(resolved, "forward", "--remove", fmt.Sprintf("tcp:%d", port))

	time.Sleep(300 * time.Millisecond)
	return CheckServer(resolved, port, hostVersion)
}

// DeployServer pushes a local frida-server binary (raw or .xz) or downloads the
// matching GitHub Release for the device's CPU ABI, installs it to /data/local/tmp,
// sets permissions, and optionally starts it.
func DeployServer(ctx context.Context, opts DeployOptions) (*DeployResult, error) {
	emit := func(stage, detail string, pct int) {
		if opts.OnProgress != nil {
			opts.OnProgress(DeployProgressEvent{
				Serial:  opts.Serial,
				Stage:   stage,
				Detail:  detail,
				Percent: pct,
			})
		}
	}

	resolved, err := android.GetDeviceSerial(opts.Serial)
	if err != nil {
		emit("error", err.Error(), 0)
		return nil, err
	}
	opts.Serial = resolved

	remoteName, err := SanitizeRemoteName(opts.RemoteName)
	if err != nil {
		emit("error", err.Error(), 0)
		return nil, err
	}
	remoteDir := strings.TrimSpace(opts.RemoteDir)
	if remoteDir == "" {
		remoteDir = DefaultRemoteDir
	}
	remotePath := strings.TrimRight(remoteDir, "/") + "/" + remoteName

	port := opts.Port
	if port <= 0 || port > 65535 {
		port = DefaultPort
	}

	emit("resolve", fmt.Sprintf("Probing device %s architecture...", resolved), 10)
	arch := strings.TrimSpace(opts.Arch)
	if arch == "" {
		abiOut, abiErr := android.AdbShell(resolved, "getprop ro.product.cpu.abi")
		if abiErr != nil {
			emit("error", "failed to detect device ABI: "+abiErr.Error(), 10)
			return nil, fmt.Errorf("detect device ABI: %w", abiErr)
		}
		arch = MapABIToFridaArch(abiOut)
		if arch == "" {
			err := fmt.Errorf("unsupported Android CPU ABI: %q", strings.TrimSpace(abiOut))
			emit("error", err.Error(), 10)
			return nil, err
		}
	}

	cacheDir := opts.CacheDir
	if cacheDir == "" {
		cacheDir = filepath.Join(config.DefaultDir(), "frida-cache")
	}
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("create frida cache dir: %w", err)
	}

	var localBinary string
	var version string
	fromCache := false

	if strings.TrimSpace(opts.LocalBinaryPath) != "" {
		src := strings.TrimSpace(opts.LocalBinaryPath)
		if _, statErr := os.Stat(src); statErr != nil {
			emit("error", statErr.Error(), 15)
			return nil, fmt.Errorf("local binary not found: %w", statErr)
		}
		version = extractVersionString(filepath.Base(src))
		if strings.HasSuffix(strings.ToLower(src), ".xz") {
			emit("extract", "Decompressing local .xz archive...", 45)
			dst := filepath.Join(cacheDir, strings.TrimSuffix(filepath.Base(src), ".xz"))
			if err := decompressXZFile(ctx, src, dst); err != nil {
				emit("error", err.Error(), 45)
				return nil, err
			}
			localBinary = dst
		} else {
			localBinary = src
		}
	} else {
		version = extractVersionString(opts.Version)
		if version == "" {
			emit("resolve", "Fetching latest Frida release version from GitHub...", 18)
			latest, relErr := FetchLatestFridaVersion(ctx)
			if relErr != nil {
				emit("error", relErr.Error(), 18)
				return nil, relErr
			}
			version = latest
		}

		cachedBin := filepath.Join(cacheDir, fmt.Sprintf("frida-server-%s-android-%s", version, arch))
		if fi, statErr := os.Stat(cachedBin); statErr == nil && fi.Size() > 1024*1024 {
			localBinary = cachedBin
			fromCache = true
			emit("download", fmt.Sprintf("Using cached frida-server %s (%s)", version, arch), 65)
		} else {
			xzPath := cachedBin + ".xz"
			dlURL := fmt.Sprintf("%s/%s/frida-server-%s-android-%s.xz", githubDownloadBaseURL, version, version, arch)
			emit("download", fmt.Sprintf("Downloading frida-server %s (%s)...", version, arch), 25)
			if err := downloadFileWithProgress(ctx, dlURL, xzPath, func(pct int) {
				mapped := 25 + (pct*35)/100
				emit("download", fmt.Sprintf("Downloading frida-server %s (%s)... %d%%", version, arch, pct), mapped)
			}); err != nil {
				emit("error", err.Error(), 25)
				return nil, err
			}
			emit("extract", "Decompressing frida-server .xz archive...", 65)
			if err := decompressXZFile(ctx, xzPath, cachedBin); err != nil {
				_ = os.Remove(xzPath)
				emit("error", err.Error(), 65)
				return nil, err
			}
			_ = os.Remove(xzPath)
			localBinary = cachedBin
		}
	}

	// Stop existing running instance with same name before overwriting binary
	emit("push", fmt.Sprintf("Pushing binary to %s...", remotePath), 75)
	_, _ = android.SuShell(resolved, fmt.Sprintf("pkill -9 -f %s 2>/dev/null || true", shellSingleQuote(remoteName)))
	if _, err := android.AdbCmd(resolved, "push", localBinary, remotePath); err != nil {
		emit("error", err.Error(), 75)
		return nil, fmt.Errorf("adb push %s -> %s: %w", localBinary, remotePath, err)
	}
	if _, err := android.AdbShell(resolved, fmt.Sprintf("chmod 755 %s", shellSingleQuote(remotePath))); err != nil {
		emit("error", err.Error(), 85)
		return nil, fmt.Errorf("chmod 755 %s: %w", remotePath, err)
	}

	res := &DeployResult{
		Serial:        resolved,
		Version:       version,
		Arch:          arch,
		RemotePath:    remotePath,
		FromCache:     fromCache,
		LocalFilePath: localBinary,
	}

	if opts.AutoStart {
		emit("start", fmt.Sprintf("Starting %s on port %d...", remoteName, port), 90)
		st, startErr := StartServer(StartServerOptions{
			Serial:      resolved,
			BinaryPath:  remotePath,
			Port:        port,
			ForwardPort: opts.ForwardPort,
			HostVersion: version,
		})
		if startErr != nil {
			res.Message = fmt.Sprintf("Deployed to %s, but failed to start: %v", remotePath, startErr)
			emit("done", res.Message, 100)
			return res, nil
		}
		res.Started = st.Running
		res.Status = st
		res.Message = fmt.Sprintf("Deployed & started %s (%s) on %s", remotePath, arch, resolved)
	} else {
		st, _ := CheckServer(resolved, port, version)
		res.Status = st
		res.Message = fmt.Sprintf("Deployed frida-server (%s) to %s", arch, remotePath)
	}

	emit("done", res.Message, 100)
	return res, nil
}

// FetchLatestFridaVersion queries GitHub Releases API for the newest Frida tag.
func FetchLatestFridaVersion(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubLatestReleaseURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "cap-frida-deployer")
	req.Header.Set("Accept", "application/vnd.github+json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("query latest Frida release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub release query returned HTTP %d", resp.StatusCode)
	}
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", fmt.Errorf("decode GitHub release: %w", err)
	}
	ver := extractVersionString(rel.TagName)
	if ver == "" {
		return "", fmt.Errorf("unexpected release tag: %q", rel.TagName)
	}
	return ver, nil
}

func downloadFileWithProgress(ctx context.Context, rawURL, dstPath string, onPct func(int)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "cap-frida-deployer")

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download %s: %w", rawURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: HTTP %d", rawURL, resp.StatusCode)
	}

	tmpPath := dstPath + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	defer func() {
		f.Close()
		_ = os.Remove(tmpPath)
	}()

	total := resp.ContentLength
	var written int64
	lastPct := -1
	buf := make([]byte, 32*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, wErr := f.Write(buf[:n]); wErr != nil {
				return wErr
			}
			written += int64(n)
			if total > 0 && onPct != nil {
				pct := int((written * 100) / total)
				if pct > 100 {
					pct = 100
				}
				if pct != lastPct && (pct-lastPct >= 5 || pct == 100) {
					lastPct = pct
					onPct(pct)
				}
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, dstPath)
}

func decompressXZFile(ctx context.Context, srcXZ, dstPath string) error {
	// Strategy 1: native `xz` binary if available
	if xzBin, err := exec.LookPath("xz"); err == nil {
		cmd := exec.CommandContext(ctx, xzBin, "-d", "-c", srcXZ)
		outFile, err := os.Create(dstPath)
		if err != nil {
			return err
		}
		cmd.Stdout = outFile
		var errBuf strings.Builder
		cmd.Stderr = &errBuf
		runErr := cmd.Run()
		closeErr := outFile.Close()
		if runErr == nil && closeErr == nil {
			return os.Chmod(dstPath, 0755)
		}
		_ = os.Remove(dstPath)
	}

	// Strategy 2: Python 3 stdlib `lzma` (available across macOS/Linux/Windows)
	if pyBin, err := exec.LookPath("python3"); err == nil {
		script := `import lzma, shutil, sys
with lzma.open(sys.argv[1], "rb") as src, open(sys.argv[2], "wb") as dst:
    shutil.copyfileobj(src, dst)
`
		cmd := exec.CommandContext(ctx, pyBin, "-c", script, srcXZ, dstPath)
		if out, err := cmd.CombinedOutput(); err == nil {
			return os.Chmod(dstPath, 0755)
		} else {
			_ = os.Remove(dstPath)
			return fmt.Errorf("decompress .xz via python3 lzma: %v (%s)", err, strings.TrimSpace(string(out)))
		}
	}

	return fmt.Errorf("cannot decompress %s: neither `xz` nor `python3` found in PATH", filepath.Base(srcXZ))
}

// ListProcesses enumerates applications and running processes on the device.
// It prefers the Python Frida bridge (gives exact running PID + package identifier),
// falls back to `frida-ps -ai`, and finally falls back to `adb shell pm/ps`.
func ListProcesses(ctx context.Context, serial, remoteHost string, tc ToolchainInfo) ([]ProcessEntry, error) {
	resolved, err := android.GetDeviceSerial(serial)
	if err != nil && remoteHost == "" {
		return nil, err
	}
	if resolved != "" {
		serial = resolved
	}

	// Strategy 1: Python Frida bridge --ps
	if tc.FridaModuleOK && tc.PythonPath != "" {
		if entries, err := listProcessesViaPythonBridge(ctx, tc.PythonPath, serial, remoteHost); err == nil && len(entries) > 0 {
			sortProcessEntries(entries)
			return entries, nil
		}
	}

	// Strategy 2: frida-ps CLI
	if tc.FridaPSPath != "" {
		if entries, err := listProcessesViaFridaPS(ctx, tc.FridaPSPath, serial, remoteHost); err == nil && len(entries) > 0 {
			sortProcessEntries(entries)
			return entries, nil
		}
	}

	// Strategy 3: ADB fallback (always works even when frida-server is stopped)
	entries, err := listProcessesViaADB(serial)
	if err != nil {
		return nil, err
	}
	sortProcessEntries(entries)
	return entries, nil
}

func listProcessesViaPythonBridge(ctx context.Context, pythonPath, serial, remoteHost string) ([]ProcessEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, pythonPath, "-c", pythonBridgeScript, "--ps", serial, remoteHost)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var entries []ProcessEntry
	if err := json.Unmarshal(out, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func listProcessesViaFridaPS(ctx context.Context, fridaPSPath, serial, remoteHost string) ([]ProcessEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	args := []string{"-ai"}
	if remoteHost != "" {
		args = append(args, "-H", remoteHost)
	} else if serial != "" {
		args = append(args, "-D", serial)
	} else {
		args = append(args, "-U")
	}
	cmd := exec.CommandContext(ctx, fridaPSPath, args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return parseFridaPSOutput(string(out)), nil
}

func parseFridaPSOutput(out string) []ProcessEntry {
	var entries []ProcessEntry
	for _, rawLine := range strings.Split(out, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "PID") || strings.HasPrefix(line, "---") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		pid := 0
		if fields[0] != "-" {
			pid, _ = strconv.Atoi(fields[0])
		}
		ident := fields[len(fields)-1]
		name := strings.Join(fields[1:len(fields)-1], " ")
		entries = append(entries, ProcessEntry{
			PID:        pid,
			Name:       name,
			Identifier: ident,
			Running:    pid > 0,
			Source:     "frida",
		})
	}
	return entries
}

func listProcessesViaADB(serial string) ([]ProcessEntry, error) {
	script := `echo "PKGS_START"; pm list packages -3 2>/dev/null || true; echo "PKGS_END"; echo "PS_START"; ps -A -o PID,NAME 2>/dev/null || ps 2>/dev/null || true; echo "PS_END"`
	out, err := android.AdbShell(serial, script)
	if err != nil && strings.TrimSpace(out) == "" {
		return nil, err
	}

	runningPIDs := make(map[string]int)
	var pkgs []string
	section := ""
	for _, rawLine := range strings.Split(out, "\n") {
		line := strings.TrimSpace(rawLine)
		switch {
		case line == "PKGS_START":
			section = "pkgs"
		case line == "PKGS_END":
			section = ""
		case line == "PS_START":
			section = "ps"
		case line == "PS_END":
			section = ""
		case section == "pkgs":
			if strings.HasPrefix(line, "package:") {
				pkgs = append(pkgs, strings.TrimSpace(strings.TrimPrefix(line, "package:")))
			}
		case section == "ps":
			fields := strings.Fields(line)
			if len(fields) < 2 || fields[0] == "PID" || fields[0] == "USER" {
				continue
			}
			pid, err := strconv.Atoi(fields[0])
			name := fields[len(fields)-1]
			if err != nil && len(fields) >= 3 {
				pid, err = strconv.Atoi(fields[1])
			}
			if err == nil && pid > 0 && name != "" {
				runningPIDs[name] = pid
			}
		}
	}

	entries := make([]ProcessEntry, 0, len(pkgs))
	for _, pkg := range pkgs {
		pid := runningPIDs[pkg]
		entries = append(entries, ProcessEntry{
			PID:        pid,
			Name:       pkg,
			Identifier: pkg,
			Running:    pid > 0,
			Source:     "adb",
		})
	}
	return entries, nil
}

func sortProcessEntries(entries []ProcessEntry) {
	sort.SliceStable(entries, func(i, j int) bool {
		// Running apps with identifiers first, then stopped apps, then bare native processes
		iHasID := entries[i].Identifier != ""
		jHasID := entries[j].Identifier != ""
		if entries[i].Running != entries[j].Running {
			return entries[i].Running
		}
		if iHasID != jHasID {
			return iHasID
		}
		a := strings.ToLower(entries[i].Identifier + entries[i].Name)
		b := strings.ToLower(entries[j].Identifier + entries[j].Name)
		return a < b
	})
}

func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
