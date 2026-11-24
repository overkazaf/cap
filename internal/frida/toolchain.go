package frida

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var (
	semverRe = regexp.MustCompile(`(\d+)\.(\d+)(?:\.(\d+))?`)
)

const toolchainProbeTimeout = 5 * time.Second

// DetectToolchain probes the local machine for a working Python 3 interpreter
// with the `frida` package installed (preferred Python Bridge driver), as well
// as `frida` / `frida-ps` CLI tools and `adb`.
func DetectToolchain(cfg ToolchainConfig) ToolchainInfo {
	info := ToolchainInfo{
		Driver:    DriverNone,
		CheckedAt: nowRFC3339(),
	}

	// 1. Check adb
	if adbPath, err := exec.LookPath("adb"); err == nil {
		info.ADBPath = adbPath
		info.ADBReady = true
	} else {
		info.Issues = append(info.Issues, "adb not found in PATH")
	}

	// 2. Locate frida & frida-ps CLIs (custom path first, then PATH & common dirs)
	fridaCandidates := buildBinaryCandidates(cfg.FridaPath, "frida")
	for _, bin := range fridaCandidates {
		if info.FridaCLIPath == "" {
			info.FridaCLIPath = bin
		}
		if ver, ok := probeFridaCLI(bin); ok {
			info.FridaCLIPath = bin
			info.FridaCLIOK = true
			info.FridaCLIVersion = ver
			break
		}
	}
	if fridaPSCandidates := buildBinaryCandidates("", "frida-ps"); len(fridaPSCandidates) > 0 {
		info.FridaPSPath = fridaPSCandidates[0]
	}

	// 3. Locate a Python interpreter that can `import frida`
	pyCandidates := buildPythonCandidates(cfg.PythonPath, info.FridaCLIPath)
	firstWorkingPython := ""
	firstWorkingPyVer := ""
	for _, py := range pyCandidates {
		pyVer, fridaVer, hasFrida, ok := probePythonFrida(py)
		if !ok {
			continue
		}
		if firstWorkingPython == "" {
			firstWorkingPython = py
			firstWorkingPyVer = pyVer
		}
		if hasFrida {
			info.PythonPath = py
			info.PythonVersion = pyVer
			info.FridaModuleOK = true
			info.FridaVersion = fridaVer
			break
		}
	}
	if !info.FridaModuleOK && firstWorkingPython != "" {
		info.PythonPath = firstWorkingPython
		info.PythonVersion = firstWorkingPyVer
	}

	// 4. Choose best driver & summarize actionable diagnostics
	switch {
	case info.FridaModuleOK:
		info.Driver = DriverPythonBridge
		info.Ready = true
	case info.FridaCLIOK:
		info.Driver = DriverFridaCLI
		info.Ready = true
		if info.FridaVersion == "" {
			info.FridaVersion = info.FridaCLIVersion
		}
		info.Issues = append(info.Issues, "Python `frida` module not found for live bridge — falling back to `frida` CLI (hot-reload disabled)")
	default:
		info.Driver = DriverNone
		info.Ready = false
		if info.FridaCLIPath != "" && !info.FridaCLIOK {
			info.Issues = append(info.Issues, fmt.Sprintf("frida binary at %s failed health check (check Python environment / frida-tools install)", info.FridaCLIPath))
		}
		if info.PythonPath != "" {
			info.Issues = append(info.Issues, fmt.Sprintf("Python %s found at %s without `frida` module — install with: %s -m pip install frida-tools", info.PythonVersion, info.PythonPath, info.PythonPath))
		} else {
			info.Issues = append(info.Issues, "Neither Python `frida` module nor working `frida` CLI found — install with: pip3 install frida-tools")
		}
	}

	return info
}

// CompareVersions classifies compatibility between host Frida and device frida-server.
// Frida's wire protocol requires matching major versions and works best with exact match.
func CompareVersions(hostVer, serverVer string) string {
	hm, hmin, hp, hok := parseSemver(hostVer)
	sm, smin, sp, sok := parseSemver(serverVer)
	if !hok || !sok {
		return VersionMatchUnknown
	}
	if hm != sm {
		return VersionMatchMajor
	}
	if hmin != smin || hp != sp {
		return VersionMatchMinor
	}
	return VersionMatchExact
}

func parseSemver(raw string) (major, minor, patch int, ok bool) {
	m := semverRe.FindStringSubmatch(strings.TrimSpace(raw))
	if len(m) < 3 {
		return 0, 0, 0, false
	}
	maj, err1 := strconv.Atoi(m[1])
	min, err2 := strconv.Atoi(m[2])
	if err1 != nil || err2 != nil {
		return 0, 0, 0, false
	}
	pat := 0
	if len(m) >= 4 && m[3] != "" {
		pat, _ = strconv.Atoi(m[3])
	}
	return maj, min, pat, true
}

func probeFridaCLI(bin string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), toolchainProbeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", false
	}
	ver := extractVersionString(string(out))
	if ver == "" {
		return "", false
	}
	return ver, true
}

func probePythonFrida(py string) (pyVer, fridaVer string, hasFrida, pyOK bool) {
	ctx, cancel := context.WithTimeout(context.Background(), toolchainProbeTimeout)
	defer cancel()
	snippet := `import sys
print("PY=" + ".".join(map(str, sys.version_info[:3])))
try:
    import frida
    print("FRIDA=" + getattr(frida, "__version__", ""))
except Exception:
    print("FRIDA=")
`
	cmd := exec.CommandContext(ctx, py, "-c", snippet)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", false, false
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "PY=") {
			pyVer = strings.TrimPrefix(line, "PY=")
			pyOK = pyVer != ""
		} else if strings.HasPrefix(line, "FRIDA=") {
			fridaVer = extractVersionString(strings.TrimPrefix(line, "FRIDA="))
			hasFrida = fridaVer != ""
		}
	}
	return pyVer, fridaVer, hasFrida, pyOK
}

func extractVersionString(raw string) string {
	m := semverRe.FindStringSubmatch(strings.TrimSpace(raw))
	if len(m) == 0 {
		return ""
	}
	return m[0]
}

func buildBinaryCandidates(preferred, name string) []string {
	var out []string
	seen := make(map[string]bool)
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if resolved, err := exec.LookPath(p); err == nil {
			p = resolved
		} else {
			info, err := os.Stat(p)
			if err != nil || info.IsDir() {
				return
			}
		}
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}

	if preferred != "" {
		add(preferred)
	}
	add(name)

	home, _ := os.UserHomeDir()
	commonDirs := []string{
		"/opt/homebrew/bin",
		"/usr/local/bin",
	}
	if home != "" {
		commonDirs = append(commonDirs,
			filepath.Join(home, ".local", "bin"),
			filepath.Join(home, ".pyenv", "shims"),
			filepath.Join(home, ".local", "pipx", "venvs", "frida-tools", "bin"),
			filepath.Join(home, "miniconda3", "bin"),
			filepath.Join(home, "anaconda3", "bin"),
			filepath.Join(home, "miniforge3", "bin"),
		)
		if runtime.GOOS == "darwin" {
			if entries, err := os.ReadDir(filepath.Join(home, "Library", "Python")); err == nil {
				for _, e := range entries {
					if e.IsDir() {
						commonDirs = append(commonDirs, filepath.Join(home, "Library", "Python", e.Name(), "bin"))
					}
				}
			}
		}
	}
	for _, dir := range commonDirs {
		add(filepath.Join(dir, name))
	}
	return out
}

func buildPythonCandidates(preferred, fridaCLIPath string) []string {
	var out []string
	seen := make(map[string]bool)
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if resolved, err := exec.LookPath(p); err == nil {
			p = resolved
		} else {
			info, err := os.Stat(p)
			if err != nil || info.IsDir() {
				return
			}
		}
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}

	if preferred != "" {
		add(preferred)
	}

	// If a frida CLI script exists, inspect its #! shebang first (very common for pipx/venv installs)
	if fridaCLIPath != "" {
		if shebangPy := parsePythonShebang(fridaCLIPath); shebangPy != "" {
			add(shebangPy)
		}
		// Sibling python3 in the same bin directory (e.g. venv/bin/frida -> venv/bin/python3)
		binDir := filepath.Dir(fridaCLIPath)
		add(filepath.Join(binDir, "python3"))
		add(filepath.Join(binDir, "python"))
	}

	// Active virtualenvs in environment
	if venv := os.Getenv("VIRTUAL_ENV"); venv != "" {
		add(filepath.Join(venv, "bin", "python3"))
		add(filepath.Join(venv, "bin", "python"))
	}
	if conda := os.Getenv("CONDA_PREFIX"); conda != "" {
		add(filepath.Join(conda, "bin", "python3"))
		add(filepath.Join(conda, "bin", "python"))
	}

	add("python3")
	add("python")

	home, _ := os.UserHomeDir()
	extra := []string{
		"/opt/homebrew/bin/python3",
		"/usr/local/bin/python3",
		"/usr/bin/python3",
	}
	if home != "" {
		extra = append(extra,
			filepath.Join(home, ".local", "pipx", "venvs", "frida-tools", "bin", "python"),
			filepath.Join(home, ".local", "pipx", "venvs", "frida-tools", "bin", "python3"),
			filepath.Join(home, ".pyenv", "shims", "python3"),
			filepath.Join(home, "miniconda3", "bin", "python3"),
			filepath.Join(home, "miniforge3", "bin", "python3"),
			filepath.Join(home, "anaconda3", "bin", "python3"),
		)
	}
	for _, p := range extra {
		add(p)
	}

	return out
}

func parsePythonShebang(scriptPath string) string {
	data, err := os.ReadFile(scriptPath)
	if err != nil || len(data) < 2 || data[0] != '#' || data[1] != '!' {
		return ""
	}
	firstLine := string(data)
	if idx := strings.IndexByte(firstLine, '\n'); idx >= 0 {
		firstLine = firstLine[:idx]
	}
	firstLine = strings.TrimSpace(strings.TrimPrefix(firstLine, "#!"))
	fields := strings.Fields(firstLine)
	if len(fields) == 0 {
		return ""
	}
	if filepath.Base(fields[0]) == "env" && len(fields) >= 2 {
		return fields[1]
	}
	return fields[0]
}
