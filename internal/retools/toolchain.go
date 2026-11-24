package retools

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const toolchainProbeTimeout = 4 * time.Second

var (
	semverRe     = regexp.MustCompile(`(\d+)\.(\d+)(?:\.(\d+))?(?:[_.-]\d+)?`)
	javaQuotedRe = regexp.MustCompile(`version\s+"([^"]+)"`)
	pomVersionRe = regexp.MustCompile(`<version>\s*([^<\s]+)\s*</version>`)
)

// DetectToolchain probes the host machine for radare2, Java/Maven/Unidbg,
// and Python 3 with qiling and angr installed. Custom paths in cfg override
// auto-discovery for their corresponding tools.
func DetectToolchain(cfg ToolchainConfig) ToolchainInfo {
	info := ToolchainInfo{
		R2: ToolStatus{
			Name:    "r2",
			Install: "brew install radare2 (macOS) or https://github.com/radareorg/radare2",
		},
		Java: ToolStatus{
			Name:    "java",
			Install: "brew install openjdk@17 (macOS) or install JDK 8/11/17",
		},
		Mvn: ToolStatus{
			Name:    "mvn",
			Install: "brew install maven (macOS) or https://maven.apache.org/download.cgi",
		},
		Unidbg: ToolStatus{
			Name:    "unidbg",
			Install: "git clone https://github.com/zhkl0228/unidbg && mvn -DskipTests package, then set UnidbgDir",
		},
		Python: ToolStatus{
			Name:    "python3",
			Install: "brew install python@3.11 (macOS) or install Python 3.9+",
		},
		Qiling: ToolStatus{
			Name:    "qiling",
			Install: "pip3 install qiling (plus qiling rootfs from https://github.com/qilingframework/rootfs)",
		},
		Angr: ToolStatus{
			Name:    "angr",
			Install: "pip3 install angr",
		},
		CheckedAt: nowRFC3339(),
	}

	// Probe independent tools in parallel so host toolchain checks stay fast.
	var (
		wg       sync.WaitGroup
		r2Info   ToolchainInfo
		javaInfo ToolchainInfo
		mvnInfo  ToolchainInfo
		uniInfo  ToolchainInfo
		pyInfo   ToolchainInfo
	)
	r2Info.R2 = info.R2
	javaInfo.Java = info.Java
	mvnInfo.Mvn = info.Mvn
	uniInfo.Unidbg = info.Unidbg
	pyInfo.Python = info.Python
	pyInfo.Qiling = info.Qiling
	pyInfo.Angr = info.Angr

	wg.Add(5)
	go func() { defer wg.Done(); probeR2Toolchain(cfg.R2Path, &r2Info) }()
	go func() { defer wg.Done(); probeJavaToolchain(cfg.JavaPath, &javaInfo) }()
	go func() { defer wg.Done(); probeMvnToolchain(cfg.MvnPath, &mvnInfo) }()
	go func() { defer wg.Done(); probeUnidbgToolchain(cfg.UnidbgDir, &uniInfo) }()
	go func() { defer wg.Done(); probePythonToolchain(cfg.PythonPath, &pyInfo) }()
	wg.Wait()

	info.R2 = r2Info.R2
	info.Java = javaInfo.Java
	info.JavacPath = javaInfo.JavacPath
	info.Mvn = mvnInfo.Mvn
	info.Unidbg = uniInfo.Unidbg
	info.UnidbgJars = uniInfo.UnidbgJars
	info.Python = pyInfo.Python
	info.Qiling = pyInfo.Qiling
	info.Angr = pyInfo.Angr

	// 6. Validate optional Qiling RootFS path
	rootfs := strings.TrimSpace(cfg.QilingRootFS)
	if rootfs == "" {
		rootfs = strings.TrimSpace(os.Getenv("QILING_ROOTFS"))
	}
	if rootfs != "" {
		if fi, err := os.Stat(rootfs); err == nil && fi.IsDir() {
			if abs, err := filepath.Abs(rootfs); err == nil {
				rootfs = abs
			}
			info.QilingRootFS = rootfs
		} else {
			info.Issues = append(info.Issues, fmt.Sprintf("Qiling rootfs directory not found: %s", rootfs))
		}
	}

	// 7. Compute aggregate engine readiness flags & collect actionable issues.
	info.R2Ready = info.R2.Ready

	unidbgHasJars := len(info.UnidbgJars) > 0
	unidbgHasPom := false
	if info.Unidbg.Ready && info.Unidbg.Path != "" {
		if fi, err := os.Stat(info.Unidbg.Path); err == nil && fi.IsDir() {
			_, unidbgHasPom = detectUnidbgPom(info.Unidbg.Path)
		}
	}
	unidbgCanBuild := info.JavacPath != "" && (unidbgHasJars || (unidbgHasPom && info.Mvn.Ready))
	info.UnidbgReady = info.Java.Ready && info.Unidbg.Ready && unidbgCanBuild

	if info.Java.Ready && info.Unidbg.Ready && !unidbgCanBuild {
		if info.JavacPath == "" {
			info.Issues = append(info.Issues, "JDK `javac` compiler not found (required to compile Unidbg harnesses) — install a full JDK (e.g. brew install openjdk@17)")
		} else if !unidbgHasJars && (!unidbgHasPom || !info.Mvn.Ready) {
			info.Issues = append(info.Issues, "Unidbg requires either pre-built JARs or a Maven pom.xml with `mvn` installed")
		}
	}

	info.QilingReady = info.Python.Ready && info.Qiling.Ready
	info.AngrReady = info.Python.Ready && info.Angr.Ready

	for _, ts := range []ToolStatus{
		info.R2, info.Java, info.Mvn, info.Unidbg, info.Python, info.Qiling, info.Angr,
	} {
		if ts.Issue != "" {
			info.Issues = append(info.Issues, ts.Issue)
		}
	}

	return info
}

func probeR2Toolchain(preferred string, info *ToolchainInfo) {
	preferred = strings.TrimSpace(preferred)
	cands := buildBinaryCandidates(preferred, "r2", "radare2")
	for _, bin := range cands {
		if info.R2.Path == "" {
			info.R2.Path = bin
		}
		if ver, ok := probeBinaryVersion(bin, "-v"); ok {
			info.R2.Path = bin
			info.R2.Version = ver
			info.R2.Ready = true
			return
		}
	}
	if preferred != "" {
		info.R2.Path = preferred
		info.R2.Issue = fmt.Sprintf("r2 not working at configured path %s — install with: %s", preferred, info.R2.Install)
	} else {
		info.R2.Issue = fmt.Sprintf("radare2 (r2) not found (pure-Go ELF fallback still available) — install with: %s", info.R2.Install)
	}
}

func probeJavaToolchain(preferred string, info *ToolchainInfo) {
	preferred = strings.TrimSpace(preferred)
	var extraDirs []string
	if jh := strings.TrimSpace(os.Getenv("JAVA_HOME")); jh != "" {
		extraDirs = append(extraDirs, filepath.Join(jh, "bin"))
	}
	extraDirs = append(extraDirs,
		"/opt/homebrew/opt/openjdk/bin",
		"/opt/homebrew/opt/openjdk@17/bin",
		"/opt/homebrew/opt/openjdk@11/bin",
		"/usr/local/opt/openjdk/bin",
		"/usr/local/opt/openjdk@17/bin",
		"/usr/bin",
	)
	cands := buildBinaryCandidatesWithDirs(preferred, extraDirs, "java")
	for _, bin := range cands {
		if info.Java.Path == "" {
			info.Java.Path = bin
		}
		if ver, ok := probeJavaVersion(bin); ok {
			info.Java.Path = bin
			info.Java.Version = ver
			info.Java.Ready = true
			// Check sibling javac in the same bin directory first, then PATH
			sibling := filepath.Join(filepath.Dir(bin), executableName("javac"))
			if isExecutableFile(sibling) {
				info.JavacPath = sibling
			} else if p, err := exec.LookPath("javac"); err == nil {
				info.JavacPath = p
			}
			return
		}
	}
	if preferred != "" {
		info.Java.Path = preferred
		info.Java.Issue = fmt.Sprintf("java not working at configured path %s — install with: %s", preferred, info.Java.Install)
	} else {
		info.Java.Issue = fmt.Sprintf("java runtime not found (required for Unidbg) — install with: %s", info.Java.Install)
	}
}

func probeMvnToolchain(preferred string, info *ToolchainInfo) {
	preferred = strings.TrimSpace(preferred)
	cands := buildBinaryCandidates(preferred, "mvn")
	for _, bin := range cands {
		if info.Mvn.Path == "" {
			info.Mvn.Path = bin
		}
		if ver, ok := probeBinaryVersion(bin, "-v"); ok {
			info.Mvn.Path = bin
			info.Mvn.Version = ver
			info.Mvn.Ready = true
			return
		}
	}
	if preferred != "" {
		info.Mvn.Path = preferred
		info.Mvn.Issue = fmt.Sprintf("mvn not working at configured path %s — install with: %s", preferred, info.Mvn.Install)
	} else {
		info.Mvn.Issue = fmt.Sprintf("Maven (mvn) not found (optional if Unidbg jars are pre-built) — install with: %s", info.Mvn.Install)
	}
}

func probeUnidbgToolchain(preferred string, info *ToolchainInfo) {
	preferred = strings.TrimSpace(preferred)
	var candidates []string
	if preferred != "" {
		candidates = []string{preferred}
	} else {
		if env := strings.TrimSpace(os.Getenv("UNIDBG_DIR")); env != "" {
			candidates = append(candidates, env)
		}
		if env := strings.TrimSpace(os.Getenv("UNIDBG_HOME")); env != "" {
			candidates = append(candidates, env)
		}
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			candidates = append(candidates,
				filepath.Join(home, ".cap", "unidbg"),
				filepath.Join(home, "unidbg"),
				filepath.Join(home, "tools", "unidbg"),
			)
		}
		candidates = append(candidates, "/opt/unidbg")
	}

	for _, cand := range candidates {
		fi, err := os.Stat(cand)
		if err != nil {
			continue
		}
		absPath := cand
		if abs, err := filepath.Abs(cand); err == nil {
			absPath = abs
		}
		// Case A: direct fat jar file
		if !fi.IsDir() {
			if strings.HasSuffix(strings.ToLower(absPath), ".jar") {
				info.Unidbg.Ready = true
				info.Unidbg.Path = absPath
				info.Unidbg.Version = extractVersionFromName(filepath.Base(absPath), "jar")
				info.UnidbgJars = []string{absPath}
				return
			}
			continue
		}

		// Case B: directory containing jars or Maven pom.xml
		jars := collectUnidbgJars(absPath)
		pomVer, hasPom := detectUnidbgPom(absPath)
		if len(jars) > 0 || hasPom {
			info.Unidbg.Ready = true
			info.Unidbg.Path = absPath
			info.UnidbgJars = jars
			if pomVer != "" {
				info.Unidbg.Version = pomVer
			} else if len(jars) > 0 {
				info.Unidbg.Version = extractVersionFromName(filepath.Base(jars[0]), "jar")
			} else {
				info.Unidbg.Version = "maven-project"
			}
			return
		}
	}

	if preferred != "" {
		info.Unidbg.Path = preferred
		info.Unidbg.Issue = fmt.Sprintf("Unidbg not found (no .jar or pom.xml) at %s — %s", preferred, info.Unidbg.Install)
	} else {
		info.Unidbg.Issue = fmt.Sprintf("Unidbg directory/jars not configured — %s", info.Unidbg.Install)
	}
}

func probePythonToolchain(preferred string, info *ToolchainInfo) {
	preferred = strings.TrimSpace(preferred)
	cands := buildPythonCandidates(preferred)

	type pyProbe struct {
		path      string
		pyVer     string
		qilingVer string
		angrVer   string
		score     int
	}
	var best *pyProbe

	for _, py := range cands {
		pyVer, qVer, aVer, ok := probePythonModules(py)
		if !ok {
			continue
		}
		score := 1
		if qVer != "" {
			score += 2
		}
		if aVer != "" {
			score += 2
		}
		p := &pyProbe{
			path:      py,
			pyVer:     pyVer,
			qilingVer: qVer,
			angrVer:   aVer,
			score:     score,
		}
		if best == nil || p.score > best.score {
			best = p
		}
		// Stop early when we found a Python with both qiling & angr, or when an explicit path was specified.
		if preferred != "" || (qVer != "" && aVer != "") {
			break
		}
	}

	if best == nil {
		if preferred != "" {
			info.Python.Path = preferred
			info.Python.Issue = fmt.Sprintf("python3 not working at configured path %s — install with: %s", preferred, info.Python.Install)
		} else {
			info.Python.Issue = fmt.Sprintf("python3 not found (required for Qiling & angr) — install with: %s", info.Python.Install)
		}
		info.Qiling.Issue = fmt.Sprintf("qiling unavailable without Python 3 — install with: %s", info.Qiling.Install)
		info.Angr.Issue = fmt.Sprintf("angr unavailable without Python 3 — install with: %s", info.Angr.Install)
		return
	}

	info.Python.Ready = true
	info.Python.Path = best.path
	info.Python.Version = best.pyVer

	if best.qilingVer != "" {
		info.Qiling.Ready = true
		info.Qiling.Path = best.path
		info.Qiling.Version = best.qilingVer
	} else {
		info.Qiling.Path = best.path
		info.Qiling.Issue = fmt.Sprintf("Python `qiling` module not installed in %s — install with: %s -m pip install qiling", best.path, best.path)
	}

	if best.angrVer != "" {
		info.Angr.Ready = true
		info.Angr.Path = best.path
		info.Angr.Version = best.angrVer
	} else {
		info.Angr.Path = best.path
		info.Angr.Issue = fmt.Sprintf("Python `angr` module not installed in %s — install with: %s -m pip install angr", best.path, best.path)
	}
}

func probeBinaryVersion(bin string, flag string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), toolchainProbeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, flag)
	configureProcGroup(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", false
	}
	ver := extractVersionString(string(out))
	if ver == "" {
		// Accept non-empty output even if version format is unconventional.
		first := firstNonEmptyLine(string(out))
		if first == "" {
			return "", false
		}
		return first, true
	}
	return ver, true
}

func probeJavaVersion(bin string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), toolchainProbeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-version")
	configureProcGroup(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", false
	}
	text := string(out)
	if m := javaQuotedRe.FindStringSubmatch(text); len(m) >= 2 && strings.TrimSpace(m[1]) != "" {
		return strings.TrimSpace(m[1]), true
	}
	if ver := extractVersionString(text); ver != "" {
		return ver, true
	}
	return "", false
}

func probePythonModules(py string) (pyVer, qilingVer, angrVer string, ok bool) {
	ctx, cancel := context.WithTimeout(context.Background(), toolchainProbeTimeout)
	defer cancel()
	const snippet = `import sys
print("PY=" + ".".join(map(str, sys.version_info[:3])))
for mod, key in (("qiling", "QILING"), ("angr", "ANGR")):
    try:
        m = __import__(mod)
        v = getattr(m, "__version__", "") or "installed"
        print(key + "=" + str(v))
    except Exception:
        print(key + "=")
`
	cmd := exec.CommandContext(ctx, py, "-c", snippet)
	configureProcGroup(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", "", false
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "PY="):
			pyVer = strings.TrimSpace(strings.TrimPrefix(line, "PY="))
			ok = pyVer != ""
		case strings.HasPrefix(line, "QILING="):
			qilingVer = strings.TrimSpace(strings.TrimPrefix(line, "QILING="))
		case strings.HasPrefix(line, "ANGR="):
			angrVer = strings.TrimSpace(strings.TrimPrefix(line, "ANGR="))
		}
	}
	return pyVer, qilingVer, angrVer, ok
}

func collectUnidbgJars(dir string) []string {
	searchDirs := []string{
		dir,
		filepath.Join(dir, "lib"),
		filepath.Join(dir, "libs"),
		filepath.Join(dir, "target"),
		filepath.Join(dir, "unidbg-android", "target"),
		filepath.Join(dir, "unidbg-android", "target", "dependency"),
	}
	seen := make(map[string]bool)
	var jars []string
	for _, d := range searchDirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if !strings.HasSuffix(strings.ToLower(name), ".jar") {
				continue
			}
			full := filepath.Join(d, name)
			if !seen[full] {
				seen[full] = true
				jars = append(jars, full)
			}
		}
	}
	sort.Strings(jars)
	return jars
}

func detectUnidbgPom(dir string) (version string, found bool) {
	pomPaths := []string{
		filepath.Join(dir, "pom.xml"),
		filepath.Join(dir, "unidbg-android", "pom.xml"),
	}
	for _, p := range pomPaths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		text := string(data)
		if strings.Contains(strings.ToLower(text), "unidbg") || strings.Contains(text, "<project") {
			if m := pomVersionRe.FindStringSubmatch(text); len(m) >= 2 {
				return m[1], true
			}
			return "maven-project", true
		}
	}
	return "", false
}

func buildBinaryCandidates(preferred string, names ...string) []string {
	return buildBinaryCandidatesWithDirs(preferred, nil, names...)
}

func buildBinaryCandidatesWithDirs(preferred string, extraDirs []string, names ...string) []string {
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
			fi, err := os.Stat(p)
			if err != nil || fi.IsDir() {
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

	// Explicit override: strictly honor only the configured path.
	if strings.TrimSpace(preferred) != "" {
		add(preferred)
		return out
	}

	for _, name := range names {
		add(name)
	}

	dirs := make([]string, 0, len(extraDirs)+8)
	dirs = append(dirs, extraDirs...)
	dirs = append(dirs, "/opt/homebrew/bin", "/usr/local/bin")
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		dirs = append(dirs,
			filepath.Join(home, ".local", "bin"),
			filepath.Join(home, "bin"),
		)
	}
	for _, dir := range dirs {
		for _, name := range names {
			add(filepath.Join(dir, executableName(name)))
		}
	}
	return out
}

func buildPythonCandidates(preferred string) []string {
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
			fi, err := os.Stat(p)
			if err != nil || fi.IsDir() {
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

	if strings.TrimSpace(preferred) != "" {
		add(preferred)
		return out
	}

	if venv := strings.TrimSpace(os.Getenv("VIRTUAL_ENV")); venv != "" {
		add(filepath.Join(venv, "bin", executableName("python3")))
		add(filepath.Join(venv, "bin", executableName("python")))
	}
	if conda := strings.TrimSpace(os.Getenv("CONDA_PREFIX")); conda != "" {
		add(filepath.Join(conda, "bin", executableName("python3")))
		add(filepath.Join(conda, "bin", executableName("python")))
	}

	add("python3")
	add("python")

	extra := []string{
		"/opt/homebrew/bin/python3",
		"/usr/local/bin/python3",
		"/usr/bin/python3",
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		extra = append(extra,
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

func extractVersionString(raw string) string {
	m := semverRe.FindStringSubmatch(strings.TrimSpace(raw))
	if len(m) == 0 {
		return ""
	}
	return m[0]
}

func extractVersionFromName(name, fallback string) string {
	if ver := extractVersionString(name); ver != "" {
		return ver
	}
	return fallback
}

func firstNonEmptyLine(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			if len(line) > 80 {
				return line[:80]
			}
			return line
		}
	}
	return ""
}

func executableName(name string) string {
	if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(name), ".exe") {
		return name + ".exe"
	}
	return name
}

func isExecutableFile(p string) bool {
	fi, err := os.Stat(p)
	if err != nil || fi.IsDir() {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	return fi.Mode()&0111 != 0
}
