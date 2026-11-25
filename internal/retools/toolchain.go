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
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	toolchainProbeTimeout = 4 * time.Second
	pythonProbeTimeout    = 6 * time.Second
	probeWorkerPoolSize   = 6
)

var (
	semverRe         = regexp.MustCompile(`(\d+)\.(\d+)(?:\.(\d+))?(?:[_.-]\d+)?`)
	javaQuotedRe     = regexp.MustCompile(`version\s+"([^"]+)"`)
	pomVersionRe     = regexp.MustCompile(`<version>\s*([^<\s]+)\s*</version>`)
	pythonBinNameRe  = regexp.MustCompile(`^python3(\.\d+)?(\.exe)?$`)
	defaultJavaGlobs = []string{
		"/Library/Java/JavaVirtualMachines/*/Contents/Home/bin/java",
		"/opt/homebrew/opt/openjdk*/bin/java",
		"/usr/local/opt/openjdk*/bin/java",
		"/usr/local/Cellar/openjdk*/*/libexec/openjdk.jdk/Contents/Home/bin/java",
		"/usr/lib/jvm/*/bin/java",
	}
	defaultJavaExtraDirs = []string{
		"/opt/homebrew/opt/openjdk/bin",
		"/opt/homebrew/opt/openjdk@17/bin",
		"/opt/homebrew/opt/openjdk@11/bin",
		"/usr/local/opt/openjdk/bin",
		"/usr/local/opt/openjdk@17/bin",
		"/usr/local/opt/openjdk@11/bin",
		"/opt/homebrew/bin",
		"/usr/local/bin",
		"/usr/bin",
	}
	// javaSearchGlobs and javaExtraDirs are overridable in unit tests for hermetic JDK discovery checks.
	javaSearchGlobs = defaultJavaGlobs
	javaExtraDirs   = defaultJavaExtraDirs
	// m2RepoOverride is overridable in unit tests for hermetic ~/.m2 fallback checks.
	m2RepoOverride = ""
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
	go func() { defer wg.Done(); probePythonToolchain(cfg, &pyInfo) }()
	wg.Wait()

	info.R2 = r2Info.R2
	info.Java = javaInfo.Java
	info.JavaHome = javaInfo.JavaHome
	info.JavacPath = javaInfo.JavacPath
	info.Mvn = mvnInfo.Mvn
	info.Unidbg = uniInfo.Unidbg
	info.UnidbgMode = uniInfo.UnidbgMode
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

	unidbgCanBuild := false
	if info.Java.Ready && info.Unidbg.Ready && info.JavacPath != "" {
		switch info.UnidbgMode {
		case UnidbgModeFatJar, UnidbgModeJarBundle:
			unidbgCanBuild = len(info.UnidbgJars) > 0
		case UnidbgModeMavenRepo:
			_, hasPom := detectUnidbgPom(info.Unidbg.Path)
			unidbgCanBuild = hasPom && info.Mvn.Ready
		case UnidbgModeM2Cache:
			unidbgCanBuild = len(info.UnidbgJars) > 0 && info.Mvn.Ready
		default:
			unidbgCanBuild = len(info.UnidbgJars) > 0
		}
	}
	info.UnidbgReady = unidbgCanBuild

	if info.Java.Ready && info.Unidbg.Ready && !unidbgCanBuild {
		if info.JavacPath == "" {
			info.Issues = append(info.Issues, "JDK `javac` compiler not found (required to compile Unidbg harnesses) — install a full JDK (e.g. brew install openjdk@17)")
		} else if (info.UnidbgMode == UnidbgModeMavenRepo || info.UnidbgMode == UnidbgModeM2Cache) && !info.Mvn.Ready {
			info.Issues = append(info.Issues, fmt.Sprintf("Unidbg (%s mode) requires Maven (`mvn`) to resolve dependency classpath", info.UnidbgMode))
		} else {
			info.Issues = append(info.Issues, "Unidbg requires either pre-built JARs or a Maven pom.xml with `mvn` installed")
		}
	}

	info.QilingReady = info.Qiling.Ready && info.Qiling.Path != ""
	info.AngrReady = info.Angr.Ready && info.Angr.Path != ""

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

type javaCandidateProbe struct {
	idx             int
	path            string
	version         string
	major           int
	isStub          bool
	hasSiblingJavac bool
	siblingJavac    string
	ok              bool
}

func probeJavaToolchain(preferred string, info *ToolchainInfo) {
	preferred = strings.TrimSpace(preferred)

	// Explicit override: strictly honor the configured Java binary.
	if preferred != "" {
		cands := buildBinaryCandidatesWithDirs(preferred, nil, "java")
		for _, bin := range cands {
			if ver, ok := probeJavaVersion(bin); ok {
				info.Java.Path = bin
				info.Java.Version = ver
				info.Java.Ready = true
				info.JavaHome = deriveJavaHome(bin)
				sibling := filepath.Join(filepath.Dir(bin), executableName("javac"))
				switch {
				case !isMacOSJavaStub(bin) && isExecutableFile(sibling):
					info.JavacPath = sibling
				case isExecutableFile(sibling):
					// macOS /usr/bin/java stub: verify /usr/bin/javac major version matches before pairing.
					javaMajor := parseJavaMajor(ver)
					javacMajor := probeJavacMajor(sibling)
					if javacMajor == 0 || javaMajor == 0 || javacMajor == javaMajor {
						info.JavacPath = sibling
					}
				default:
					if p, err := exec.LookPath("javac"); err == nil {
						// Pair with PATH javac only when major versions match (or javac version is unparseable, e.g. mock script).
						javaMajor := parseJavaMajor(ver)
						javacMajor := probeJavacMajor(p)
						if javacMajor == 0 || javaMajor == 0 || javacMajor == javaMajor {
							info.JavacPath = p
						}
					}
				}
				return
			}
		}
		info.Java.Path = preferred
		info.Java.Issue = fmt.Sprintf("java not working at configured path %s — install with: %s", preferred, info.Java.Install)
		return
	}

	cands := buildJavaCandidates()
	if len(cands) == 0 {
		info.Java.Issue = fmt.Sprintf("java runtime not found (required for Unidbg) — install with: %s", info.Java.Install)
		return
	}

	results := make([]javaCandidateProbe, len(cands))
	sem := make(chan struct{}, probeWorkerPoolSize)
	var wg sync.WaitGroup
	for i, bin := range cands {
		wg.Add(1)
		go func(idx int, path string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			stub := isMacOSJavaStub(path)
			sibling := filepath.Join(filepath.Dir(path), executableName("javac"))
			hasSibling := !stub && isExecutableFile(sibling)
			ver, ok := probeJavaVersion(path)
			results[idx] = javaCandidateProbe{
				idx:             idx,
				path:            path,
				version:         ver,
				major:           parseJavaMajor(ver),
				isStub:          stub,
				hasSiblingJavac: hasSibling,
				siblingJavac:    sibling,
				ok:              ok,
			}
		}(i, bin)
	}
	wg.Wait()

	var valid []javaCandidateProbe
	for _, r := range results {
		if r.ok {
			valid = append(valid, r)
		}
	}
	if len(valid) == 0 {
		info.Java.Path = cands[0]
		info.Java.Issue = fmt.Sprintf("java runtime not found (required for Unidbg) — install with: %s", info.Java.Install)
		return
	}

	sort.SliceStable(valid, func(i, j int) bool {
		a, b := valid[i], valid[j]
		ta, tb := javaCandidateTier(a), javaCandidateTier(b)
		if ta != tb {
			return ta > tb
		}
		ra, rb := javaVersionRank(a.major), javaVersionRank(b.major)
		if ra != rb {
			return ra > rb
		}
		if a.version != b.version {
			return compareVersionStringsDesc(a.version, b.version)
		}
		return a.idx < b.idx
	})

	best := valid[0]
	info.Java.Path = best.path
	info.Java.Version = best.version
	info.Java.Ready = true

	if best.hasSiblingJavac {
		info.JavacPath = best.siblingJavac
		info.JavaHome = deriveJavaHome(best.path)
		return
	}
	if best.isStub {
		// Last-resort fallback when no real JDK was found: only pair /usr/bin/javac if major version matches.
		sibling := filepath.Join(filepath.Dir(best.path), executableName("javac"))
		if isExecutableFile(sibling) {
			javacMajor := probeJavacMajor(sibling)
			if javacMajor == 0 || best.major == 0 || javacMajor == best.major {
				info.JavacPath = sibling
			}
		}
		return
	}
	// JRE-only installation (missing sibling javac): NEVER silently pair with an unrelated /usr/bin/javac.
	info.JavaHome = deriveJavaHome(best.path)
}

func buildJavaCandidates() []string {
	var out []string
	seenAbs := make(map[string]bool)
	seenReal := make(map[string]bool)

	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if !isExecutableFile(p) {
			return
		}
		abs := p
		if a, err := filepath.Abs(p); err == nil {
			abs = a
		}
		if seenAbs[abs] {
			return
		}
		if !isMacOSJavaStub(abs) {
			if realPath, err := filepath.EvalSymlinks(abs); err == nil && realPath != "" {
				if seenReal[realPath] {
					return
				}
				seenReal[realPath] = true
			}
		}
		seenAbs[abs] = true
		out = append(out, abs)
	}

	// 1. JAVA_HOME/bin/java (if set)
	if jh := strings.TrimSpace(os.Getenv("JAVA_HOME")); jh != "" {
		add(filepath.Join(jh, "bin", executableName("java")))
	}

	// 2. Dynamic JVM / Homebrew / Linux JVM globs
	for _, pattern := range javaSearchGlobs {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		sort.Strings(matches)
		for _, m := range matches {
			add(m)
		}
	}

	// 3. Explicit PATH scan (every entry) + standard bin directories
	if resolved, err := exec.LookPath("java"); err == nil {
		add(resolved)
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		dir = strings.TrimSpace(dir)
		if dir != "" {
			add(filepath.Join(dir, executableName("java")))
		}
	}
	for _, dir := range javaExtraDirs {
		add(filepath.Join(dir, executableName("java")))
	}

	return out
}

func isMacOSJavaStub(p string) bool {
	return runtime.GOOS == "darwin" && filepath.Clean(p) == "/usr/bin/java"
}

func deriveJavaHome(javaBin string) string {
	clean := filepath.Clean(strings.TrimSpace(javaBin))
	if clean == "" || isMacOSJavaStub(clean) {
		return ""
	}
	homeFromBin := func(p string) string {
		dir := filepath.Dir(p)
		if strings.EqualFold(filepath.Base(dir), "bin") {
			parent := filepath.Dir(dir)
			switch filepath.Clean(parent) {
			case "/", "/usr", "/usr/local", "/opt/homebrew":
				return ""
			default:
				return parent
			}
		}
		return ""
	}
	if h := homeFromBin(clean); h != "" {
		return h
	}
	if resolved, err := filepath.EvalSymlinks(clean); err == nil && resolved != "" && resolved != clean {
		if h := homeFromBin(filepath.Clean(resolved)); h != "" {
			return h
		}
	}
	return ""
}

func javaCandidateTier(c javaCandidateProbe) int {
	if c.hasSiblingJavac && !c.isStub {
		return 2
	}
	if c.isStub {
		return 1
	}
	return 0
}

// javaVersionRank ranks Unidbg-compatible LTS JDKs highest: 17 > 11 > 8 > 21 > 22+/other.
func javaVersionRank(major int) int {
	switch major {
	case 17:
		return 100
	case 11:
		return 90
	case 8:
		return 80
	case 21:
		return 60
	default:
		if major > 0 {
			return 40
		}
		return 20
	}
}

func parseJavaMajor(ver string) int {
	ver = strings.TrimSpace(ver)
	if ver == "" {
		return 0
	}
	// Legacy Java 1.8.0_291 -> major 8
	if strings.HasPrefix(ver, "1.") {
		rest := strings.TrimPrefix(ver, "1.")
		parts := strings.FieldsFunc(rest, func(r rune) bool { return r < '0' || r > '9' })
		if len(parts) > 0 {
			if n, err := strconv.Atoi(parts[0]); err == nil {
				return n
			}
		}
	}
	parts := strings.FieldsFunc(ver, func(r rune) bool { return r < '0' || r > '9' })
	if len(parts) > 0 {
		if n, err := strconv.Atoi(parts[0]); err == nil {
			return n
		}
	}
	return 0
}

func probeJavacMajor(javacBin string) int {
	ctx, cancel := context.WithTimeout(context.Background(), toolchainProbeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, javacBin, "-version")
	configureProcGroup(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return 0
	}
	text := string(out)
	if ver := extractVersionString(text); ver != "" {
		return parseJavaMajor(ver)
	}
	return 0
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
			if isRuntimeJarName(filepath.Base(absPath)) {
				info.Unidbg.Ready = true
				info.Unidbg.Path = absPath
				info.Unidbg.Version = extractVersionFromName(filepath.Base(absPath), "jar")
				info.UnidbgJars = []string{absPath}
				info.UnidbgMode = UnidbgModeFatJar
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
			info.UnidbgMode = classifyUnidbgDir(absPath, jars, hasPom)
			if pomVer != "" {
				info.Unidbg.Version = pomVer
			} else if info.UnidbgMode == UnidbgModeM2Cache {
				info.Unidbg.Version = filepath.Base(absPath)
			} else if len(jars) > 0 {
				info.Unidbg.Version = extractVersionFromName(filepath.Base(jars[0]), "jar")
			} else {
				info.Unidbg.Version = "maven-project"
			}
			return
		}
	}

	// Case C: Auto-discovery fallback to ~/.m2/repository/com/github/zhkl0228/unidbg-android
	if preferred == "" {
		m2Dir := resolveUnidbgM2Dir()
		if verDir, ver, jarPath, ok := probeUnidbgM2Cache(m2Dir); ok {
			info.Unidbg.Ready = true
			info.Unidbg.Path = verDir
			info.Unidbg.Version = ver
			info.UnidbgJars = []string{jarPath}
			info.UnidbgMode = UnidbgModeM2Cache
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

func resolveUnidbgM2Dir() string {
	if strings.TrimSpace(m2RepoOverride) != "" {
		return filepath.Join(m2RepoOverride, "com", "github", "zhkl0228", "unidbg-android")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".m2", "repository", "com", "github", "zhkl0228", "unidbg-android")
	}
	return ""
}

func probeUnidbgM2Cache(m2UnidbgDir string) (verDir, ver, jarPath string, ok bool) {
	if strings.TrimSpace(m2UnidbgDir) == "" {
		return "", "", "", false
	}
	entries, err := os.ReadDir(m2UnidbgDir)
	if err != nil {
		return "", "", "", false
	}
	type m2Cand struct {
		ver     string
		dir     string
		jarPath string
	}
	var found []m2Cand
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		v := e.Name()
		d := filepath.Join(m2UnidbgDir, v)
		jar, hasPom := findM2ArtifactFiles(d, v)
		if jar != "" && hasPom {
			found = append(found, m2Cand{ver: v, dir: d, jarPath: jar})
		}
	}
	if len(found) == 0 {
		return "", "", "", false
	}
	sort.Slice(found, func(i, j int) bool {
		return compareVersionStringsDesc(found[i].ver, found[j].ver)
	})
	best := found[0]
	absDir := best.dir
	if abs, err := filepath.Abs(best.dir); err == nil {
		absDir = abs
	}
	absJar := best.jarPath
	if abs, err := filepath.Abs(best.jarPath); err == nil {
		absJar = abs
	}
	return absDir, best.ver, absJar, true
}

func findM2ArtifactFiles(dir, ver string) (jarPath string, hasPom bool) {
	exactJar := filepath.Join(dir, fmt.Sprintf("unidbg-android-%s.jar", ver))
	exactPom := filepath.Join(dir, fmt.Sprintf("unidbg-android-%s.pom", ver))
	if isRegularFile(exactJar) && isRegularFile(exactPom) {
		return exactJar, true
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", false
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		low := strings.ToLower(name)
		if strings.HasSuffix(low, ".pom") && strings.HasPrefix(low, "unidbg-android-") {
			hasPom = true
		}
		if isRuntimeJarName(name) && strings.HasPrefix(low, "unidbg-android-") && jarPath == "" {
			jarPath = filepath.Join(dir, name)
		}
	}
	return jarPath, hasPom
}

type pyProbeResult struct {
	idx       int
	path      string
	pyVer     string
	qilingVer string
	angrVer   string
	ok        bool
}

func probePythonToolchain(cfg ToolchainConfig, info *ToolchainInfo) {
	baseOverride := strings.TrimSpace(cfg.PythonPath)
	qilingOverride := strings.TrimSpace(cfg.QilingPythonPath)
	angrOverride := strings.TrimSpace(cfg.AngrPythonPath)

	// Helper to probe a single explicit Python path.
	probeSingle := func(path string) *pyProbeResult {
		cands := buildPythonCandidates(path)
		if len(cands) == 0 {
			return nil
		}
		py := cands[0]
		pyVer, qVer, aVer, ok := probePythonModules(py)
		if !ok {
			return &pyProbeResult{path: py, ok: false}
		}
		return &pyProbeResult{
			path:      py,
			pyVer:     pyVer,
			qilingVer: qVer,
			angrVer:   aVer,
			ok:        true,
		}
	}

	var (
		baseBest   *pyProbeResult
		qilingBest *pyProbeResult
		angrBest   *pyProbeResult
	)

	if baseOverride != "" {
		// Strict mode: honor cfg.PythonPath deterministically (keeps hermetic unit tests deterministic),
		// while still honoring explicit per-engine overrides if provided.
		var wg sync.WaitGroup
		var baseRes, qRes, aRes *pyProbeResult
		wg.Add(1)
		go func() { defer wg.Done(); baseRes = probeSingle(baseOverride) }()
		if qilingOverride != "" {
			wg.Add(1)
			go func() { defer wg.Done(); qRes = probeSingle(qilingOverride) }()
		}
		if angrOverride != "" {
			wg.Add(1)
			go func() { defer wg.Done(); aRes = probeSingle(angrOverride) }()
		}
		wg.Wait()

		if baseRes != nil && baseRes.ok {
			baseBest = baseRes
		}
		if qilingOverride != "" {
			qilingBest = qRes
		} else {
			qilingBest = baseBest
		}
		if angrOverride != "" {
			angrBest = aRes
		} else {
			angrBest = baseBest
		}
	} else {
		// Auto-discovery mode: scan host interpreters concurrently (pool of 6) and
		// select the best Qiling Python and best angr Python independently.
		cands := buildPythonCandidates("")

		// Also probe explicit per-engine overrides concurrently if present.
		var (
			qOverrideRes *pyProbeResult
			aOverrideRes *pyProbeResult
			results      = make([]pyProbeResult, len(cands))
			sem          = make(chan struct{}, probeWorkerPoolSize)
			wg           sync.WaitGroup
		)
		if qilingOverride != "" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				qOverrideRes = probeSingle(qilingOverride)
			}()
		}
		if angrOverride != "" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				aOverrideRes = probeSingle(angrOverride)
			}()
		}
		for i, py := range cands {
			wg.Add(1)
			go func(idx int, pyPath string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				pyVer, qVer, aVer, ok := probePythonModules(pyPath)
				results[idx] = pyProbeResult{
					idx:       idx,
					path:      pyPath,
					pyVer:     pyVer,
					qilingVer: qVer,
					angrVer:   aVer,
					ok:        ok,
				}
			}(i, py)
		}
		wg.Wait()

		bestBaseScore := -1
		bestQScore := -1
		bestAScore := -1
		for i := range results {
			r := &results[i]
			if !r.ok {
				continue
			}
			isShim := strings.Contains(r.path, string(filepath.Separator)+".pyenv"+string(filepath.Separator)+"shims"+string(filepath.Separator))
			baseScore := 10
			if r.qilingVer != "" {
				baseScore += 20
			}
			if r.angrVer != "" {
				baseScore += 20
			}
			if !isShim {
				baseScore += 5
			}
			if baseScore > bestBaseScore {
				bestBaseScore = baseScore
				baseBest = r
			}

			if qilingOverride == "" && r.qilingVer != "" {
				qScore := 10
				if r.angrVer != "" {
					qScore += 5
				}
				if !isShim {
					qScore += 3
				}
				if qScore > bestQScore {
					bestQScore = qScore
					qilingBest = r
				}
			}
			if angrOverride == "" && r.angrVer != "" {
				aScore := 10
				if r.qilingVer != "" {
					aScore += 5
				}
				if !isShim {
					aScore += 3
				}
				if aScore > bestAScore {
					bestAScore = aScore
					angrBest = r
				}
			}
		}

		if qilingOverride != "" {
			qilingBest = qOverrideRes
		} else if qilingBest == nil {
			qilingBest = baseBest
		}
		if angrOverride != "" {
			angrBest = aOverrideRes
		} else if angrBest == nil {
			angrBest = baseBest
		}
		if baseBest == nil {
			if qilingBest != nil && qilingBest.ok {
				baseBest = qilingBest
			} else if angrBest != nil && angrBest.ok {
				baseBest = angrBest
			}
		}
	}

	// Populate base Python status.
	if baseBest != nil && baseBest.ok {
		info.Python.Ready = true
		info.Python.Path = baseBest.path
		info.Python.Version = baseBest.pyVer
	} else if baseOverride != "" {
		info.Python.Path = baseOverride
		info.Python.Issue = fmt.Sprintf("python3 not working at configured path %s — install with: %s", baseOverride, info.Python.Install)
	} else {
		info.Python.Issue = fmt.Sprintf("python3 not found (required for Qiling & angr) — install with: %s", info.Python.Install)
	}

	// Populate Qiling status independently.
	if qilingBest != nil && qilingBest.ok {
		info.Qiling.Path = qilingBest.path
		if qilingBest.qilingVer != "" {
			info.Qiling.Ready = true
			info.Qiling.Version = qilingBest.qilingVer
		} else {
			info.Qiling.Issue = fmt.Sprintf("Python `qiling` module not installed in %s — install with: %s -m pip install qiling", qilingBest.path, qilingBest.path)
		}
	} else if qilingOverride != "" {
		info.Qiling.Path = qilingOverride
		info.Qiling.Issue = fmt.Sprintf("Qiling python3 not working at configured path %s — install with: %s", qilingOverride, info.Qiling.Install)
	} else {
		info.Qiling.Issue = fmt.Sprintf("qiling unavailable without Python 3 — install with: %s", info.Qiling.Install)
	}

	// Populate angr status independently.
	if angrBest != nil && angrBest.ok {
		info.Angr.Path = angrBest.path
		if angrBest.angrVer != "" {
			info.Angr.Ready = true
			info.Angr.Version = angrBest.angrVer
		} else {
			info.Angr.Issue = fmt.Sprintf("Python `angr` module not installed in %s — install with: %s -m pip install angr", angrBest.path, angrBest.path)
		}
	} else if angrOverride != "" {
		info.Angr.Path = angrOverride
		info.Angr.Issue = fmt.Sprintf("angr python3 not working at configured path %s — install with: %s", angrOverride, info.Angr.Install)
	} else {
		info.Angr.Issue = fmt.Sprintf("angr unavailable without Python 3 — install with: %s", info.Angr.Install)
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
	ctx, cancel := context.WithTimeout(context.Background(), pythonProbeTimeout)
	defer cancel()
	// Use fast importlib.util.find_spec + importlib.metadata.version first (avoids ~2.5s
	// cold import of angr/z3 during discovery), falling back to __import__ when needed.
	const snippet = `import sys
print("PY=" + ".".join(map(str, sys.version_info[:3])))
try:
    import importlib.util as iu
except Exception:
    iu = None
try:
    import importlib.metadata as im
except Exception:
    im = None
for mod, key in (("qiling", "QILING"), ("angr", "ANGR")):
    ver = ""
    if iu is not None:
        try:
            spec = iu.find_spec(mod)
        except Exception:
            spec = None
        if spec is not None:
            if im is not None:
                try:
                    ver = im.version(mod) or ""
                except Exception:
                    ver = ""
            if not ver:
                try:
                    m = __import__(mod)
                    ver = getattr(m, "__version__", "") or "installed"
                except Exception:
                    ver = ""
    else:
        try:
            m = __import__(mod)
            ver = getattr(m, "__version__", "") or "installed"
        except Exception:
            ver = ""
    print(key + "=" + str(ver))
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

func isRuntimeJarName(name string) bool {
	low := strings.ToLower(strings.TrimSpace(name))
	if !strings.HasSuffix(low, ".jar") {
		return false
	}
	if strings.HasSuffix(low, "-sources.jar") ||
		strings.HasSuffix(low, "-javadoc.jar") ||
		strings.HasSuffix(low, "-tests.jar") ||
		strings.HasSuffix(low, "-test-sources.jar") ||
		strings.HasPrefix(low, "original-") {
		return false
	}
	return true
}

func isShadedFatJarName(name string) bool {
	low := strings.ToLower(strings.TrimSpace(name))
	if !isRuntimeJarName(low) {
		return false
	}
	return strings.Contains(low, "-jar-with-dependencies") ||
		strings.Contains(low, "-shaded") ||
		strings.HasSuffix(low, "-all.jar") ||
		strings.Contains(low, "-all-") ||
		strings.HasSuffix(low, "-fat.jar") ||
		strings.Contains(low, "-fat-")
}

func countBundledDepJars(dir string) int {
	depDirs := []string{
		filepath.Join(dir, "lib"),
		filepath.Join(dir, "libs"),
		filepath.Join(dir, "target", "dependency"),
		filepath.Join(dir, "unidbg-android", "target", "dependency"),
	}
	seen := make(map[string]bool)
	for _, d := range depDirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !isRuntimeJarName(e.Name()) {
				continue
			}
			seen[filepath.Join(d, e.Name())] = true
		}
	}
	return len(seen)
}

func classifyUnidbgDir(dir string, jars []string, hasPom bool) string {
	if hasPom {
		for _, j := range jars {
			if isShadedFatJarName(filepath.Base(j)) {
				return UnidbgModeJarBundle
			}
		}
		if countBundledDepJars(dir) >= 5 {
			return UnidbgModeJarBundle
		}
		return UnidbgModeMavenRepo
	}
	if len(jars) > 0 {
		if jar, hasM2Pom := findM2ArtifactFiles(dir, filepath.Base(dir)); jar != "" && hasM2Pom && len(jars) == 1 {
			return UnidbgModeM2Cache
		}
		return UnidbgModeJarBundle
	}
	return ""
}

func collectUnidbgJars(dir string) []string {
	searchDirs := []string{
		dir,
		filepath.Join(dir, "lib"),
		filepath.Join(dir, "libs"),
		filepath.Join(dir, "target"),
		filepath.Join(dir, "target", "dependency"),
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
			if !isRuntimeJarName(name) {
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
		if !strings.ContainsAny(p, `/\`) {
			resolved, err := exec.LookPath(p)
			if err != nil {
				return
			}
			p = resolved
		} else if !isExecutableFile(p) {
			return
		}
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	addGlob := func(pattern string, filterPythonName bool) {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return
		}
		sort.Strings(matches)
		for _, m := range matches {
			if filterPythonName && !pythonBinNameRe.MatchString(strings.ToLower(filepath.Base(m))) {
				continue
			}
			add(m)
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
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		dir = strings.TrimSpace(dir)
		if dir != "" {
			add(filepath.Join(dir, executableName("python3")))
		}
	}

	for _, p := range []string{
		"/opt/homebrew/bin/python3",
		"/usr/local/bin/python3",
		"/usr/bin/python3",
	} {
		add(p)
	}
	addGlob("/opt/homebrew/opt/python@*/bin/python3*", true)
	addGlob("/usr/local/opt/python@*/bin/python3*", true)

	// macOS Python.org framework installs (skip "Current" symlink to avoid duplicate probe).
	if matches, err := filepath.Glob("/Library/Frameworks/Python.framework/Versions/*/bin/python3"); err == nil {
		sort.Strings(matches)
		for _, m := range matches {
			if strings.Contains(m, "/Versions/Current/") {
				continue
			}
			add(m)
		}
	}

	if home, err := os.UserHomeDir(); err == nil && home != "" {
		// Concrete pyenv versions first, then shims as fallback.
		addGlob(filepath.Join(home, ".pyenv", "versions", "*", "bin", executableName("python3")), false)
		add(filepath.Join(home, ".pyenv", "shims", executableName("python3")))

		for _, condaRoot := range []string{
			filepath.Join(home, "miniconda3"),
			filepath.Join(home, "miniforge3"),
			filepath.Join(home, "anaconda3"),
			filepath.Join(home, "opt", "anaconda3"),
		} {
			add(filepath.Join(condaRoot, "bin", executableName("python3")))
			addGlob(filepath.Join(condaRoot, "envs", "*", "bin", executableName("python3")), false)
		}

		addGlob(filepath.Join(home, ".virtualenvs", "*", "bin", executableName("python3")), false)
		addGlob(filepath.Join(home, ".cap", "venv*", "bin", executableName("python3")), false)
	}

	return out
}

func compareVersionStringsDesc(a, b string) bool {
	pa, snapA := splitVersionNumbers(a)
	pb, snapB := splitVersionNumbers(b)
	maxLen := len(pa)
	if len(pb) > maxLen {
		maxLen = len(pb)
	}
	for i := 0; i < maxLen; i++ {
		va, vb := 0, 0
		if i < len(pa) {
			va = pa[i]
		}
		if i < len(pb) {
			vb = pb[i]
		}
		if va != vb {
			return va > vb
		}
	}
	// Release beats SNAPSHOT when numeric tuple matches.
	if snapA != snapB {
		return !snapA
	}
	return a > b
}

func splitVersionNumbers(v string) ([]int, bool) {
	low := strings.ToLower(strings.TrimSpace(v))
	isSnap := strings.Contains(low, "snapshot")
	fields := strings.FieldsFunc(low, func(r rune) bool { return r < '0' || r > '9' })
	nums := make([]int, 0, len(fields))
	for _, f := range fields {
		if n, err := strconv.Atoi(f); err == nil {
			nums = append(nums, n)
		}
	}
	return nums, isSnap
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

func isRegularFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}
