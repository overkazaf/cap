package recon

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

const toolchainProbeTimeout = 3 * time.Second

var reconSemverRe = regexp.MustCompile(`v?(\d+\.\d+(?:\.\d+)?(?:[-._][0-9A-Za-z]+)?)`)

// DetectToolchain concurrently probes the host for nmap, subfinder, whois, and dig
// across cfg overrides, PATH, /usr/local/bin, /opt/homebrew/bin, ~/go/bin, and ~/.local/bin.
func DetectToolchain(cfg ToolchainConfig) ToolchainInfo {
	info := ToolchainInfo{
		Nmap: ToolStatus{
			Name:    "nmap",
			Install: "brew install nmap (macOS) or https://nmap.org/download.html",
		},
		Subfinder: ToolStatus{
			Name:    "subfinder",
			Install: "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
		},
		Whois: ToolStatus{
			Name:    "whois",
			Install: "brew install whois (macOS) or apt install whois (Linux)",
		},
		Dig: ToolStatus{
			Name:    "dig",
			Install: "brew install bind (macOS) or apt install dnsutils (Linux)",
		},
		CheckedAt: nowRFC3339(),
	}

	var wg sync.WaitGroup
	wg.Add(4)
	go func() {
		defer wg.Done()
		probeNmap(&info.Nmap, cfg.NmapPath)
	}()
	go func() {
		defer wg.Done()
		probeSubfinder(&info.Subfinder, cfg.SubfinderPath)
	}()
	go func() {
		defer wg.Done()
		probeWhois(&info.Whois, cfg.WhoisPath)
	}()
	go func() {
		defer wg.Done()
		probeDig(&info.Dig, cfg.DigPath)
	}()
	wg.Wait()

	for _, ts := range []ToolStatus{info.Nmap, info.Subfinder, info.Whois, info.Dig} {
		if ts.Issue != "" {
			info.Issues = append(info.Issues, ts.Issue)
		}
	}
	return info
}

func probeNmap(st *ToolStatus, preferred string) {
	preferred = strings.TrimSpace(preferred)
	cands := buildToolCandidates(preferred, "nmap")
	for _, bin := range cands {
		if st.Path == "" {
			st.Path = bin
		}
		if out, ok := runVersionProbe(bin, "--version"); ok {
			st.Path = bin
			st.Version = extractToolVersion(out)
			st.Ready = true
			return
		}
	}
	if preferred != "" {
		st.Path = preferred
		st.Issue = fmt.Sprintf("nmap not working at configured path %s — install with: %s", preferred, st.Install)
	} else {
		st.Issue = fmt.Sprintf("nmap not found (pure-Go native TCP scanner remains available) — install with: %s", st.Install)
	}
}

func probeSubfinder(st *ToolStatus, preferred string) {
	preferred = strings.TrimSpace(preferred)
	cands := buildToolCandidates(preferred, "subfinder")
	for _, bin := range cands {
		if st.Path == "" {
			st.Path = bin
		}
		if out, ok := runVersionProbe(bin, "-version"); ok {
			st.Path = bin
			st.Version = extractToolVersion(out)
			st.Ready = true
			return
		}
	}
	if preferred != "" {
		st.Path = preferred
		st.Issue = fmt.Sprintf("subfinder not working at configured path %s — install with: %s", preferred, st.Install)
	} else {
		st.Issue = fmt.Sprintf("subfinder not found (CT log + common DNS discovery remain available) — install with: %s", st.Install)
	}
}

func probeWhois(st *ToolStatus, preferred string) {
	preferred = strings.TrimSpace(preferred)
	cands := buildToolCandidates(preferred, "whois")
	for _, bin := range cands {
		if st.Path == "" {
			st.Path = bin
		}
		if out, ok := runVersionProbe(bin, "--version"); ok {
			st.Path = bin
			st.Version = extractToolVersion(out)
			st.Ready = true
			return
		}
		// BSD/macOS /usr/bin/whois does not support --version and exits non-zero;
		// accept any verified executable binary as ready.
		if isExecutableFile(bin) {
			st.Path = bin
			st.Version = "system"
			st.Ready = true
			return
		}
	}
	if preferred != "" {
		st.Path = preferred
		st.Issue = fmt.Sprintf("whois not found or not executable at configured path %s — install with: %s", preferred, st.Install)
	} else {
		st.Issue = fmt.Sprintf("whois not found — install with: %s", st.Install)
	}
}

func probeDig(st *ToolStatus, preferred string) {
	preferred = strings.TrimSpace(preferred)
	cands := buildToolCandidates(preferred, "dig")
	for _, bin := range cands {
		if st.Path == "" {
			st.Path = bin
		}
		if out, ok := runVersionProbe(bin, "-v"); ok {
			st.Path = bin
			st.Version = extractToolVersion(out)
			st.Ready = true
			return
		}
	}
	if preferred != "" {
		st.Path = preferred
		st.Issue = fmt.Sprintf("dig not working at configured path %s — install with: %s", preferred, st.Install)
	} else {
		st.Issue = fmt.Sprintf("dig not found (pure-Go DNS resolver remains available) — install with: %s", st.Install)
	}
}

func resolveToolBinary(preferred, name string) (string, bool) {
	preferred = strings.TrimSpace(preferred)
	cands := buildToolCandidates(preferred, name)
	for _, bin := range cands {
		if isExecutableFile(bin) {
			return bin, true
		}
	}
	return "", false
}

func buildToolCandidates(preferred string, names ...string) []string {
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

	// Explicit override: strictly honor only the configured path.
	if strings.TrimSpace(preferred) != "" {
		add(preferred)
		return out
	}

	for _, name := range names {
		add(name)
	}

	dirs := []string{
		"/usr/local/bin",
		"/opt/homebrew/bin",
		"/usr/bin",
	}
	if gopath := strings.TrimSpace(os.Getenv("GOPATH")); gopath != "" {
		for _, gp := range filepath.SplitList(gopath) {
			if strings.TrimSpace(gp) != "" {
				dirs = append(dirs, filepath.Join(gp, "bin"))
			}
		}
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		dirs = append(dirs,
			filepath.Join(home, "go", "bin"),
			filepath.Join(home, ".local", "bin"),
		)
	}
	for _, dir := range dirs {
		for _, name := range names {
			add(filepath.Join(dir, executableName(name)))
		}
	}
	return out
}

func runVersionProbe(bin string, args ...string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), toolchainProbeTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	configureProcGroup(cmd)
	raw, err := cmd.CombinedOutput()
	out := strings.TrimSpace(string(raw))
	if err != nil {
		return out, false
	}
	return out, true
}

func extractToolVersion(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "available"
	}
	if m := reconSemverRe.FindStringSubmatch(raw); len(m) >= 2 {
		return m[1]
	}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			if len(line) > 80 {
				return line[:80]
			}
			return line
		}
	}
	return "available"
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
