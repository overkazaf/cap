package trace

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	jadxCacheMetaFile = ".cap-jadx-cache.json"
	apkCacheMetaFile  = ".cap-apk-cache.json"
	fingerprintChunk  = 64 * 1024
)

// apkFingerprint uniquely identifies an APK file by size, mtime, and partial
// SHA-256 of its leading and trailing 64 KiB (fast even on 200MB APKs).
type apkFingerprint struct {
	Key         string `json:"key"`
	Size        int64  `json:"size"`
	ModTimeUnix int64  `json:"mod_time_unix"`
}

type jadxCacheMeta struct {
	APKKey          string `json:"apk_key"`
	APKSize         int64  `json:"apk_size"`
	JavaFiles       int    `json:"java_files"`
	PartialWarnings string `json:"partial_warnings,omitempty"`
	UpdatedAt       int64  `json:"updated_at"`
}

type apkPullCacheMeta struct {
	Package        string   `json:"package"`
	RemoteBasePath string   `json:"remote_base_path"`
	RemoteStamp    string   `json:"remote_stamp"`
	LocalBasePath  string   `json:"local_base_path"`
	SplitPaths     []string `json:"split_paths,omitempty"`
}

func computeAPKFingerprint(apkPath string) (apkFingerprint, error) {
	f, err := os.Open(apkPath)
	if err != nil {
		return apkFingerprint{}, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return apkFingerprint{}, err
	}

	h := sha256.New()
	fmt.Fprintf(h, "%d:%d:", st.Size(), st.ModTime().UnixNano())

	buf := make([]byte, fingerprintChunk)
	n, _ := io.ReadFull(f, buf)
	if n > 0 {
		h.Write(buf[:n])
	}
	if st.Size() > int64(fingerprintChunk) {
		if _, err := f.Seek(-int64(fingerprintChunk), io.SeekEnd); err == nil {
			n2, _ := io.ReadFull(f, buf)
			if n2 > 0 {
				h.Write(buf[:n2])
			}
		}
	}

	sum := hex.EncodeToString(h.Sum(nil))
	return apkFingerprint{
		Key:         sum[:16],
		Size:        st.Size(),
		ModTimeUnix: st.ModTime().Unix(),
	}, nil
}

func readJadxCache(jadxDir string) (*jadxCacheMeta, bool) {
	data, err := os.ReadFile(filepath.Join(jadxDir, jadxCacheMetaFile))
	if err != nil {
		return nil, false
	}
	var m jadxCacheMeta
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, false
	}
	return &m, true
}

func writeJadxCache(jadxDir string, m jadxCacheMeta) {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(jadxDir, jadxCacheMetaFile), data, 0o644)
}

func readAPKPullCache(pkgDir string) (*apkPullCacheMeta, bool) {
	data, err := os.ReadFile(filepath.Join(pkgDir, apkCacheMetaFile))
	if err != nil {
		return nil, false
	}
	var m apkPullCacheMeta
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, false
	}
	return &m, true
}

func writeAPKPullCache(pkgDir string, m apkPullCacheMeta) {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(pkgDir, apkCacheMetaFile), data, 0o644)
}

// sanitizeCacheSegment turns a package name or identifier into a safe single
// directory segment under Options.OutputDir.
func sanitizeCacheSegment(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "default"
	}
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), ".")
	if out == "" {
		return "default"
	}
	return out
}

// countJavaFiles counts .java files under dir, stopping early if maxCount > 0
// and that threshold is reached.
func countJavaFiles(dir string) int {
	count := 0
	_ = filepath.Walk(dir, func(path string, fi os.FileInfo, err error) error {
		if err == nil && fi != nil && !fi.IsDir() && strings.HasSuffix(path, ".java") {
			count++
		}
		return nil
	})
	return count
}

// jadxProgressCallback reports live progress parsed from jadx stdout/stderr.
type jadxProgressCallback func(pct int, detail string)

type jadxRunResult struct {
	OutDir          string
	Cached          bool
	JavaFiles       int
	Partial         bool
	PartialWarnings string
}

var (
	jadxPercentRe = regexp.MustCompile(`(?i)progress:\s*(\d{1,3})\s*%`)
	jadxRatioRe   = regexp.MustCompile(`\((\d+)\s*(?:of|/)\s*(\d+)\)`)
	jadxInfoRe    = regexp.MustCompile(`(?i)\bINFO\s*-\s*(.+)$`)
)

// ParseJadxProgress extracts a percentage (0..100) and human-readable detail
// from a single line of jadx output.
func ParseJadxProgress(line string) (pct int, detail string, ok bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return 0, "", false
	}
	if m := jadxPercentRe.FindStringSubmatch(trimmed); len(m) >= 2 {
		v, err := strconv.Atoi(m[1])
		if err == nil {
			if v < 0 {
				v = 0
			}
			if v > 100 {
				v = 100
			}
			detail = fmt.Sprintf("jadx decompiling %d%%", v)
			if rm := jadxRatioRe.FindStringSubmatch(trimmed); len(rm) >= 3 {
				detail = fmt.Sprintf("jadx decompiling %d%% (%s/%s classes)", v, rm[1], rm[2])
			}
			return v, detail, true
		}
	}
	if rm := jadxRatioRe.FindStringSubmatch(trimmed); len(rm) >= 3 {
		cur, err1 := strconv.Atoi(rm[1])
		tot, err2 := strconv.Atoi(rm[2])
		if err1 == nil && err2 == nil && tot > 0 {
			v := (cur * 100) / tot
			if v > 100 {
				v = 100
			}
			return v, fmt.Sprintf("jadx decompiling %d%% (%d/%d)", v, cur, tot), true
		}
	}
	if m := jadxInfoRe.FindStringSubmatch(trimmed); len(m) >= 2 {
		msg := strings.TrimSpace(m[1])
		if msg != "" {
			return -1, "jadx: " + msg, true
		}
	}
	return 0, "", false
}

// scanLinesOrCR splits scanner tokens on \n OR \r so jadx's single-line
// carriage-return progress bar updates stream immediately.
func scanLinesOrCR(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexAny(data, "\r\n"); i >= 0 {
		adv := i + 1
		if data[i] == '\r' && i+1 < len(data) && data[i+1] == '\n' {
			adv = i + 2
		}
		return adv, data[:i], nil
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}

// decompileJadxContext runs jadx with context cancellation, APK-fingerprinted
// caching, live throttled stdout/stderr progress streaming, and graceful
// acceptance of partial decompilations when jadx exits non-zero with warnings
// after producing .java source files.
func decompileJadxContext(
	ctx context.Context,
	jadxPath, apkPath, outDir string,
	timeout time.Duration,
	forceRefresh bool,
	onProgress jadxProgressCallback,
) (jadxRunResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return jadxRunResult{}, err
	}

	fp, fpErr := computeAPKFingerprint(apkPath)

	// Check cache when ForceRefresh is false.
	if !forceRefresh && fpErr == nil {
		if meta, ok := readJadxCache(outDir); ok && meta.APKKey == fp.Key && meta.JavaFiles > 0 {
			if fi, err := os.Stat(outDir); err == nil && fi.IsDir() {
				return jadxRunResult{
					OutDir:          outDir,
					Cached:          true,
					JavaFiles:       meta.JavaFiles,
					Partial:         meta.PartialWarnings != "",
					PartialWarnings: meta.PartialWarnings,
				}, nil
			}
		}
	}

	if forceRefresh {
		_ = os.RemoveAll(outDir)
	}

	if timeout <= 0 {
		timeout = defaultJadxTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, jadxPath, "-d", outDir, "--no-res", apkPath)
	configureCancellableCmd(cmd)

	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw

	if err := cmd.Start(); err != nil {
		_ = pw.Close()
		_ = pr.Close()
		return jadxRunResult{}, fmt.Errorf("jadx start: %w", err)
	}

	var tailLines []string
	const maxTail = 25
	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		scanner := bufio.NewScanner(pr)
		scanner.Buffer(make([]byte, 16*1024), 512*1024)
		scanner.Split(scanLinesOrCR)

		lastEmit := time.Time{}
		lastPct := -1
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			tailLines = append(tailLines, line)
			if len(tailLines) > maxTail {
				tailLines = tailLines[len(tailLines)-maxTail:]
			}

			if onProgress != nil {
				pct, detail, ok := ParseJadxProgress(line)
				if ok {
					now := time.Now()
					pctJump := pct >= 0 && (lastPct < 0 || pct-lastPct >= 5 || pct == 100)
					timeElapsed := lastEmit.IsZero() || now.Sub(lastEmit) >= 400*time.Millisecond
					if pctJump || timeElapsed {
						if pct >= 0 {
							lastPct = pct
						}
						lastEmit = now
						onProgress(pct, detail)
					}
				}
			}
		}
	}()

	waitErr := cmd.Wait()
	_ = pw.Close()
	<-scanDone
	_ = pr.Close()

	// If caller cancelled or timed out, propagate immediately.
	if ctx.Err() != nil {
		return jadxRunResult{}, ctx.Err()
	}
	if runCtx.Err() != nil {
		return jadxRunResult{}, fmt.Errorf("jadx timed out after %s: %s", timeout, strings.Join(tailLines, "\n"))
	}

	javaFiles := countJavaFiles(outDir)

	if waitErr != nil {
		// Real obfuscated APKs frequently cause jadx to exit 1 with decompilation
		// warnings even though hundreds/thousands of .java files succeeded.
		if javaFiles > 0 {
			warn := firstNonEmptyTail(tailLines)
			if fpErr == nil {
				writeJadxCache(outDir, jadxCacheMeta{
					APKKey:          fp.Key,
					APKSize:         fp.Size,
					JavaFiles:       javaFiles,
					PartialWarnings: warn,
					UpdatedAt:       time.Now().Unix(),
				})
			}
			return jadxRunResult{
				OutDir:          outDir,
				JavaFiles:       javaFiles,
				Partial:         true,
				PartialWarnings: warn,
			}, nil
		}
		return jadxRunResult{}, fmt.Errorf("jadx: %w: %s", waitErr, strings.Join(tailLines, "\n"))
	}

	if fpErr == nil {
		writeJadxCache(outDir, jadxCacheMeta{
			APKKey:    fp.Key,
			APKSize:   fp.Size,
			JavaFiles: javaFiles,
			UpdatedAt: time.Now().Unix(),
		})
	}

	return jadxRunResult{
		OutDir:    outDir,
		JavaFiles: javaFiles,
	}, nil
}

func firstNonEmptyTail(lines []string) string {
	for i := len(lines) - 1; i >= 0; i-- {
		if s := strings.TrimSpace(lines[i]); s != "" {
			return s
		}
	}
	return "completed with warnings"
}

// parsePMPathOutput splits `adb shell pm path <pkg>` output into the base APK
// path and any ABI split APKs (prioritizing arm64_v8a > armeabi_v7a > others).
func parsePMPathOutput(out string) (basePath string, abiSplitPaths []string) {
	var allPaths []string
	for _, line := range strings.Split(out, "\n") {
		if p, ok := strings.CutPrefix(strings.TrimSpace(line), "package:"); ok {
			p = strings.TrimSpace(p)
			if p != "" {
				allPaths = append(allPaths, p)
			}
		}
	}
	if len(allPaths) == 0 {
		return "", nil
	}

	// Prefer explicit base.apk; fall back to first entry.
	baseIdx := 0
	for i, p := range allPaths {
		if filepath.Base(p) == "base.apk" {
			baseIdx = i
			break
		}
	}
	basePath = allPaths[baseIdx]

	var arm64, arm32, otherABI []string
	for i, p := range allPaths {
		if i == baseIdx {
			continue
		}
		lower := strings.ToLower(filepath.Base(p))
		switch {
		case strings.Contains(lower, "arm64"):
			arm64 = append(arm64, p)
		case strings.Contains(lower, "armeabi") || strings.Contains(lower, "arm_v7") || strings.Contains(lower, "armv7"):
			arm32 = append(arm32, p)
		case strings.Contains(lower, "x86_64") || strings.Contains(lower, "x86"):
			otherABI = append(otherABI, p)
		}
	}
	abiSplitPaths = append(abiSplitPaths, arm64...)
	abiSplitPaths = append(abiSplitPaths, arm32...)
	abiSplitPaths = append(abiSplitPaths, otherABI...)
	return basePath, abiSplitPaths
}
