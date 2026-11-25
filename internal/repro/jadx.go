package repro

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	jadxMetaFileName    = ".cap-repro-jadx.json"
	jadxProbeTimeout    = 5 * time.Second
	jadxDecompTimeout   = 5 * time.Minute
	maxJavaReadBytes    = 8 * 1024 * 1024
	maxDEXFallbackBytes = 64 * 1024 * 1024
	dexAccNative        = 0x0100
	dexAccStatic        = 0x0008
)

var (
	javaPkgDeclRe    = regexp.MustCompile(`(?m)^\s*package\s+([A-Za-z0-9_.]+)\s*;`)
	javaImportRe     = regexp.MustCompile(`(?m)^\s*import\s+(?:static\s+)?([A-Za-z0-9_.$]+)\s*;`)
	javaClassDeclRe  = regexp.MustCompile(`(?m)\b(?:class|interface|enum)\s+([A-Za-z_][A-Za-z0-9_$]*)`)
	javaNativeMethRe = regexp.MustCompile(`\bnative\b\s+(?:(?:public|private|protected|static|final|synchronized|strictfp)\s+)*(?:<[^>]+>\s+)?([A-Za-z0-9_$.\[\]<>?,\s]+?)\s+([A-Za-z_][A-Za-z0-9_$]*)\s*\(([^)]*)\)\s*(?:throws\s+[A-Za-z0-9_.,\s]+)?\s*;`)
	javaNativePreRe  = regexp.MustCompile(`\b(?:(?:public|private|protected|static|final|synchronized|strictfp)\s+)*native\b`)
)

type jadxCacheMeta struct {
	CacheKey         string   `json:"cache_key"`
	APKPath          string   `json:"apk_path"`
	Mode             string   `json:"mode"`
	ClassCount       int      `json:"class_count"`
	NativeClassCount int      `json:"native_class_count"`
	JadxVersion      string   `json:"jadx_version,omitempty"`
	Warnings         []string `json:"warnings,omitempty"`
	DecompiledAt     string   `json:"decompiled_at"`
}

// DetectJadx probes the host for a runnable jadx CLI binary, checking preferred
// first, then PATH, /usr/local/bin/jadx, and /opt/homebrew/bin/jadx.
func DetectJadx(preferred string) JadxInfo {
	var candidates []string
	seen := make(map[string]bool)
	addCand := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		candidates = append(candidates, p)
	}

	if strings.TrimSpace(preferred) != "" {
		if resolved, err := exec.LookPath(preferred); err == nil {
			addCand(resolved)
		} else {
			addCand(preferred)
		}
	}
	if p, err := exec.LookPath("jadx"); err == nil {
		addCand(p)
	}
	addCand("/usr/local/bin/jadx")
	addCand("/opt/homebrew/bin/jadx")

	var firstFoundPath, firstIssue string
	for _, cand := range candidates {
		st, err := os.Stat(cand)
		if err != nil || st.IsDir() {
			continue
		}
		if firstFoundPath == "" {
			firstFoundPath = cand
		}
		ctx, cancel := context.WithTimeout(context.Background(), jadxProbeTimeout)
		cmd := exec.CommandContext(ctx, cand, "--version")
		out, runErr := cmd.CombinedOutput()
		cancel()
		if runErr == nil {
			ver := firstNonEmptyLine(string(out))
			if ver == "" {
				ver = "unknown"
			}
			return JadxInfo{
				Available: true,
				Path:      cand,
				Version:   ver,
			}
		}
		if firstIssue == "" {
			msg := firstNonEmptyLine(string(out))
			if msg == "" {
				msg = runErr.Error()
			}
			firstIssue = fmt.Sprintf("%s --version failed: %s", cand, msg)
		}
	}

	if firstIssue == "" {
		firstIssue = "jadx binary not found in PATH, /usr/local/bin/jadx, or /opt/homebrew/bin/jadx"
	}
	return JadxInfo{
		Available: false,
		Path:      firstFoundPath,
		Issue:     firstIssue,
	}
}

// DecompileAPK decompiles an APK or DEX into a deterministic cached workspace
// directory (<cacheDir>/<sha256(path+mtime+size)>), reusing cached output on
// repeat calls. Falls back gracefully to a pure-Go ZIP/DEX class & native
// method stub extractor when jadx is absent or unavailable.
func DecompileAPK(ctx context.Context, apkPath, jadxPath, cacheDir string, maxClasses int) (*JadxWorkspace, error) {
	start := time.Now()
	if ctx == nil {
		ctx = context.Background()
	}
	apkPath = strings.TrimSpace(apkPath)
	if apkPath == "" {
		return nil, errors.New("apkPath is required")
	}
	absAPK, err := filepath.Abs(apkPath)
	if err != nil {
		return nil, fmt.Errorf("resolve apk path: %w", err)
	}
	st, err := os.Stat(absAPK)
	if err != nil {
		return nil, fmt.Errorf("stat apk: %w", err)
	}
	if st.IsDir() {
		return nil, fmt.Errorf("apkPath %q is a directory", absAPK)
	}

	if strings.TrimSpace(cacheDir) == "" {
		cacheDir = filepath.Join(os.TempDir(), "cap-repro-jadx-cache")
	}
	absCacheDir, err := filepath.Abs(cacheDir)
	if err != nil {
		return nil, fmt.Errorf("resolve cache dir: %w", err)
	}
	if err := os.MkdirAll(absCacheDir, 0o755); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}

	cacheKey := computeJadxCacheKey(absAPK, st.ModTime().UnixNano(), st.Size())
	workspaceDir := filepath.Join(absCacheDir, cacheKey)

	// Reuse existing valid cache if present.
	if meta, ok := readJadxCacheMeta(workspaceDir); ok && meta.CacheKey == cacheKey {
		if hasJavaFiles(workspaceDir) {
			return &JadxWorkspace{
				APKPath:          absAPK,
				WorkspaceDir:     workspaceDir,
				CacheKey:         cacheKey,
				CacheHit:         true,
				Mode:             meta.Mode,
				ClassCount:       meta.ClassCount,
				NativeClassCount: meta.NativeClassCount,
				JadxVersion:      meta.JadxVersion,
				Warnings:         meta.Warnings,
				DecompiledAt:     meta.DecompiledAt,
				ElapsedMs:        time.Since(start).Milliseconds(),
			}, nil
		}
	}

	if err := os.MkdirAll(workspaceDir, 0o755); err != nil {
		return nil, fmt.Errorf("create workspace dir: %w", err)
	}

	var warnings []string
	mode := WorkspaceModePureGoDEX
	jadxVersion := ""

	// Only probe jadx if caller didn't explicitly disable it with a sentinel,
	// or if caller provided a custom path probe only that path first.
	var jInfo JadxInfo
	if strings.TrimSpace(jadxPath) != "" {
		jInfo = probeSingleJadx(jadxPath)
	} else {
		jInfo = DetectJadx("")
	}

	usedJadx := false
	if jInfo.Available {
		runCtx := ctx
		var cancel context.CancelFunc
		if _, hasDeadline := ctx.Deadline(); !hasDeadline {
			runCtx, cancel = context.WithTimeout(ctx, jadxDecompTimeout)
			defer cancel()
		}
		cmd := exec.CommandContext(runCtx, jInfo.Path, "--no-res", "--deobf", "-d", workspaceDir, absAPK)
		out, runErr := cmd.CombinedOutput()
		if runErr == nil || hasJavaFiles(workspaceDir) {
			usedJadx = true
			mode = WorkspaceModeJadx
			jadxVersion = jInfo.Version
			if runErr != nil {
				warnings = append(warnings, fmt.Sprintf("jadx exited with partial warnings (%v): %s", runErr, firstNonEmptyLine(string(out))))
			}
		} else {
			warnings = append(warnings, fmt.Sprintf("jadx failed (%v), falling back to pure-Go DEX parser: %s", runErr, firstNonEmptyLine(string(out))))
		}
	} else if jInfo.Issue != "" {
		warnings = append(warnings, fmt.Sprintf("jadx unavailable (%s); using pure-Go ZIP/DEX fallback", jInfo.Issue))
	}

	if !usedJadx {
		dexWarnings, err := decompilePureGoDEXFallback(absAPK, workspaceDir, maxClasses)
		if err != nil {
			return nil, fmt.Errorf("decompile failed (jadx unavailable and pure-Go DEX fallback failed): %w", err)
		}
		warnings = append(warnings, dexWarnings...)
	}

	entries, err := ListClasses(workspaceDir, "", 0)
	if err != nil {
		return nil, fmt.Errorf("index decompiled classes: %w", err)
	}
	nativeClasses := 0
	for _, e := range entries {
		if e.HasNative {
			nativeClasses++
		}
	}

	now := nowRFC3339()
	meta := jadxCacheMeta{
		CacheKey:         cacheKey,
		APKPath:          absAPK,
		Mode:             mode,
		ClassCount:       len(entries),
		NativeClassCount: nativeClasses,
		JadxVersion:      jadxVersion,
		Warnings:         warnings,
		DecompiledAt:     now,
	}
	_ = writeJadxCacheMeta(workspaceDir, meta)

	return &JadxWorkspace{
		APKPath:          absAPK,
		WorkspaceDir:     workspaceDir,
		CacheKey:         cacheKey,
		CacheHit:         false,
		Mode:             mode,
		ClassCount:       len(entries),
		NativeClassCount: nativeClasses,
		JadxVersion:      jadxVersion,
		Warnings:         warnings,
		DecompiledAt:     now,
		ElapsedMs:        time.Since(start).Milliseconds(),
	}, nil
}

func probeSingleJadx(binPath string) JadxInfo {
	cand := strings.TrimSpace(binPath)
	if cand == "" {
		return JadxInfo{Available: false, Issue: "empty jadx path"}
	}
	if resolved, err := exec.LookPath(cand); err == nil {
		cand = resolved
	}
	st, err := os.Stat(cand)
	if err != nil || st.IsDir() {
		return JadxInfo{Available: false, Path: cand, Issue: fmt.Sprintf("jadx binary not found at %q", cand)}
	}
	ctx, cancel := context.WithTimeout(context.Background(), jadxProbeTimeout)
	defer cancel()
	out, runErr := exec.CommandContext(ctx, cand, "--version").CombinedOutput()
	if runErr != nil {
		return JadxInfo{
			Available: false,
			Path:      cand,
			Issue:     fmt.Sprintf("%s --version failed: %s", cand, firstNonEmptyLine(string(out))),
		}
	}
	ver := firstNonEmptyLine(string(out))
	if ver == "" {
		ver = "unknown"
	}
	return JadxInfo{Available: true, Path: cand, Version: ver}
}

func computeJadxCacheKey(absPath string, mtimeNano, size int64) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%d", filepath.Clean(absPath), mtimeNano, size)))
	return hex.EncodeToString(h[:])
}

func readJadxCacheMeta(workspaceDir string) (*jadxCacheMeta, bool) {
	raw, err := os.ReadFile(filepath.Join(workspaceDir, jadxMetaFileName))
	if err != nil {
		return nil, false
	}
	var meta jadxCacheMeta
	if err := json.Unmarshal(raw, &meta); err != nil || meta.CacheKey == "" {
		return nil, false
	}
	return &meta, true
}

func writeJadxCacheMeta(workspaceDir string, meta jadxCacheMeta) error {
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(workspaceDir, jadxMetaFileName+".tmp")
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(workspaceDir, jadxMetaFileName))
}

func sourcesRootDir(workspaceDir string) (string, error) {
	if strings.TrimSpace(workspaceDir) == "" {
		return "", errors.New("workspaceDir is required")
	}
	absWS, err := filepath.Abs(workspaceDir)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(absWS)
	if err != nil || !st.IsDir() {
		return "", fmt.Errorf("workspace directory %q does not exist", workspaceDir)
	}
	srcDir := filepath.Join(absWS, "sources")
	if sst, err := os.Stat(srcDir); err == nil && sst.IsDir() {
		return srcDir, nil
	}
	return absWS, nil
}

func hasJavaFiles(workspaceDir string) bool {
	root, err := sourcesRootDir(workspaceDir)
	if err != nil {
		return false
	}
	found := false
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.HasSuffix(d.Name(), ".java") {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

type safeJavaFile struct {
	realPath string
	relSlash string
	fqcn     string
	size     int64
}

// collectSafeJavaFiles walks root, rejects symlinks escaping root, stats the
// resolved target (not the symlink), and returns sorted in-bounds .java files.
func collectSafeJavaFiles(root string) ([]safeJavaFile, error) {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("resolve workspace root: %w", err)
	}

	var files []safeJavaFile
	err = filepath.WalkDir(root, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") && p != root {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".java") {
			return nil
		}
		realPath, rerr := filepath.EvalSymlinks(p)
		if rerr != nil || !isSubPath(realRoot, realPath) {
			return nil
		}
		st, serr := os.Stat(realPath)
		if serr != nil || st.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return nil
		}
		relSlash := filepath.ToSlash(rel)
		fqcn := strings.ReplaceAll(strings.TrimSuffix(relSlash, ".java"), "/", ".")
		files = append(files, safeJavaFile{
			realPath: realPath,
			relSlash: relSlash,
			fqcn:     fqcn,
			size:     st.Size(),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].fqcn < files[j].fqcn
	})
	return files, nil
}

// ListClasses lists decompiled Java classes in workspaceDir, flagging classes
// that declare native methods.
func ListClasses(workspaceDir, filter string, limit int) ([]JadxClassEntry, error) {
	root, err := sourcesRootDir(workspaceDir)
	if err != nil {
		return nil, err
	}

	files, err := collectSafeJavaFiles(root)
	if err != nil {
		return nil, err
	}

	filterLow := strings.ToLower(strings.TrimSpace(filter))
	entries := make([]JadxClassEntry, 0, len(files))

	for _, jf := range files {
		if filterLow != "" && !strings.Contains(strings.ToLower(jf.fqcn), filterLow) && !strings.Contains(strings.ToLower(jf.relSlash), filterLow) {
			continue
		}

		pkgName, simpleName := splitFQCN(jf.fqcn)
		var nativeNames []string
		if jf.size <= maxJavaReadBytes {
			if raw, rerr := readBoundedFile(jf.realPath, maxJavaReadBytes); rerr == nil && bytes.Contains(raw, []byte("native")) {
				decls := extractNativeMethodsFromJava(string(raw), jf.fqcn, jf.relSlash)
				for _, decl := range decls {
					nativeNames = append(nativeNames, decl.MethodName)
				}
			}
		}

		entries = append(entries, JadxClassEntry{
			ClassName:     jf.fqcn,
			PackageName:   pkgName,
			SimpleName:    simpleName,
			RelPath:       jf.relSlash,
			Size:          jf.size,
			HasNative:     len(nativeNames) > 0,
			NativeMethods: nativeNames,
		})
		if limit > 0 && len(entries) >= limit {
			break
		}
	}
	return entries, nil
}

// ReadClassSource reads a decompiled class source file from workspaceDir with
// strict path-traversal and symlink-escape protection.
func ReadClassSource(workspaceDir, className string) (*JadxClassSource, error) {
	root, err := sourcesRootDir(workspaceDir)
	if err != nil {
		return nil, err
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("resolve workspace root: %w", err)
	}

	relSlash, fqcn, err := sanitizeClassTarget(className)
	if err != nil {
		return nil, err
	}

	target := filepath.Join(root, filepath.FromSlash(relSlash))
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return nil, fmt.Errorf("resolve target path: %w", err)
	}
	if !isSubPath(root, absTarget) {
		return nil, fmt.Errorf("path traversal rejected for %q", className)
	}

	realTarget, err := filepath.EvalSymlinks(absTarget)
	if err != nil {
		return nil, fmt.Errorf("read class %q: %w", className, err)
	}
	if !isSubPath(realRoot, realTarget) {
		return nil, fmt.Errorf("symlink escape rejected for %q", className)
	}

	st, err := os.Stat(realTarget)
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return nil, fmt.Errorf("%q is a directory", className)
	}
	if st.Size() > maxJavaReadBytes {
		return nil, fmt.Errorf("class source %q exceeds %d byte safety limit", className, maxJavaReadBytes)
	}

	raw, err := os.ReadFile(realTarget)
	if err != nil {
		return nil, err
	}
	src := string(raw)
	lineCount := strings.Count(src, "\n") + 1
	if src == "" {
		lineCount = 0
	}
	decls := extractNativeMethodsFromJava(src, fqcn, relSlash)

	return &JadxClassSource{
		ClassName:     fqcn,
		RelPath:       relSlash,
		Source:        src,
		LineCount:     lineCount,
		HasNative:     len(decls) > 0,
		NativeMethods: decls,
	}, nil
}

func sanitizeClassTarget(className string) (relSlash string, fqcn string, err error) {
	raw := strings.TrimSpace(className)
	if raw == "" {
		return "", "", errors.New("className is required")
	}
	if strings.ContainsRune(raw, 0) || strings.Contains(raw, "\\") || strings.Contains(raw, ":") {
		return "", "", fmt.Errorf("invalid class path %q", className)
	}
	if strings.HasPrefix(raw, "/") || strings.Contains(raw, "..") {
		return "", "", fmt.Errorf("path traversal rejected for %q", className)
	}

	if strings.HasSuffix(raw, ".java") || strings.Contains(raw, "/") {
		clean := filepath.ToSlash(filepath.Clean(raw))
		if clean == "." || clean == ".." || clean == ".java" || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
			return "", "", fmt.Errorf("path traversal rejected for %q", className)
		}
		if !strings.HasSuffix(clean, ".java") {
			clean += ".java"
		}
		segs := strings.Split(clean, "/")
		for idx, seg := range segs {
			if seg == "" || seg == "." || seg == ".." || seg == ".java" {
				return "", "", fmt.Errorf("invalid class path %q", className)
			}
			if idx == len(segs)-1 {
				stem := strings.TrimSuffix(seg, ".java")
				if stem == "" || strings.HasPrefix(stem, ".") {
					return "", "", fmt.Errorf("invalid class name %q", className)
				}
			}
		}
		fqcnOut := strings.ReplaceAll(strings.TrimSuffix(clean, ".java"), "/", ".")
		if fqcnOut == "" {
			return "", "", fmt.Errorf("invalid class name %q", className)
		}
		return clean, fqcnOut, nil
	}

	// Dotted FQCN (e.g. com.example.app.NativeSigner)
	parts := strings.Split(raw, ".")
	for _, seg := range parts {
		if seg == "" || seg == "." || seg == ".." || strings.ContainsAny(seg, `/\:*?"<>|`) {
			return "", "", fmt.Errorf("invalid class name %q", className)
		}
	}
	relSlash = strings.Join(parts, "/") + ".java"
	return relSlash, raw, nil
}

func isSubPath(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return false
	}
	return true
}

// SearchSource performs case-insensitive search across all decompiled .java
// files in workspaceDir, returning line numbers, columns, and code snippets.
func SearchSource(workspaceDir, query string, maxHits int) ([]JadxSearchHit, error) {
	root, err := sourcesRootDir(workspaceDir)
	if err != nil {
		return nil, err
	}
	q := strings.TrimSpace(query)
	if q == "" {
		return nil, errors.New("search query is required")
	}
	if maxHits <= 0 {
		maxHits = 100
	}
	qLow := strings.ToLower(q)

	files, err := collectSafeJavaFiles(root)
	if err != nil {
		return nil, err
	}

	hits := make([]JadxSearchHit, 0)
	for _, jf := range files {
		if len(hits) >= maxHits {
			break
		}
		if jf.size > maxJavaReadBytes {
			continue
		}

		f, ferr := os.Open(jf.realPath)
		if ferr != nil {
			continue
		}
		scanner := bufio.NewScanner(io.LimitReader(f, maxJavaReadBytes))
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		lineNo := 0
		for scanner.Scan() {
			lineNo++
			line := scanner.Text()
			idx := strings.Index(strings.ToLower(line), qLow)
			if idx >= 0 {
				snippet := strings.TrimSpace(line)
				if len(snippet) > 240 {
					snippet = snippet[:240] + "..."
				}
				hits = append(hits, JadxSearchHit{
					ClassName: jf.fqcn,
					RelPath:   jf.relSlash,
					Line:      lineNo,
					Column:    idx + 1,
					Snippet:   snippet,
				})
				if len(hits) >= maxHits {
					break
				}
			}
		}
		_ = f.Close()
	}

	return hits, nil
}

// LinkJavaToNative cross-links Java `native` method declarations in a
// decompiled workspace against exported ELF symbols in soPath and optional
// Frida RegisterNatives JSON records.
func LinkJavaToNative(workspaceDir, soPath string, registerNativesJSON string) (*JavaNativeLinkReport, error) {
	root, err := sourcesRootDir(workspaceDir)
	if err != nil {
		return nil, err
	}

	report := &JavaNativeLinkReport{
		WorkspaceDir: workspaceDir,
		SOPath:       soPath,
		Bindings:     []JavaNativeBinding{},
	}

	// 1. Scan all in-bounds decompiled Java files for native method declarations.
	javaFiles, err := collectSafeJavaFiles(root)
	if err != nil {
		return nil, err
	}

	var decls []NativeMethodDecl
	for _, jf := range javaFiles {
		if jf.size > maxJavaReadBytes {
			continue
		}
		raw, rerr := readBoundedFile(jf.realPath, maxJavaReadBytes)
		if rerr != nil || !bytes.Contains(raw, []byte("native")) {
			continue
		}
		decls = append(decls, extractNativeMethodsFromJava(string(raw), jf.fqcn, jf.relSlash)...)
	}

	// 2. Parse ELF exported symbols if soPath provided.
	type elfExport struct {
		name string
		addr uint64
		size uint64
	}
	exports := make(map[string]elfExport)
	if strings.TrimSpace(soPath) != "" {
		report.SOName = filepath.Base(soPath)
		ef, eerr := elf.Open(soPath)
		if eerr != nil {
			return nil, fmt.Errorf("open ELF %q: %w", soPath, eerr)
		}
		report.SOArch = elfMachineName(ef.Machine)

		addSyms := func(syms []elf.Symbol) {
			for _, s := range syms {
				if s.Name == "" || s.Section == elf.SHN_UNDEF {
					continue
				}
				// Exclude file-local (static) symbols so non-exported functions are never misclassified as JNI exports.
				if elf.ST_BIND(s.Info) == elf.STB_LOCAL {
					continue
				}
				if _, exists := exports[s.Name]; !exists {
					exports[s.Name] = elfExport{
						name: s.Name,
						addr: s.Value,
						size: s.Size,
					}
				}
			}
		}
		if dyns, derr := ef.DynamicSymbols(); derr == nil {
			addSyms(dyns)
		}
		if syms, serr := ef.Symbols(); serr == nil {
			addSyms(syms)
		}
		_ = ef.Close()
	}

	// 3. Parse optional RegisterNatives JSON records.
	dynEntries, dynWarn, derr := parseRegisterNativesJSON(registerNativesJSON)
	if derr != nil {
		return nil, fmt.Errorf("parse registerNativesJSON: %w", derr)
	}
	if dynWarn != "" {
		report.Warnings = append(report.Warnings, dynWarn)
	}

	matchedExports := make(map[string]bool)

	for _, decl := range decls {
		binding := JavaNativeBinding{
			JavaClass:     decl.ClassName,
			JavaMethod:    decl.MethodName,
			JavaSignature: decl.JNISignature,
			JavaLine:      decl.Line,
			JavaRelPath:   decl.RelPath,
			MangledName:   decl.MangledShort,
			SOName:        report.SOName,
			BindingKind:   BindingUnresolved,
		}

		// Priority 1: dynamic RegisterNatives match
		if reg, ok := matchDynamicRegistration(decl, dynEntries); ok {
			binding.BindingKind = BindingDynamicRegister
			binding.NativeSymbol = reg.Symbol
			if binding.NativeSymbol == "" {
				binding.NativeSymbol = fmt.Sprintf("dynamic_%s", decl.MethodName)
			}
			binding.NativeAddr = reg.Addr
			binding.NativeOffset = reg.Offset
			if reg.Module != "" {
				binding.SOName = reg.Module
			}
			report.DynamicCount++
		} else if exp, ok := exports[decl.MangledLong]; ok {
			// Priority 2a: overloaded long JNI export
			binding.BindingKind = BindingStaticExport
			binding.MangledName = decl.MangledLong
			binding.NativeSymbol = exp.name
			binding.NativeAddr = fmt.Sprintf("0x%x", exp.addr)
			binding.NativeOffset = exp.addr
			binding.NativeSize = exp.size
			matchedExports[exp.name] = true
			report.StaticCount++
		} else if exp, ok := exports[decl.MangledShort]; ok {
			// Priority 2b: standard short JNI export
			binding.BindingKind = BindingStaticExport
			binding.NativeSymbol = exp.name
			binding.NativeAddr = fmt.Sprintf("0x%x", exp.addr)
			binding.NativeOffset = exp.addr
			binding.NativeSize = exp.size
			matchedExports[exp.name] = true
			report.StaticCount++
		} else {
			report.UnresolvedCount++
		}

		report.Bindings = append(report.Bindings, binding)
	}

	// Collect unmatched Java_* exports from the .so as orphans.
	for name := range exports {
		if strings.HasPrefix(name, "Java_") && !matchedExports[name] {
			report.OrphanExports = append(report.OrphanExports, name)
		}
	}
	sort.Strings(report.OrphanExports)

	report.TotalNativeMethods = len(report.Bindings)
	report.Summary = fmt.Sprintf(
		"Linked %d native method(s): %d static export(s), %d dynamic RegisterNatives, %d unresolved (%d orphan Java_* export(s)).",
		report.TotalNativeMethods,
		report.StaticCount,
		report.DynamicCount,
		report.UnresolvedCount,
		len(report.OrphanExports),
	)
	return report, nil
}

// --- Java native method parser & JNI mangling --------------------------------

// MangleJNIName computes the JNI short and long (overloaded) C symbol names
// per the official JNI Specification (escaping _ -> _1, ; -> _2, [ -> _3, and
// non-alphanumeric Unicode code units -> _0xxxx).
func MangleJNIName(className, methodName, paramDescriptor string) (shortName, longName string) {
	cls := strings.TrimSpace(className)
	if strings.HasPrefix(cls, "L") && strings.HasSuffix(cls, ";") && len(cls) > 2 {
		cls = cls[1 : len(cls)-1]
	}
	cls = strings.ReplaceAll(cls, "/", ".")
	escapedClass := escapeJNIPart(cls, true)
	escapedMethod := escapeJNIPart(methodName, false)
	shortName = "Java_" + escapedClass + "_" + escapedMethod
	if paramDescriptor != "" {
		params := paramDescriptor
		if strings.HasPrefix(params, "(") {
			if closeIdx := strings.IndexByte(params, ')'); closeIdx >= 0 {
				params = params[1:closeIdx]
			}
		}
		longName = shortName + "__" + escapeJNIPart(params, true)
	} else {
		longName = shortName + "__"
	}
	return shortName, longName
}

func escapeJNIPart(s string, convertPathSep bool) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		case convertPathSep && (r == '.' || r == '/'):
			b.WriteByte('_')
		case r == '_':
			b.WriteString("_1")
		case r == ';':
			b.WriteString("_2")
		case r == '[':
			b.WriteString("_3")
		default:
			fmt.Fprintf(&b, "_0%04x", uint16(r))
		}
	}
	return b.String()
}

func extractNativeMethodsFromJava(src, defaultFQCN, relPath string) []NativeMethodDecl {
	pkg := ""
	if m := javaPkgDeclRe.FindStringSubmatch(src); len(m) == 2 {
		pkg = m[1]
	}
	imports := make(map[string]string)
	for _, m := range javaImportRe.FindAllStringSubmatch(src, -1) {
		if len(m) == 2 {
			full := m[1]
			if idx := strings.LastIndexByte(full, '.'); idx >= 0 {
				imports[full[idx+1:]] = full
			}
		}
	}

	fqcn := defaultFQCN
	if fqcn == "" {
		if cm := javaClassDeclRe.FindStringSubmatch(src); len(cm) == 2 {
			if pkg != "" {
				fqcn = pkg + "." + cm[1]
			} else {
				fqcn = cm[1]
			}
		}
	}

	// Build line index for fast byte-offset -> 1-based line lookup.
	var lineStarts []int
	lineStarts = append(lineStarts, 0)
	for i := 0; i < len(src); i++ {
		if src[i] == '\n' {
			lineStarts = append(lineStarts, i+1)
		}
	}
	offsetToLine := func(off int) int {
		idx := sort.Search(len(lineStarts), func(i int) bool { return lineStarts[i] > off })
		if idx <= 0 {
			return 1
		}
		return idx
	}

	// Strip line/block comments while preserving newlines so line numbers remain exact.
	cleaned := stripJavaCommentsPreserveLines(src)

	matches := javaNativeMethRe.FindAllStringSubmatchIndex(cleaned, -1)
	if len(matches) == 0 {
		return nil
	}

	var out []NativeMethodDecl
	for _, loc := range matches {
		fullStart := loc[0]
		retType := strings.TrimSpace(cleaned[loc[2]:loc[3]])
		methName := strings.TrimSpace(cleaned[loc[4]:loc[5]])
		paramsRaw := strings.TrimSpace(cleaned[loc[6]:loc[7]])
		if retType == "" || methName == "" {
			continue
		}

		// Inspect preceding modifiers back to the last statement boundary for `static`.
		lineNo := offsetToLine(fullStart)
		declStart := fullStart
		for declStart > 0 && fullStart-declStart < 200 {
			ch := cleaned[declStart-1]
			if ch == ';' || ch == '{' || ch == '}' {
				break
			}
			declStart--
		}
		prefix := cleaned[declStart:loc[1]]
		if !javaNativePreRe.MatchString(prefix) {
			// Guard against false positives where `native` was inside an identifier or invalid position.
			if !strings.Contains(cleaned[loc[0]:loc[1]], "native") {
				continue
			}
		}
		isStatic := regexp.MustCompile(`\bstatic\b`).MatchString(prefix)

		paramTypes := parseJavaParamTypes(paramsRaw)
		var sigBuf strings.Builder
		sigBuf.WriteByte('(')
		for _, pt := range paramTypes {
			sigBuf.WriteString(javaTypeToJNISig(pt, pkg, imports))
		}
		sigBuf.WriteByte(')')
		sigBuf.WriteString(javaTypeToJNISig(retType, pkg, imports))
		jniSig := sigBuf.String()

		shortMangled, longMangled := MangleJNIName(fqcn, methName, jniSig)
		out = append(out, NativeMethodDecl{
			ClassName:    fqcn,
			MethodName:   methName,
			ReturnType:   retType,
			ParamTypes:   paramTypes,
			JNISignature: jniSig,
			MangledShort: shortMangled,
			MangledLong:  longMangled,
			Line:         lineNo,
			IsStatic:     isStatic,
			RelPath:      relPath,
		})
	}
	return out
}

func stripJavaCommentsPreserveLines(src string) string {
	b := make([]byte, len(src))
	inLine := false
	inBlock := false
	inStr := false
	inChar := false
	for i := 0; i < len(src); i++ {
		c := src[i]
		if inLine {
			if c == '\n' {
				inLine = false
				b[i] = '\n'
			} else {
				b[i] = ' '
			}
			continue
		}
		if inBlock {
			if c == '*' && i+1 < len(src) && src[i+1] == '/' {
				b[i] = ' '
				b[i+1] = ' '
				i++
				inBlock = false
			} else if c == '\n' {
				b[i] = '\n'
			} else {
				b[i] = ' '
			}
			continue
		}
		if inStr {
			b[i] = c
			if c == '\\' && i+1 < len(src) {
				i++
				b[i] = src[i]
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		if inChar {
			b[i] = c
			if c == '\\' && i+1 < len(src) {
				i++
				b[i] = src[i]
			} else if c == '\'' {
				inChar = false
			}
			continue
		}
		if c == '"' {
			inStr = true
			b[i] = c
			continue
		}
		if c == '\'' {
			inChar = true
			b[i] = c
			continue
		}
		if c == '/' && i+1 < len(src) && src[i+1] == '/' {
			inLine = true
			b[i] = ' '
			b[i+1] = ' '
			i++
			continue
		}
		if c == '/' && i+1 < len(src) && src[i+1] == '*' {
			inBlock = true
			b[i] = ' '
			b[i+1] = ' '
			i++
			continue
		}
		b[i] = c
	}
	return string(b)
}

func parseJavaParamTypes(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	// Split on commas outside generic angle brackets `<...>`.
	var parts []string
	depth := 0
	start := 0
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '<':
			depth++
		case '>':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				parts = append(parts, raw[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, raw[start:])

	var types []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Remove annotations (@NonNull, @Nullable, etc.) and `final`
		tokens := splitJavaParamTokens(p)
		var clean []string
		for _, tok := range tokens {
			if strings.HasPrefix(tok, "@") || tok == "final" {
				continue
			}
			clean = append(clean, tok)
		}
		if len(clean) == 0 {
			continue
		}
		// Last token is parameter variable name (unless it ends with [] or ... attached to name)
		var typeStr string
		if len(clean) == 1 {
			typeStr = clean[0]
		} else {
			last := clean[len(clean)-1]
			arrSuffix := ""
			if strings.HasSuffix(last, "[]") {
				arrSuffix = strings.Repeat("[]", strings.Count(last, "[]"))
			}
			typeStr = strings.Join(clean[:len(clean)-1], "") + arrSuffix
		}
		typeStr = strings.ReplaceAll(typeStr, "...", "[]")
		types = append(types, typeStr)
	}
	return types
}

func splitJavaParamTokens(s string) []string {
	var out []string
	var cur strings.Builder
	depth := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '<':
			depth++
			cur.WriteByte(c)
		case '>':
			if depth > 0 {
				depth--
			}
			cur.WriteByte(c)
		case ' ', '\t', '\n', '\r':
			if depth == 0 {
				if cur.Len() > 0 {
					out = append(out, cur.String())
					cur.Reset()
				}
			} else {
				cur.WriteByte(c)
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

var javaLangTypes = map[string]bool{
	"Object": true, "String": true, "Class": true, "Throwable": true,
	"Exception": true, "RuntimeException": true, "Boolean": true,
	"Byte": true, "Short": true, "Integer": true, "Long": true,
	"Float": true, "Double": true, "Character": true, "CharSequence": true,
	"Number": true, "StringBuilder": true, "StringBuffer": true, "Thread": true,
}

func javaTypeToJNISig(t, pkg string, imports map[string]string) string {
	t = strings.TrimSpace(t)
	// Strip generics `<...>`
	if idx := strings.IndexByte(t, '<'); idx >= 0 {
		if end := strings.LastIndexByte(t, '>'); end > idx {
			t = t[:idx] + t[end+1:]
		}
	}
	t = strings.ReplaceAll(t, " ", "")
	dims := 0
	for strings.HasSuffix(t, "[]") {
		dims++
		t = strings.TrimSuffix(t, "[]")
	}
	prefix := strings.Repeat("[", dims)

	switch t {
	case "void":
		return prefix + "V"
	case "boolean":
		return prefix + "Z"
	case "byte":
		return prefix + "B"
	case "char":
		return prefix + "C"
	case "short":
		return prefix + "S"
	case "int":
		return prefix + "I"
	case "long":
		return prefix + "J"
	case "float":
		return prefix + "F"
	case "double":
		return prefix + "D"
	}

	if full, ok := imports[t]; ok {
		return prefix + "L" + strings.ReplaceAll(full, ".", "/") + ";"
	}
	if strings.Contains(t, ".") {
		return prefix + "L" + strings.ReplaceAll(t, ".", "/") + ";"
	}
	if javaLangTypes[t] {
		return prefix + "Ljava/lang/" + t + ";"
	}
	if pkg != "" {
		return prefix + "L" + strings.ReplaceAll(pkg, ".", "/") + "/" + t + ";"
	}
	return prefix + "L" + t + ";"
}

// --- RegisterNatives JSON parser ---------------------------------------------

type dynamicNativeEntry struct {
	Class     string
	Method    string
	Signature string
	Symbol    string
	Addr      string
	Offset    uint64
	Module    string
}

func parseRegisterNativesJSON(raw string) ([]dynamicNativeEntry, string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, "", nil
	}

	type rawItem struct {
		Class        string `json:"class"`
		ClassName    string `json:"class_name"`
		JavaClass    string `json:"java_class"`
		Name         string `json:"name"`
		Method       string `json:"method"`
		MethodName   string `json:"method_name"`
		Signature    string `json:"signature"`
		Sig          string `json:"sig"`
		JNISignature string `json:"jni_signature"`
		FnPtr        string `json:"fnPtr"`
		FnPtrSnake   string `json:"fn_ptr"`
		Addr         string `json:"addr"`
		Address      string `json:"address"`
		Offset       string `json:"offset"`
		Symbol       string `json:"symbol"`
		Module       string `json:"module"`
		SO           string `json:"so"`
	}

	var items []rawItem
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal([]byte(trimmed), &items); err != nil {
			return nil, "", err
		}
	} else {
		var wrapper struct {
			Entries       []rawItem `json:"entries"`
			Registrations []rawItem `json:"registrations"`
			Natives       []rawItem `json:"natives"`
		}
		if err := json.Unmarshal([]byte(trimmed), &wrapper); err != nil {
			return nil, "", err
		}
		items = append(items, wrapper.Entries...)
		items = append(items, wrapper.Registrations...)
		items = append(items, wrapper.Natives...)
	}

	out := make([]dynamicNativeEntry, 0, len(items))
	for _, it := range items {
		cls := strings.TrimSpace(firstNonEmptyStr(it.Class, it.ClassName, it.JavaClass))
		if strings.HasPrefix(cls, "L") && strings.HasSuffix(cls, ";") && len(cls) > 2 {
			cls = cls[1 : len(cls)-1]
		}
		cls = strings.ReplaceAll(cls, "/", ".")
		meth := firstNonEmptyStr(it.Name, it.Method, it.MethodName)
		if cls == "" || meth == "" {
			continue
		}
		sig := firstNonEmptyStr(it.Signature, it.Sig, it.JNISignature)
		addrRaw := firstNonEmptyStr(it.Offset, it.FnPtr, it.FnPtrSnake, it.Addr, it.Address)
		var off uint64
		normAddr := addrRaw
		if addrRaw != "" {
			if parsed, hexStr, err := normalizeHexAddr(addrRaw); err == nil {
				off = parsed
				normAddr = hexStr
			}
		}
		out = append(out, dynamicNativeEntry{
			Class:     cls,
			Method:    meth,
			Signature: sig,
			Symbol:    strings.TrimSpace(it.Symbol),
			Addr:      normAddr,
			Offset:    off,
			Module:    firstNonEmptyStr(it.Module, it.SO),
		})
	}
	return out, "", nil
}

func matchDynamicRegistration(decl NativeMethodDecl, entries []dynamicNativeEntry) (dynamicNativeEntry, bool) {
	// Exact match (class + method + signature) first
	for _, e := range entries {
		if e.Class == decl.ClassName && e.Method == decl.MethodName && e.Signature != "" && e.Signature == decl.JNISignature {
			return e, true
		}
	}
	// Match class + method when signature omitted in RegisterNatives trace
	for _, e := range entries {
		if e.Class == decl.ClassName && e.Method == decl.MethodName && e.Signature == "" {
			return e, true
		}
	}
	return dynamicNativeEntry{}, false
}

// --- Pure-Go ZIP/DEX Fallback ------------------------------------------------

func decompilePureGoDEXFallback(apkOrDexPath, workspaceDir string, maxClasses int) ([]string, error) {
	var warnings []string
	var dexBuffers [][]byte

	rawHead, err := readLeadingBytes(apkOrDexPath, 8)
	if err != nil {
		return nil, err
	}

	if bytes.HasPrefix(rawHead, []byte("dex\n")) {
		data, rerr := readBoundedFile(apkOrDexPath, maxDEXFallbackBytes)
		if rerr != nil {
			return nil, rerr
		}
		dexBuffers = append(dexBuffers, data)
	} else {
		zr, zerr := zip.OpenReader(apkOrDexPath)
		if zerr != nil {
			return nil, fmt.Errorf("file is neither a valid DEX nor APK archive: %w", zerr)
		}
		defer zr.Close()
		for _, f := range zr.File {
			base := filepath.Base(f.Name)
			if strings.HasPrefix(base, "classes") && strings.HasSuffix(base, ".dex") && !strings.Contains(f.Name, "/") {
				rc, oerr := f.Open()
				if oerr != nil {
					warnings = append(warnings, fmt.Sprintf("open %s: %v", f.Name, oerr))
					continue
				}
				data, rerr := io.ReadAll(io.LimitReader(rc, maxDEXFallbackBytes+1))
				_ = rc.Close()
				if rerr != nil || len(data) > maxDEXFallbackBytes {
					warnings = append(warnings, fmt.Sprintf("skip %s (read error or exceeds size cap)", f.Name))
					continue
				}
				dexBuffers = append(dexBuffers, data)
			}
		}
	}

	if len(dexBuffers) == 0 {
		return nil, errors.New("no classes*.dex found in APK/DEX")
	}

	srcRoot := filepath.Join(workspaceDir, "sources")
	if err := os.MkdirAll(srcRoot, 0o755); err != nil {
		return nil, err
	}

	written := 0
	for _, buf := range dexBuffers {
		classes, perr := parseMinimalDEXClasses(buf)
		if perr != nil {
			warnings = append(warnings, fmt.Sprintf("dex parse warning: %v", perr))
			continue
		}
		for _, cls := range classes {
			if maxClasses > 0 && written >= maxClasses {
				break
			}
			relSlash, _, serr := sanitizeClassTarget(cls.FQCN)
			if serr != nil {
				continue
			}
			outPath := filepath.Join(srcRoot, filepath.FromSlash(relSlash))
			if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
				continue
			}
			javaSrc := renderDEXStubJava(cls)
			if err := os.WriteFile(outPath, []byte(javaSrc), 0o644); err != nil {
				continue
			}
			written++
		}
	}

	if written == 0 {
		return warnings, errors.New("pure-Go DEX parser extracted 0 classes")
	}
	return warnings, nil
}

type minimalDEXMethod struct {
	Name       string
	Params     []string
	ReturnType string
	IsStatic   bool
	IsNative   bool
}

type minimalDEXClass struct {
	FQCN    string
	Package string
	Simple  string
	Methods []minimalDEXMethod
}

func parseMinimalDEXClasses(data []byte) ([]minimalDEXClass, error) {
	if len(data) < 112 || string(data[0:4]) != "dex\n" || data[7] != 0 {
		return nil, errors.New("invalid DEX header")
	}
	le := binary.LittleEndian
	strSize := le.Uint32(data[56:60])
	strOff := le.Uint32(data[60:64])
	typeSize := le.Uint32(data[64:68])
	typeOff := le.Uint32(data[68:72])
	protoSize := le.Uint32(data[72:76])
	protoOff := le.Uint32(data[76:80])
	methSize := le.Uint32(data[88:92])
	methOff := le.Uint32(data[92:96])
	classSize := le.Uint32(data[96:100])
	classOff := le.Uint32(data[100:104])

	getString := func(idx uint32) string {
		if idx >= strSize {
			return ""
		}
		entryOff := uint64(strOff) + uint64(idx)*4
		if entryOff+4 > uint64(len(data)) {
			return ""
		}
		sOff := le.Uint32(data[entryOff : entryOff+4])
		if uint64(sOff) >= uint64(len(data)) {
			return ""
		}
		pos := int(sOff)
		// Skip MUTF-8 length ULEB128
		_, n := readULEB128(data[pos:])
		pos += n
		end := pos
		for end < len(data) && data[end] != 0 && end-pos < 4096 {
			end++
		}
		return string(data[pos:end])
	}

	getType := func(idx uint32) string {
		if idx >= typeSize {
			return ""
		}
		off := uint64(typeOff) + uint64(idx)*4
		if off+4 > uint64(len(data)) {
			return ""
		}
		return getString(le.Uint32(data[off : off+4]))
	}

	getProto := func(idx uint32) (params []string, ret string) {
		if idx >= protoSize {
			return nil, "void"
		}
		off := uint64(protoOff) + uint64(idx)*12
		if off+12 > uint64(len(data)) {
			return nil, "void"
		}
		retTypeIdx := le.Uint32(data[off+4 : off+8])
		paramsOff := le.Uint32(data[off+8 : off+12])
		ret = dexDescriptorToJava(getType(retTypeIdx))
		if paramsOff != 0 && uint64(paramsOff)+4 <= uint64(len(data)) {
			cnt := le.Uint32(data[paramsOff : paramsOff+4])
			pPos := uint64(paramsOff) + 4
			for i := uint32(0); i < cnt && pPos+2 <= uint64(len(data)); i++ {
				tIdx := uint32(le.Uint16(data[pPos : pPos+2]))
				params = append(params, dexDescriptorToJava(getType(tIdx)))
				pPos += 2
			}
		}
		return params, ret
	}

	getMethod := func(idx uint32) (name string, params []string, ret string, ok bool) {
		if idx >= methSize {
			return "", nil, "", false
		}
		off := uint64(methOff) + uint64(idx)*8
		if off+8 > uint64(len(data)) {
			return "", nil, "", false
		}
		protoIdx := uint32(le.Uint16(data[off+2 : off+4]))
		nameIdx := le.Uint32(data[off+4 : off+8])
		params, ret = getProto(protoIdx)
		return getString(nameIdx), params, ret, true
	}

	var out []minimalDEXClass
	for i := uint32(0); i < classSize; i++ {
		cOff := uint64(classOff) + uint64(i)*32
		if cOff+32 > uint64(len(data)) {
			break
		}
		clsTypeIdx := le.Uint32(data[cOff : cOff+4])
		classDataOff := le.Uint32(data[cOff+24 : cOff+28])
		desc := getType(clsTypeIdx)
		if !strings.HasPrefix(desc, "L") || !strings.HasSuffix(desc, ";") {
			continue
		}
		fqcn := strings.ReplaceAll(desc[1:len(desc)-1], "/", ".")
		pkg, simple := splitFQCN(fqcn)
		cls := minimalDEXClass{
			FQCN:    fqcn,
			Package: pkg,
			Simple:  simple,
		}

		if classDataOff != 0 && int(classDataOff) < len(data) {
			pos := int(classDataOff)
			staticFields, n := readULEB128(data[pos:])
			pos += n
			instFields, n := readULEB128(data[pos:])
			pos += n
			directMethods, n := readULEB128(data[pos:])
			pos += n
			virtualMethods, n := readULEB128(data[pos:])
			pos += n

			// Skip encoded_field entries (field_idx_diff, access_flags) using uint64 to avoid wraparound.
			totalFields := uint64(staticFields) + uint64(instFields)
			for f := uint64(0); f < totalFields && pos < len(data); f++ {
				_, n1 := readULEB128(data[pos:])
				pos += n1
				_, n2 := readULEB128(data[pos:])
				pos += n2
			}

			readMethods := func(count uint32) {
				var methIdx uint32
				for m := uint32(0); m < count && pos < len(data); m++ {
					diff, n1 := readULEB128(data[pos:])
					pos += n1
					access, n2 := readULEB128(data[pos:])
					pos += n2
					_, n3 := readULEB128(data[pos:]) // code_off
					pos += n3
					methIdx += diff
					if name, params, ret, ok := getMethod(methIdx); ok && name != "" {
						cls.Methods = append(cls.Methods, minimalDEXMethod{
							Name:       name,
							Params:     params,
							ReturnType: ret,
							IsStatic:   (access & dexAccStatic) != 0,
							IsNative:   (access & dexAccNative) != 0,
						})
					}
				}
			}
			readMethods(directMethods)
			readMethods(virtualMethods)
		}

		out = append(out, cls)
	}
	return out, nil
}

func readULEB128(b []byte) (uint32, int) {
	var result uint32
	var shift uint
	for i := 0; i < len(b) && i < 5; i++ {
		val := b[i]
		result |= uint32(val&0x7f) << shift
		if (val & 0x80) == 0 {
			return result, i + 1
		}
		shift += 7
	}
	return result, len(b)
}

func dexDescriptorToJava(desc string) string {
	dims := 0
	for strings.HasPrefix(desc, "[") {
		dims++
		desc = desc[1:]
	}
	suffix := strings.Repeat("[]", dims)
	switch desc {
	case "V":
		return "void" + suffix
	case "Z":
		return "boolean" + suffix
	case "B":
		return "byte" + suffix
	case "C":
		return "char" + suffix
	case "S":
		return "short" + suffix
	case "I":
		return "int" + suffix
	case "J":
		return "long" + suffix
	case "F":
		return "float" + suffix
	case "D":
		return "double" + suffix
	}
	if strings.HasPrefix(desc, "L") && strings.HasSuffix(desc, ";") {
		return strings.ReplaceAll(desc[1:len(desc)-1], "/", ".") + suffix
	}
	return "java.lang.Object" + suffix
}

func renderDEXStubJava(cls minimalDEXClass) string {
	var b strings.Builder
	b.WriteString("// Auto-extracted by cap pure-Go DEX fallback (jadx unavailable)\n")
	if cls.Package != "" {
		fmt.Fprintf(&b, "package %s;\n\n", cls.Package)
	}
	fmt.Fprintf(&b, "public class %s {\n", cls.Simple)
	for _, m := range cls.Methods {
		if m.Name == "<init>" || m.Name == "<clinit>" {
			continue
		}
		var paramParts []string
		for idx, pt := range m.Params {
			paramParts = append(paramParts, fmt.Sprintf("%s arg%d", pt, idx))
		}
		mods := "public"
		if m.IsStatic {
			mods += " static"
		}
		if m.IsNative {
			fmt.Fprintf(&b, "    %s native %s %s(%s);\n", mods, m.ReturnType, m.Name, strings.Join(paramParts, ", "))
		} else {
			fmt.Fprintf(&b, "    %s %s %s(%s) { /* bytecode omitted in DEX fallback */ }\n", mods, m.ReturnType, m.Name, strings.Join(paramParts, ", "))
		}
	}
	b.WriteString("}\n")
	return b.String()
}

// --- Helpers -----------------------------------------------------------------

func splitFQCN(fqcn string) (pkg, simple string) {
	if idx := strings.LastIndexByte(fqcn, '.'); idx >= 0 {
		return fqcn[:idx], fqcn[idx+1:]
	}
	return "", fqcn
}

func firstNonEmptyLine(s string) string {
	for _, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		t := strings.TrimSpace(line)
		if t != "" {
			return t
		}
	}
	return ""
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if t := strings.TrimSpace(v); t != "" {
			return t
		}
	}
	return ""
}

func elfMachineName(m elf.Machine) string {
	switch m {
	case elf.EM_AARCH64:
		return "arm64"
	case elf.EM_ARM:
		return "arm"
	case elf.EM_X86_64:
		return "x86_64"
	case elf.EM_386:
		return "x86"
	default:
		return m.String()
	}
}

func readLeadingBytes(path string, n int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, n)
	readN, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return buf[:readN], nil
}

func readBoundedFile(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("file %q exceeds %d byte limit", path, maxBytes)
	}
	return data, nil
}
