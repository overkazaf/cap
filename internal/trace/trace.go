package trace

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/overkazaf/cap/internal/types"
)

type TraceResult struct {
	FlowID     string      `json:"flow_id"`
	URL        string      `json:"url"`
	Method     string      `json:"method"`
	APKPath    string      `json:"apk_path"`
	Package    string      `json:"package"`
	JavaTrace  []JavaRef   `json:"java_trace"`
	NativeTrace []NativeRef `json:"native_trace"`
	CallGraph  []CallEdge  `json:"call_graph"`
	Mermaid    string      `json:"mermaid"`
	Summary    string      `json:"summary"`
}

type JavaRef struct {
	File       string   `json:"file"`
	Class      string   `json:"class"`
	Method     string   `json:"method"`
	Line       int      `json:"line"`
	Snippet    string   `json:"snippet"`
	Annotation string   `json:"annotation"`
	CallsNative bool   `json:"calls_native"`
	NativeMethods []string `json:"native_methods,omitempty"`
}

type NativeRef struct {
	SOFile    string   `json:"so_file"`
	Function  string   `json:"function"`
	Address   string   `json:"address"`
	Calls     []string `json:"calls"`
	Strings   []string `json:"strings"`
	Imports   []string `json:"imports"`
}

type CallEdge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Type     string `json:"type"` // "java_call", "jni", "native_call", "http"
	Label    string `json:"label,omitempty"`
}

type Options struct {
	Serial     string
	APKPath    string // pre-pulled APK path, empty = pull from device
	JadxPath   string // jadx binary path, empty = find in PATH
	R2Path     string // radare2 binary path
	UnpackPath string // unpack tool path
	OutputDir  string // working directory for decompiled output
	Package    string // target package name
}

func Trace(flow *types.Flow, opts Options) (*TraceResult, error) {
	result := &TraceResult{
		FlowID: flow.ID,
		URL:    flow.URL,
		Method: flow.Method,
	}

	if opts.OutputDir == "" {
		home, _ := os.UserHomeDir()
		opts.OutputDir = filepath.Join(home, ".cap", "trace")
	}
	os.MkdirAll(opts.OutputDir, 0755)

	// Step 1: Get APK
	apkPath := opts.APKPath
	if apkPath == "" && opts.Package != "" {
		var err error
		apkPath, err = pullAPK(opts.Serial, opts.Package, opts.OutputDir)
		if err != nil {
			return result, fmt.Errorf("pull APK: %w", err)
		}
	}
	result.APKPath = apkPath
	result.Package = opts.Package

	// Step 2: Unpack if unpack tool available
	if opts.UnpackPath != "" && apkPath != "" {
		runUnpack(opts.UnpackPath, apkPath, opts.OutputDir)
	}

	// Step 3: Decompile with jadx
	jadxDir := filepath.Join(opts.OutputDir, "jadx-output")
	if apkPath != "" {
		decompileJadx(opts.JadxPath, apkPath, jadxDir)
	}

	// Step 4: Search for URL/endpoint in Java sources
	if _, err := os.Stat(jadxDir); err == nil {
		result.JavaTrace = searchJavaSource(jadxDir, flow)
	}

	// Step 5: Find native methods and analyze with r2
	for i, jref := range result.JavaTrace {
		if jref.CallsNative && len(jref.NativeMethods) > 0 {
			soFiles := findSOFiles(apkPath, opts.OutputDir)
			for _, soFile := range soFiles {
				for _, nativeMethod := range jref.NativeMethods {
					refs := analyzeNative(opts.R2Path, soFile, nativeMethod)
					result.NativeTrace = append(result.NativeTrace, refs...)
				}
			}
			_ = i
		}
	}

	// Step 6: Build call graph
	result.CallGraph = buildCallGraph(flow, result.JavaTrace, result.NativeTrace)
	result.Mermaid = generateMermaid(result.CallGraph)
	result.Summary = generateSummary(result)

	return result, nil
}

func pullAPK(serial, pkg, outDir string) (string, error) {
	args := []string{}
	if serial != "" {
		args = append(args, "-s", serial)
	}
	args = append(args, "shell", "pm", "path", pkg)
	out, err := exec.Command("adb", args...).Output()
	if err != nil {
		return "", err
	}

	apkPath := ""
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "package:") {
			apkPath = strings.TrimPrefix(line, "package:")
			break
		}
	}
	if apkPath == "" {
		return "", fmt.Errorf("package %s not found", pkg)
	}

	localPath := filepath.Join(outDir, filepath.Base(apkPath))
	pullArgs := []string{}
	if serial != "" {
		pullArgs = append(pullArgs, "-s", serial)
	}
	pullArgs = append(pullArgs, "pull", apkPath, localPath)
	if err := exec.Command("adb", pullArgs...).Run(); err != nil {
		return "", err
	}
	return localPath, nil
}

func runUnpack(unpackPath, apkPath, outDir string) {
	exec.Command(unpackPath, "scan", apkPath, "--output", outDir).Run()
}

func decompileJadx(jadxPath, apkPath, outDir string) {
	if jadxPath == "" {
		jadxPath = "jadx"
	}
	if _, err := os.Stat(outDir); err == nil {
		return // already decompiled
	}
	exec.Command(jadxPath, "-d", outDir, "--no-res", apkPath).Run()
}

var (
	retrofitPattern = regexp.MustCompile(`@(GET|POST|PUT|DELETE|PATCH)\s*\(\s*"([^"]+)"`)
	urlPattern      = regexp.MustCompile(`"(https?://[^"]+)"`)
	nativePattern   = regexp.MustCompile(`\bnative\s+\w+\s+(\w+)\s*\(`)
	jniPattern      = regexp.MustCompile(`System\.loadLibrary\s*\(\s*"([^"]+)"`)
)

func searchJavaSource(jadxDir string, flow *types.Flow) []JavaRef {
	var refs []JavaRef
	searchPath := extractPathForSearch(flow)

	filepath.Walk(jadxDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".java") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		content := string(data)

		// Search for URL or path
		if !strings.Contains(content, searchPath) {
			return nil
		}

		relPath, _ := filepath.Rel(jadxDir, path)
		lines := strings.Split(content, "\n")
		className := extractClassName(relPath)

		for i, line := range lines {
			if strings.Contains(line, searchPath) {
				ref := JavaRef{
					File:    relPath,
					Class:   className,
					Line:    i + 1,
					Snippet: strings.TrimSpace(line),
				}

				// Check for Retrofit annotation
				if m := retrofitPattern.FindStringSubmatch(line); len(m) >= 3 {
					ref.Annotation = m[1] + " " + m[2]
					ref.Method = extractMethodFromContext(lines, i)
				}

				// Check for native methods in the class
				for _, nline := range lines {
					if nm := nativePattern.FindStringSubmatch(nline); len(nm) >= 2 {
						ref.CallsNative = true
						ref.NativeMethods = append(ref.NativeMethods, nm[1])
					}
				}

				// Check for loadLibrary
				for _, nline := range lines {
					if jni := jniPattern.FindStringSubmatch(nline); len(jni) >= 2 {
						ref.NativeMethods = append(ref.NativeMethods, "lib"+jni[1]+".so")
					}
				}

				refs = append(refs, ref)
			}
		}
		return nil
	})
	return refs
}

func extractPathForSearch(flow *types.Flow) string {
	path := flow.Path
	if path == "" {
		parts := strings.SplitN(flow.URL, "//", 2)
		if len(parts) >= 2 {
			idx := strings.Index(parts[1], "/")
			if idx >= 0 {
				path = parts[1][idx:]
			}
		}
	}
	if idx := strings.Index(path, "?"); idx >= 0 {
		path = path[:idx]
	}
	return path
}

func extractClassName(relPath string) string {
	name := strings.TrimSuffix(relPath, ".java")
	name = strings.ReplaceAll(name, "/", ".")
	if strings.HasPrefix(name, "sources.") {
		name = strings.TrimPrefix(name, "sources.")
	}
	return name
}

func extractMethodFromContext(lines []string, lineIdx int) string {
	for i := lineIdx + 1; i < len(lines) && i < lineIdx+5; i++ {
		line := strings.TrimSpace(lines[i])
		if idx := strings.Index(line, "("); idx > 0 {
			parts := strings.Fields(line[:idx])
			if len(parts) > 0 {
				return parts[len(parts)-1]
			}
		}
	}
	return ""
}

func findSOFiles(apkPath, outDir string) []string {
	var soFiles []string
	libDir := filepath.Join(outDir, "lib")
	if _, err := os.Stat(libDir); err != nil {
		// Try to extract from APK
		exec.Command("unzip", "-o", "-j", apkPath, "lib/*/*.so", "-d", libDir).Run()
	}
	filepath.Walk(libDir, func(path string, info os.FileInfo, err error) error {
		if err == nil && strings.HasSuffix(path, ".so") {
			soFiles = append(soFiles, path)
		}
		return nil
	})
	return soFiles
}

func analyzeNative(r2Path, soFile, funcName string) []NativeRef {
	if r2Path == "" {
		r2Path = "r2"
	}

	ref := NativeRef{
		SOFile:   filepath.Base(soFile),
		Function: funcName,
	}

	// r2 analysis: find function, get calls and strings
	r2Cmd := fmt.Sprintf("aaa; afl~%s; pdf @ sym.%s 2>/dev/null; izz~%s", funcName, funcName, funcName)
	out, err := exec.Command(r2Path, "-q", "-c", r2Cmd, soFile).CombinedOutput()
	if err == nil {
		output := string(out)
		// Extract function address
		for _, line := range strings.Split(output, "\n") {
			if strings.Contains(line, funcName) && strings.Contains(line, "0x") {
				fields := strings.Fields(line)
				if len(fields) > 0 {
					ref.Address = fields[0]
					break
				}
			}
		}
		// Extract called functions
		for _, line := range strings.Split(output, "\n") {
			if strings.Contains(line, "call") || strings.Contains(line, "bl ") {
				fields := strings.Fields(line)
				for _, f := range fields {
					if strings.HasPrefix(f, "sym.") || strings.HasPrefix(f, "imp.") {
						ref.Calls = append(ref.Calls, f)
					}
				}
			}
		}
		// Extract interesting strings
		for _, line := range strings.Split(output, "\n") {
			line = strings.TrimSpace(line)
			if len(line) > 5 && !strings.HasPrefix(line, "0x") {
				ref.Strings = append(ref.Strings, line)
			}
		}
	}

	// r2: get imports
	importOut, _ := exec.Command(r2Path, "-q", "-c", "ii", soFile).Output()
	if importOut != nil {
		for _, line := range strings.Split(string(importOut), "\n") {
			if strings.Contains(line, funcName) || strings.Contains(line, "JNI") {
				ref.Imports = append(ref.Imports, strings.TrimSpace(line))
			}
		}
	}

	return []NativeRef{ref}
}

func buildCallGraph(flow *types.Flow, javaRefs []JavaRef, nativeRefs []NativeRef) []CallEdge {
	var edges []CallEdge

	httpNode := fmt.Sprintf("%s %s", flow.Method, flow.Path)
	edges = append(edges, CallEdge{From: "App", To: httpNode, Type: "http", Label: flow.Host})

	for _, jr := range javaRefs {
		javaNode := jr.Class
		if jr.Method != "" {
			javaNode += "." + jr.Method + "()"
		}
		edges = append(edges, CallEdge{From: httpNode, To: javaNode, Type: "java_call", Label: jr.Annotation})

		if jr.CallsNative {
			for _, nm := range jr.NativeMethods {
				if strings.HasSuffix(nm, ".so") {
					edges = append(edges, CallEdge{From: javaNode, To: nm, Type: "jni", Label: "loadLibrary"})
				} else {
					edges = append(edges, CallEdge{From: javaNode, To: "native:" + nm, Type: "jni", Label: "JNI"})
				}
			}
		}
	}

	for _, nr := range nativeRefs {
		nativeNode := nr.SOFile + ":" + nr.Function
		for _, call := range nr.Calls {
			edges = append(edges, CallEdge{From: nativeNode, To: call, Type: "native_call"})
		}
	}

	return edges
}

func generateMermaid(edges []CallEdge) string {
	var lines []string
	lines = append(lines, "graph TD")

	nodeID := func(name string) string {
		id := strings.NewReplacer(" ", "_", ".", "_", "(", "", ")", "", "/", "_", ":", "_").Replace(name)
		return id
	}

	for _, e := range edges {
		fromID := nodeID(e.From)
		toID := nodeID(e.To)
		label := ""
		if e.Label != "" {
			label = "|" + e.Label + "|"
		}

		style := "-->"
		switch e.Type {
		case "jni":
			style = "-.->|JNI|"
		case "native_call":
			style = "==>"
		case "http":
			style = "-->|HTTP|"
		}

		if label != "" && e.Type != "jni" && e.Type != "http" {
			lines = append(lines, fmt.Sprintf("    %s %s %s", fromID, style, toID))
		} else {
			lines = append(lines, fmt.Sprintf("    %s %s %s", fromID, style, toID))
		}
	}

	return strings.Join(lines, "\n")
}

func generateSummary(result *TraceResult) string {
	parts := []string{
		fmt.Sprintf("Flow: %s %s", result.Method, result.URL),
	}
	if len(result.JavaTrace) > 0 {
		parts = append(parts, fmt.Sprintf("Java: %d source locations found", len(result.JavaTrace)))
		for _, jr := range result.JavaTrace {
			parts = append(parts, fmt.Sprintf("  → %s:%d", jr.File, jr.Line))
		}
	}
	if len(result.NativeTrace) > 0 {
		parts = append(parts, fmt.Sprintf("Native: %d SO functions analyzed", len(result.NativeTrace)))
	}
	return strings.Join(parts, "\n")
}

func ToJSON(result *TraceResult) string {
	data, _ := json.MarshalIndent(result, "", "  ")
	return string(data)
}
