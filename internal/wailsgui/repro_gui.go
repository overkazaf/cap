package wailsgui

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/overkazaf/cap/internal/config"
	"github.com/overkazaf/cap/internal/repro"
)

// ==================== P1 Professional RE Extensions ====================

// AnalyzeUnidbgLog parses raw Unidbg execution logs, deduplicates missing JNI
// callbacks, files, system properties, and libraries, and synthesizes ready-to-compile
// Java stub snippets.
func (a *App) AnalyzeUnidbgLog(rawLog string) *repro.UnidbgStubDiagnosis {
	return repro.AnalyzeUnidbgLog(rawLog)
}

// GenerateFridaEnvSnapshotScript generates a Frida JS script that snapshots real
// Android device runtime properties as JSON ready for Unidbg stubs.
func (a *App) GenerateFridaEnvSnapshotScript(targetPkg string) *repro.GeneratedToolScript {
	return repro.GenerateFridaEnvSnapshotScript(targetPkg)
}

// DetectJadx probes the host for a runnable jadx CLI binary.
func (a *App) DetectJadx(preferred string) repro.JadxInfo {
	pref := strings.TrimSpace(preferred)
	if pref == "" {
		pref = strings.TrimSpace(a.GetSetting("re_jadx_path"))
	}
	return repro.DetectJadx(pref)
}

// DecompileAPKWithJadx decompiles an APK/DEX into a deterministic cached workspace
// under <certDir>/jadx-cache with a 3-minute timeout, falling back to pure-Go DEX
// extraction when jadx is unavailable.
func (a *App) DecompileAPKWithJadx(apkPath string, maxClasses int) (*repro.JadxWorkspace, error) {
	a.mu.Lock()
	capDir := a.certDir
	jadxPath := strings.TrimSpace(a.settings["re_jadx_path"])
	a.mu.Unlock()

	if strings.TrimSpace(capDir) == "" {
		capDir = config.DefaultDir()
	}
	cacheDir := filepath.Join(capDir, "jadx-cache")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	return repro.DecompileAPK(ctx, apkPath, jadxPath, cacheDir, maxClasses)
}

// ListJadxClasses lists decompiled Java classes inside workspaceDir.
func (a *App) ListJadxClasses(workspaceDir, filter string, limit int) ([]repro.JadxClassEntry, error) {
	return repro.ListClasses(workspaceDir, filter, limit)
}

// ReadJadxClassSource reads the full decompiled Java source for className in workspaceDir.
func (a *App) ReadJadxClassSource(workspaceDir, className string) (*repro.JadxClassSource, error) {
	return repro.ReadClassSource(workspaceDir, className)
}

// SearchJadxSource performs case-insensitive text search across decompiled .java files.
func (a *App) SearchJadxSource(workspaceDir, query string, maxHits int) ([]repro.JadxSearchHit, error) {
	return repro.SearchSource(workspaceDir, query, maxHits)
}

// LinkJavaToNative cross-links Java native declarations in workspaceDir against
// ELF exports in soPath and optional Frida RegisterNatives JSON records.
func (a *App) LinkJavaToNative(workspaceDir, soPath, registerNativesJSON string) (*repro.JavaNativeLinkReport, error) {
	return repro.LinkJavaToNative(workspaceDir, soPath, registerNativesJSON)
}

// ExportSymbolScript exports a SymbolBundle as an IDAPython script ("ida"),
// Ghidra Python script ("ghidra"), or normalized SymbolBundle JSON ("json").
func (a *App) ExportSymbolScript(bundle repro.SymbolBundle, format string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "ida":
		if _, err := repro.ExportSymbolBundleJSON(&bundle); err != nil {
			return "", err
		}
		return repro.ExportIDAPython(&bundle), nil
	case "ghidra":
		if _, err := repro.ExportSymbolBundleJSON(&bundle); err != nil {
			return "", err
		}
		return repro.ExportGhidraPython(&bundle), nil
	case "json":
		return repro.ExportSymbolBundleJSON(&bundle)
	default:
		return "", fmt.Errorf("unsupported symbol export format %q (expected ida, ghidra, or json)", format)
	}
}

// ImportSymbolBundleJSON parses, validates, and normalizes a SymbolBundle JSON document.
func (a *App) ImportSymbolBundleJSON(raw string) (*repro.SymbolBundle, error) {
	return repro.ImportSymbolBundleJSON(raw)
}

// AnalyzeIOSBinary statically inspects a standalone Mach-O, Fat Mach-O, or .ipa archive.
func (a *App) AnalyzeIOSBinary(filePath string) (*repro.IOSBinaryReport, error) {
	return repro.AnalyzeIOSBinary(filePath)
}

// GenerateUnidbgIOSHarness generates a DarwinEmulatorBuilder Unidbg iOS Java harness.
func (a *App) GenerateUnidbgIOSHarness(opts repro.UnidbgIOSOptions) *repro.GeneratedToolScript {
	return repro.GenerateUnidbgIOSHarness(opts)
}

// GenerateIOSStealthScript generates an authorized Frida iOS stealth diagnostic script.
func (a *App) GenerateIOSStealthScript(opts repro.IOSStealthOptions) *repro.GeneratedToolScript {
	return repro.GenerateIOSStealthScript(opts)
}
