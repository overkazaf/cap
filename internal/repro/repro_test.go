package repro

import (
	"archive/zip"
	"bytes"
	"context"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// --- 1. Unidbg Auto-Stub & Frida Env Snapshot Tests --------------------------

func TestAnalyzeUnidbgLogFullCoverage(t *testing.T) {
	rawLog := strings.Join([]string{
		"java.lang.UnsupportedOperationException: callObjectMethodV: android/content/Context->getPackageName()Ljava/lang/String;",
		"java.lang.UnsupportedOperationException: callObjectMethodV: android/content/Context->getPackageName()Ljava/lang/String;",
		"java.lang.UnsupportedOperationException: android/content/pm/PackageManager->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;",
		"    at com.github.unidbg.linux.android.dvm.AbstractJni.callObjectMethodV(AbstractJni.java:258)",
		"java.lang.UnsupportedOperationException: callObjectMethodV: android/content/pm/Signature->toByteArray()[B",
		"java.lang.UnsupportedOperationException: callStaticObjectMethodV: android/provider/Settings$Secure->getString(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;",
		"java.lang.UnsupportedOperationException: getStaticObjectField: android/os/Build->MODEL:Ljava/lang/String;",
		"java.lang.UnsupportedOperationException: android/os/Build->FINGERPRINT:Ljava/lang/String;",
		"    at com.github.unidbg.linux.android.dvm.AbstractJni.getStaticObjectField(AbstractJni.java:436)",
		"java.lang.UnsupportedOperationException: getObjectField: android/content/pm/PackageInfo->signatures:[Landroid/content/pm/Signature;",
		"java.lang.UnsupportedOperationException: getObjectField: android/content/pm/ApplicationInfo->sourceDir:Ljava/lang/String;",
		"java.lang.UnsupportedOperationException: callIntMethodV: android/telephony/TelephonyManager->getNetworkType()I",
		"java.lang.UnsupportedOperationException: callBooleanMethodV: java/io/File->exists()Z",
		"java.lang.UnsupportedOperationException: newObjectV: java/io/File-><init>(Ljava/lang/String;)V",
		"java.lang.UnsupportedOperationException: resolveClass: com/example/secret/NativeBridge",
		"WARN [ARM64SyscallHandler] - openat dirfd=-100, pathname=/proc/self/cmdline, oflags=0x0 => -2",
		"WARN [ARM64SyscallHandler] - openat dirfd=-100, pathname=/proc/self/cmdline, oflags=0x0 => -2",
		"java.io.FileNotFoundException: /proc/cpuinfo",
		"FileResult resolve failed: /system/build.prop",
		"WARN [SystemPropertyHook] - __system_property_get(\"ro.build.fingerprint\")",
		"WARN [SystemPropertyHook] - __system_property_get(\"ro.build.fingerprint\")",
		"WARN [SystemPropertyHook] - key=ro.product.model",
		"WARN [SystemPropertyHook] - Unsupported system property: ro.debuggable",
		"WARN [DalvikModule] - Library not found: libcrypto.so",
		"ERROR - dlopen failed: library \"libguard_v2.so\" not found",
	}, "\n")

	diag := AnalyzeUnidbgLog(rawLog)
	if diag == nil {
		t.Fatal("AnalyzeUnidbgLog returned nil")
	}

	// Verify deduplication and callback coverage.
	cbSeen := make(map[string]bool)
	pkgCount := 0
	smartCount := 0
	for _, it := range diag.MissingJNI {
		cbSeen[it.Callback] = true
		if it.Signature == "android/content/Context->getPackageName()Ljava/lang/String;" {
			pkgCount = it.Count
		}
		if it.SmartMatch {
			smartCount++
		}
	}

	expectedCBs := []string{
		CallbackCallObjectMethodV,
		CallbackCallStaticObjectMethodV,
		CallbackGetStaticObjectField,
		CallbackGetObjectField,
		CallbackCallIntMethodV,
		CallbackCallBooleanMethodV,
		CallbackNewObjectV,
		CallbackResolveClass,
	}
	for _, cb := range expectedCBs {
		if !cbSeen[cb] {
			t.Errorf("expected callback %q to be parsed from log, got map=%v", cb, cbSeen)
		}
	}
	if pkgCount != 2 {
		t.Errorf("expected getPackageName deduplicated count=2, got %d", pkgCount)
	}
	if smartCount < 8 {
		t.Errorf("expected >=8 smart defaults matched, got %d", smartCount)
	}

	// Verify missing classes, files, properties, libraries.
	if len(diag.MissingClasses) != 1 || diag.MissingClasses[0] != "com/example/secret/NativeBridge" {
		t.Errorf("unexpected MissingClasses: %v", diag.MissingClasses)
	}
	if len(diag.MissingFiles) != 3 {
		t.Errorf("expected 3 deduplicated missing files, got %d (%v)", len(diag.MissingFiles), diag.MissingFiles)
	}
	if diag.MissingFiles[0].Path != "/proc/self/cmdline" || diag.MissingFiles[0].Count != 2 {
		t.Errorf("expected /proc/self/cmdline count=2, got %+v", diag.MissingFiles[0])
	}
	if len(diag.MissingSysProps) != 3 {
		t.Errorf("expected 3 deduplicated sys props, got %d (%v)", len(diag.MissingSysProps), diag.MissingSysProps)
	}
	if diag.MissingSysProps[0].Key != "ro.build.fingerprint" || diag.MissingSysProps[0].Count != 2 {
		t.Errorf("expected ro.build.fingerprint count=2, got %+v", diag.MissingSysProps[0])
	}
	if len(diag.MissingLibraries) != 2 {
		t.Errorf("expected 2 missing libraries, got %d (%v)", len(diag.MissingLibraries), diag.MissingLibraries)
	}

	// Verify generated Java snippets contain expected override signatures and realistic defaults.
	for _, needle := range []string{
		"public DvmObject<?> callObjectMethodV(",
		"public DvmObject<?> callStaticObjectMethodV(",
		"public DvmObject<?> getStaticObjectField(",
		"public DvmObject<?> getObjectField(",
		"public int callIntMethodV(",
		"public boolean callBooleanMethodV(",
		"public DvmObject<?> newObjectV(",
		"android/content/Context->getPackageName()Ljava/lang/String;",
		"android/os/Build->MODEL:Ljava/lang/String;",
		"Pixel 7",
		"ANDROID_ID",
		"SIGNING_CERT_HEX",
		"registerMissingClasses",
	} {
		if !strings.Contains(diag.AbstractJniSnippet, needle) {
			t.Errorf("AbstractJniSnippet missing %q", needle)
		}
	}
	for _, needle := range []string{
		"public FileResult<AndroidFileIO> resolve(",
		`case "/proc/self/cmdline":`,
		`case "/proc/cpuinfo":`,
		`case "/system/build.prop":`,
	} {
		if !strings.Contains(diag.IOResolverSnippet, needle) {
			t.Errorf("IOResolverSnippet missing %q", needle)
		}
	}
	for _, needle := range []string{
		"new SystemPropertyHook(emulator)",
		`case "ro.build.fingerprint":`,
		`case "ro.product.model":`,
		`case "ro.debuggable":`,
	} {
		if !strings.Contains(diag.SysPropHookSnippet, needle) {
			t.Errorf("SysPropHookSnippet missing %q", needle)
		}
	}
	if !strings.Contains(diag.CombinedJavaSnippet, "callObjectMethodV") ||
		!strings.Contains(diag.CombinedJavaSnippet, "FileResult<AndroidFileIO>") ||
		!strings.Contains(diag.CombinedJavaSnippet, "SystemPropertyHook") {
		t.Error("CombinedJavaSnippet should include all 3 snippet sections")
	}
}

func TestFridaEnvSnapshotScriptSyntaxWithNode(t *testing.T) {
	script := GenerateFridaEnvSnapshotScript("com.example.shop")
	if script == nil || script.Code == "" {
		t.Fatal("GenerateFridaEnvSnapshotScript returned empty script")
	}
	for _, needle := range []string{
		"unidbg_env_snapshot",
		"android.os.Build",
		"android.os.Build$VERSION",
		"android.os.SystemProperties",
		"android.provider.Settings$Secure",
		"android_id",
		"shared_prefs",
		"SHA-256",
		"com.example.shop",
	} {
		if !strings.Contains(script.Code, needle) {
			t.Errorf("Frida env snapshot script missing %q", needle)
		}
	}
	verifyNodeSyntax(t, "unidbg_env_snapshot.js", script.Code)
}

// --- 2. JADX Workspace, Cache Reuse, Path Traversal, JNI Linking Tests -------

func TestJadxMockDecompileCacheReuseAndTraversal(t *testing.T) {
	tmp := t.TempDir()
	apkPath := filepath.Join(tmp, "sample.apk")
	if err := os.WriteFile(apkPath, []byte("PK\x03\x04mock-apk-payload"), 0o644); err != nil {
		t.Fatalf("write fake apk: %v", err)
	}

	counterFile := filepath.Join(tmp, "jadx_invocations.txt")
	mockJadx := filepath.Join(tmp, "mock-jadx")
	mockScript := `#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "1.5.0-mock"
  exit 0
fi
echo "run" >> "` + counterFile + `"
OUT=""
while [ $# -gt 0 ]; do
  if [ "$1" = "-d" ]; then
    OUT="$2"
    shift 2
    continue
  fi
  shift
done
mkdir -p "$OUT/sources/com/example/app_v2"
cat > "$OUT/sources/com/example/app_v2/Native_Signer.java" <<'EOF'
package com.example.app_v2;

import android.content.Context;

public class Native_Signer {
    public static native String sign_request(Context ctx, String payload, byte[] body);
    public native int check_token(String token);
    public native void dynamic_init(long ts);
    public native String unresolved_hook(int flag);
}
EOF
cat > "$OUT/sources/com/example/app_v2/PlainHelper.java" <<'EOF'
package com.example.app_v2;

public class PlainHelper {
    public String format(String in) {
        return "SIG:" + in;
    }
}
EOF
exit 0
`
	if err := os.WriteFile(mockJadx, []byte(mockScript), 0o755); err != nil {
		t.Fatalf("write mock jadx: %v", err)
	}

	// DetectJadx should detect the mock CLI cleanly.
	info := DetectJadx(mockJadx)
	if !info.Available || info.Version != "1.5.0-mock" {
		t.Fatalf("DetectJadx failed: %+v", info)
	}

	cacheDir := filepath.Join(tmp, "cache")
	ws1, err := DecompileAPK(context.Background(), apkPath, mockJadx, cacheDir, 0)
	if err != nil {
		t.Fatalf("first DecompileAPK failed: %v", err)
	}
	if ws1.CacheHit || ws1.Mode != WorkspaceModeJadx || ws1.ClassCount != 2 || ws1.NativeClassCount != 1 {
		t.Fatalf("unexpected ws1: %+v", ws1)
	}

	// Repeat call MUST reuse cache without executing mock-jadx again.
	ws2, err := DecompileAPK(context.Background(), apkPath, mockJadx, cacheDir, 0)
	if err != nil {
		t.Fatalf("second DecompileAPK failed: %v", err)
	}
	if !ws2.CacheHit || ws2.WorkspaceDir != ws1.WorkspaceDir || ws2.CacheKey != ws1.CacheKey {
		t.Fatalf("expected cache hit on repeat call, got ws2=%+v", ws2)
	}
	invBytes, err := os.ReadFile(counterFile)
	if err != nil {
		t.Fatalf("read counter: %v", err)
	}
	if lines := strings.Split(strings.TrimSpace(string(invBytes)), "\n"); len(lines) != 1 {
		t.Fatalf("expected jadx invoked exactly once (cached on 2nd call), got %d invocations", len(lines))
	}

	// ListClasses + filter + native flagging.
	classes, err := ListClasses(ws1.WorkspaceDir, "", 10)
	if err != nil {
		t.Fatalf("ListClasses failed: %v", err)
	}
	if len(classes) != 2 {
		t.Fatalf("expected 2 classes, got %d", len(classes))
	}
	if !classes[0].HasNative || len(classes[0].NativeMethods) != 4 {
		t.Errorf("expected Native_Signer to have 4 native methods, got %+v", classes[0])
	}
	if classes[1].HasNative {
		t.Errorf("expected PlainHelper HasNative=false, got %+v", classes[1])
	}

	filtered, err := ListClasses(ws1.WorkspaceDir, "plainhelper", 10)
	if err != nil || len(filtered) != 1 || filtered[0].SimpleName != "PlainHelper" {
		t.Fatalf("filtered ListClasses failed: %v %+v", err, filtered)
	}

	// ReadClassSource valid + path traversal rejection.
	src, err := ReadClassSource(ws1.WorkspaceDir, "com.example.app_v2.Native_Signer")
	if err != nil {
		t.Fatalf("ReadClassSource failed: %v", err)
	}
	if !src.HasNative || len(src.NativeMethods) != 4 {
		t.Fatalf("expected 4 native methods in source, got %+v", src)
	}

	// Strict path traversal rejections.
	traversalInputs := []string{
		"../secret.txt",
		"../../etc/passwd",
		"/etc/passwd",
		`com\..\..\etc\passwd`,
		"com/example/../../../etc/passwd.java",
		"com..example.Foo",
		"com.example.Foo\x00.java",
		"C:foo.java",
	}
	for _, bad := range traversalInputs {
		if _, rerr := ReadClassSource(ws1.WorkspaceDir, bad); rerr == nil {
			t.Errorf("expected ReadClassSource(%q) to reject path traversal, but it succeeded", bad)
		}
	}

	// Symlink escape rejection.
	outsideFile := filepath.Join(tmp, "outside_secret.java")
	_ = os.WriteFile(outsideFile, []byte("class Secret {}"), 0o644)
	symPath := filepath.Join(ws1.WorkspaceDir, "sources", "com", "example", "app_v2", "Escape.java")
	if err := os.Symlink(outsideFile, symPath); err == nil {
		if _, serr := ReadClassSource(ws1.WorkspaceDir, "com.example.app_v2.Escape"); serr == nil {
			t.Error("expected symlink escape to be rejected by ReadClassSource")
		}
	}

	// SearchSource case-insensitive search.
	hits, err := SearchSource(ws1.WorkspaceDir, "sig:", 10)
	if err != nil {
		t.Fatalf("SearchSource failed: %v", err)
	}
	if len(hits) != 1 || hits[0].ClassName != "com.example.app_v2.PlainHelper" || hits[0].Line != 5 {
		t.Fatalf("unexpected SearchSource hits: %+v", hits)
	}

	// Verify JNI mangling (_1, _2, _3 escaping) and ELF + RegisterNatives linking.
	shortName, longName := MangleJNIName(
		"com.example.app_v2.Native_Signer",
		"sign_request",
		"(Landroid/content/Context;Ljava/lang/String;[B)Ljava/lang/String;",
	)
	wantShort := "Java_com_example_app_1v2_Native_1Signer_sign_1request"
	wantLong := "Java_com_example_app_1v2_Native_1Signer_sign_1request__Landroid_content_Context_2Ljava_lang_String_2_3B"
	if shortName != wantShort {
		t.Errorf("short mangled mismatch:\n got: %s\nwant: %s", shortName, wantShort)
	}
	if longName != wantLong {
		t.Errorf("long mangled mismatch:\n got: %s\nwant: %s", longName, wantLong)
	}

	// Build synthetic ELF64 .so exporting long JNI name, short JNI name, and one orphan Java_* export.
	soPath := filepath.Join(tmp, "libnative.so")
	elfBytes := buildTestELF64(t, []testELFSym{
		{name: wantLong, addr: 0x1100, size: 64},
		{name: "Java_com_example_app_1v2_Native_1Signer_check_1token", addr: 0x1200, size: 48},
		{name: "Java_com_example_other_Orphan_ping", addr: 0x1300, size: 32},
	})
	if err := os.WriteFile(soPath, elfBytes, 0o644); err != nil {
		t.Fatalf("write synthetic ELF: %v", err)
	}

	regJSON := `[
		{"class": "com/example/app_v2/Native_Signer", "name": "dynamic_init", "signature": "(J)V", "offset": "0x2400", "symbol": "sub_2400", "module": "libnative.so"}
	]`

	linkReport, err := LinkJavaToNative(ws1.WorkspaceDir, soPath, regJSON)
	if err != nil {
		t.Fatalf("LinkJavaToNative failed: %v", err)
	}
	if linkReport.TotalNativeMethods != 4 || linkReport.StaticCount != 2 || linkReport.DynamicCount != 1 || linkReport.UnresolvedCount != 1 {
		t.Fatalf("unexpected link counts: %+v", linkReport)
	}
	if linkReport.SOArch != "arm64" {
		t.Errorf("expected SOArch=arm64, got %q", linkReport.SOArch)
	}
	if len(linkReport.OrphanExports) != 1 || linkReport.OrphanExports[0] != "Java_com_example_other_Orphan_ping" {
		t.Errorf("unexpected OrphanExports: %v", linkReport.OrphanExports)
	}

	byMethod := make(map[string]JavaNativeBinding)
	for _, b := range linkReport.Bindings {
		byMethod[b.JavaMethod] = b
	}
	if byMethod["sign_request"].BindingKind != BindingStaticExport || byMethod["sign_request"].NativeAddr != "0x1100" {
		t.Errorf("sign_request binding wrong: %+v", byMethod["sign_request"])
	}
	if byMethod["check_token"].BindingKind != BindingStaticExport || byMethod["check_token"].NativeAddr != "0x1200" {
		t.Errorf("check_token binding wrong: %+v", byMethod["check_token"])
	}
	if byMethod["dynamic_init"].BindingKind != BindingDynamicRegister || byMethod["dynamic_init"].NativeAddr != "0x2400" || byMethod["dynamic_init"].NativeSymbol != "sub_2400" {
		t.Errorf("dynamic_init binding wrong: %+v", byMethod["dynamic_init"])
	}
	if byMethod["unresolved_hook"].BindingKind != BindingUnresolved {
		t.Errorf("unresolved_hook binding wrong: %+v", byMethod["unresolved_hook"])
	}
}

func TestDecompileAPKPureGoDEXFallback(t *testing.T) {
	tmp := t.TempDir()
	apkPath := filepath.Join(tmp, "fallback.apk")
	dexBytes := buildMinimalSyntheticDEX("Lcom/example/fallback/CryptoNative;", "nativeHash", "(Ljava/lang/String;)Ljava/lang/String;", true)
	writeZipArchive(t, apkPath, map[string][]byte{
		"classes.dex": dexBytes,
	})

	cacheDir := filepath.Join(tmp, "cache")
	ws, err := DecompileAPK(context.Background(), apkPath, filepath.Join(tmp, "missing-jadx-bin"), cacheDir, 50)
	if err != nil {
		t.Fatalf("pure-Go DEX fallback failed: %v", err)
	}
	if ws.Mode != WorkspaceModePureGoDEX || ws.ClassCount != 1 || ws.NativeClassCount != 1 {
		t.Fatalf("unexpected fallback workspace: %+v", ws)
	}
	classes, err := ListClasses(ws.WorkspaceDir, "", 10)
	if err != nil || len(classes) != 1 || !classes[0].HasNative || classes[0].ClassName != "com.example.fallback.CryptoNative" {
		t.Fatalf("unexpected fallback classes: err=%v classes=%+v", err, classes)
	}
}

// --- 3. IDA Pro / Ghidra Symbol & Comment Bridge Tests -----------------------

func TestSymbolBridgeJSONAndPythonSyntax(t *testing.T) {
	bundle := &SymbolBundle{
		BinaryName: "libsign.so",
		Arch:       "arm64",
		ImageBase:  "0X00001000",
		Functions: []SymbolItem{
			{
				Name:      "sign_hmac_sha256",
				Address:   "0x00401234",
				Size:      128,
				Signature: "int sign_hmac_sha256(const char *in, char *out)",
				Comment:   "Entry \"signer\" with newline\nand unicode 签名",
			},
		},
		Comments: []CommentItem{
			{
				Address:    "401250",
				Text:       "XOR key schedule 'round 1'",
				Repeatable: true,
			},
		},
		JNIBindings: []JavaNativeBinding{
			{
				JavaClass:     "com.example.Signer",
				JavaMethod:    "sign",
				JavaSignature: "(Ljava/lang/String;)Ljava/lang/String;",
				MangledName:   "Java_com_example_Signer_sign",
				NativeSymbol:  "Java_com_example_Signer_sign",
				NativeAddr:    "0X00401234",
				BindingKind:   BindingStaticExport,
			},
		},
	}

	exportedJSON, err := ExportSymbolBundleJSON(bundle)
	if err != nil {
		t.Fatalf("ExportSymbolBundleJSON failed: %v", err)
	}

	imported, err := ImportSymbolBundleJSON(exportedJSON)
	if err != nil {
		t.Fatalf("ImportSymbolBundleJSON failed: %v", err)
	}
	if imported.ImageBase != "0x1000" {
		t.Errorf("expected normalized ImageBase 0x1000, got %q", imported.ImageBase)
	}
	if imported.Functions[0].Address != "0x401234" {
		t.Errorf("expected normalized function address 0x401234, got %q", imported.Functions[0].Address)
	}
	if imported.Comments[0].Address != "0x401250" {
		t.Errorf("expected normalized comment address 0x401250, got %q", imported.Comments[0].Address)
	}
	if imported.JNIBindings[0].NativeAddr != "0x401234" {
		t.Errorf("expected normalized JNI address 0x401234, got %q", imported.JNIBindings[0].NativeAddr)
	}

	// Strict validation errors.
	if _, err := ImportSymbolBundleJSON(`{"binary_name":"","functions":[]}`); err == nil {
		t.Error("expected error for missing binary_name")
	}
	if _, err := ImportSymbolBundleJSON(`{"binary_name":"a.so","functions":[{"name":"fn","address":"not-hex"}]}`); err == nil {
		t.Error("expected error for invalid hex address")
	}
	if _, err := ImportSymbolBundleJSON(`{"binary_name":"a.so","comments":[{"address":"0x10","text":""}]}`); err == nil {
		t.Error("expected error for empty comment text")
	}

	// Verify both IDAPython and Ghidra Python scripts compile cleanly via python3 -m py_compile.
	idaPy := ExportIDAPython(imported)
	for _, needle := range []string{"import idaapi", "import idc", "idc.set_name", "idc.set_cmt", "sign_hmac_sha256"} {
		if !strings.Contains(idaPy, needle) {
			t.Errorf("IDAPython script missing %q", needle)
		}
	}
	verifyPythonSyntax(t, "cap_ida_bridge.py", idaPy)

	ghidraPy := ExportGhidraPython(imported)
	for _, needle := range []string{"currentProgram", "createLabel", "setEOLComment", "sign_hmac_sha256"} {
		if !strings.Contains(ghidraPy, needle) {
			t.Errorf("Ghidra Python script missing %q", needle)
		}
	}
	verifyPythonSyntax(t, "cap_ghidra_bridge.py", ghidraPy)
}

// --- 4. iOS Mach-O / Fat Mach-O / IPA & Templates Tests ----------------------

func TestAnalyzeIOSMachOAndIPA(t *testing.T) {
	tmp := t.TempDir()

	// Build a synthetic 64-bit ARM64 Mach-O with:
	// - PIE + NX flags
	// - LC_ENCRYPTION_INFO_64 (cryptid = 1)
	// - LC_BUILD_VERSION (iOS 15.0)
	// - LC_LOAD_DYLIB (UIKit, Foundation)
	// - LC_SYMTAB (_objc_release -> ARC, ___stack_chk_fail -> Canary, _sign_payload export)
	// - __TEXT/__objc_classname + __TEXT/__objc_methname + __DATA/__objc_classlist
	machoBytes := buildSyntheticMachO64(t, synthMachOOpts{
		cpu:         macho.CpuArm64,
		pie:         true,
		nx:          true,
		cryptID:     1,
		minOSMajor:  15,
		minOSMinor:  0,
		dylibs:      []string{"/System/Library/Frameworks/UIKit.framework/UIKit", "/System/Library/Frameworks/Foundation.framework/Foundation", "/usr/lib/libSystem.B.dylib"},
		imports:     []string{"_objc_release", "___stack_chk_fail"},
		exports:     []string{"_sign_payload", "_OBJC_CLASS_$_NetworkSigner"},
		objcClasses: []string{"AppDelegate", "NetworkSigner"},
		objcMethods: []string{"signRequest:timestamp:", "application:didFinishLaunchingWithOptions:"},
	})

	machoPath := filepath.Join(tmp, "DemoApp")
	if err := os.WriteFile(machoPath, machoBytes, 0o755); err != nil {
		t.Fatalf("write synthetic Mach-O: %v", err)
	}

	report, err := AnalyzeIOSBinary(machoPath)
	if err != nil {
		t.Fatalf("AnalyzeIOSBinary(Mach-O) failed: %v", err)
	}
	if report.FileKind != IOSKindMachO || report.IsUniversal {
		t.Errorf("unexpected FileKind/IsUniversal: %+v", report)
	}
	if !report.PIE || !report.NX || !report.ARC || !report.StackCanary {
		t.Errorf("expected PIE/NX/ARC/StackCanary all true, got PIE=%v NX=%v ARC=%v Canary=%v", report.PIE, report.NX, report.ARC, report.StackCanary)
	}
	if !report.FairPlayEncrypted || report.CryptID != 1 {
		t.Errorf("expected FairPlayEncrypted=true CryptID=1, got enc=%v id=%d", report.FairPlayEncrypted, report.CryptID)
	}
	if report.MinOS != "15.0" {
		t.Errorf("expected MinOS=15.0, got %q", report.MinOS)
	}
	if len(report.Architectures) != 1 || report.Architectures[0].Arch != "arm64" {
		t.Errorf("unexpected Architectures: %+v", report.Architectures)
	}
	if len(report.Frameworks) != 2 || report.Frameworks[0] != "Foundation" || report.Frameworks[1] != "UIKit" {
		t.Errorf("unexpected Frameworks: %v", report.Frameworks)
	}
	if len(report.ObjCClasses) != 2 || report.ObjCClasses[0] != "AppDelegate" || report.ObjCClasses[1] != "NetworkSigner" {
		t.Errorf("unexpected ObjCClasses: %v", report.ObjCClasses)
	}
	if len(report.ObjCSelectors) != 2 {
		t.Errorf("unexpected ObjCSelectors: %v", report.ObjCSelectors)
	}

	// Build a synthetic .ipa archive containing Info.plist + the Mach-O binary.
	infoPlistXML := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>com.example.demoios</string>
	<key>CFBundleName</key>
	<string>DemoApp</string>
	<key>CFBundleDisplayName</key>
	<string>Demo iOS</string>
	<key>CFBundleExecutable</key>
	<string>DemoApp</string>
	<key>CFBundleShortVersionString</key>
	<string>2.4.1</string>
	<key>CFBundleVersion</key>
	<string>241</string>
	<key>MinimumOSVersion</key>
	<string>15.0</string>
	<key>CFBundleURLTypes</key>
	<array>
		<dict>
			<key>CFBundleURLSchemes</key>
			<array>
				<string>demoapp</string>
				<string>demoapp-oauth</string>
			</array>
		</dict>
	</array>
	<key>LSApplicationQueriesSchemes</key>
	<array>
		<string>cydia</string>
		<string>weixin</string>
	</array>
	<key>NSAppTransportSecurity</key>
	<dict>
		<key>NSAllowsArbitraryLoads</key>
		<true/>
		<key>NSExceptionDomains</key>
		<dict>
			<key>api.example.com</key>
			<dict>
				<key>NSExceptionAllowsInsecureHTTPLoads</key>
				<true/>
			</dict>
		</dict>
	</dict>
</dict>
</plist>`

	ipaPath := filepath.Join(tmp, "DemoApp.ipa")
	writeZipArchive(t, ipaPath, map[string][]byte{
		"Payload/DemoApp.app/Info.plist": []byte(infoPlistXML),
		"Payload/DemoApp.app/DemoApp":    machoBytes,
	})

	ipaReport, err := AnalyzeIOSBinary(ipaPath)
	if err != nil {
		t.Fatalf("AnalyzeIOSBinary(.ipa) failed: %v", err)
	}
	if ipaReport.FileKind != IOSKindIPA || ipaReport.InfoPlist == nil {
		t.Fatalf("unexpected IPA report: %+v", ipaReport)
	}
	if ipaReport.InfoPlist.BundleID != "com.example.demoios" || ipaReport.InfoPlist.Version != "2.4.1" {
		t.Errorf("unexpected InfoPlist metadata: %+v", ipaReport.InfoPlist)
	}
	if !ipaReport.InfoPlist.ATSAllowsArbitraryLoads || len(ipaReport.InfoPlist.ATSExceptionDomains) != 1 || ipaReport.InfoPlist.ATSExceptionDomains[0] != "api.example.com" {
		t.Errorf("unexpected ATS settings: %+v", ipaReport.InfoPlist)
	}
	if len(ipaReport.InfoPlist.URLSchemes) != 2 || len(ipaReport.InfoPlist.QueriesSchemes) != 2 {
		t.Errorf("unexpected URL schemes: %+v", ipaReport.InfoPlist)
	}
	if !ipaReport.FairPlayEncrypted || len(ipaReport.ObjCClasses) != 2 {
		t.Errorf("expected IPA Mach-O inspection findings propagated: %+v", ipaReport)
	}

	// Verify zip-slip archive rejection.
	badIPA := filepath.Join(tmp, "evil.ipa")
	writeZipArchive(t, badIPA, map[string][]byte{
		"Payload/../../etc/evil": []byte("nope"),
	})
	if _, err := AnalyzeIOSBinary(badIPA); err == nil {
		t.Error("expected zip-slip IPA to be rejected")
	}

	// Verify JSON serialization round-trip of IOSBinaryReport.
	if _, err := json.Marshal(ipaReport); err != nil {
		t.Fatalf("json.Marshal(ipaReport) failed: %v", err)
	}

	// Build a synthetic Universal Fat Mach-O (arm64 + x86_64) and verify multi-slice inspection.
	x86Slice := buildSyntheticMachO64(t, synthMachOOpts{
		cpu:         macho.CpuAmd64,
		pie:         true,
		nx:          true,
		cryptID:     0,
		minOSMajor:  15,
		minOSMinor:  0,
		dylibs:      []string{"/usr/lib/libSystem.B.dylib"},
		imports:     []string{"_objc_release"},
		exports:     []string{"_sign_payload"},
		objcClasses: []string{"SimulatorHelper"},
		objcMethods: []string{"simPing"},
	})
	fatBytes := buildSyntheticFatMachO(t, []fatSliceSpec{
		{cpu: macho.CpuArm64, data: machoBytes},
		{cpu: macho.CpuAmd64, data: x86Slice},
	})
	fatPath := filepath.Join(tmp, "DemoAppUniversal")
	if err := os.WriteFile(fatPath, fatBytes, 0o755); err != nil {
		t.Fatalf("write fat Mach-O: %v", err)
	}
	fatReport, err := AnalyzeIOSBinary(fatPath)
	if err != nil {
		t.Fatalf("AnalyzeIOSBinary(Fat Mach-O) failed: %v", err)
	}
	if !fatReport.IsUniversal || fatReport.FileKind != IOSKindFatMachO || len(fatReport.Architectures) != 2 {
		t.Fatalf("unexpected Universal Fat Mach-O report: %+v", fatReport)
	}
	if !fatReport.FairPlayEncrypted || len(fatReport.ObjCClasses) != 3 {
		t.Errorf("expected merged FairPlay flag & 3 ObjC classes across slices, got enc=%v classes=%v", fatReport.FairPlayEncrypted, fatReport.ObjCClasses)
	}
}

type fatSliceSpec struct {
	cpu  macho.Cpu
	data []byte
}

func buildSyntheticFatMachO(t *testing.T, slices []fatSliceSpec) []byte {
	t.Helper()
	be := binary.BigEndian
	const alignPow = 12 // 4096-byte page alignment
	const pageSize = 1 << alignPow

	// Fat header: 8 bytes + 20 bytes per arch
	hdrLen := 8 + len(slices)*20
	curOff := ((hdrLen + pageSize - 1) / pageSize) * pageSize

	offsets := make([]int, len(slices))
	for i, s := range slices {
		offsets[i] = curOff
		curOff += ((len(s.data) + pageSize - 1) / pageSize) * pageSize
	}

	out := make([]byte, curOff)
	be.PutUint32(out[0:4], macho.MagicFat)
	be.PutUint32(out[4:8], uint32(len(slices)))
	for i, s := range slices {
		base := 8 + i*20
		be.PutUint32(out[base:base+4], uint32(s.cpu))
		be.PutUint32(out[base+4:base+8], 0)
		be.PutUint32(out[base+8:base+12], uint32(offsets[i]))
		be.PutUint32(out[base+12:base+16], uint32(len(s.data)))
		be.PutUint32(out[base+16:base+20], alignPow)
		copy(out[offsets[i]:], s.data)
	}
	return out
}

func TestIOSHarnessAndStealthTemplates(t *testing.T) {
	harness := GenerateUnidbgIOSHarness(UnidbgIOSOptions{
		BundleID:     "com.example.demoios",
		BinaryPath:   "/tmp/DemoApp",
		ObjCClass:    "NetworkSigner",
		ObjCSelector: "signRequest:",
		Args:         []string{"hello=world"},
	})
	for _, needle := range []string{
		"DarwinEmulatorBuilder.for64Bit()",
		"DarwinResolver",
		"NetworkSigner",
		"signRequest:",
		"[CAP_RE]",
	} {
		if !strings.Contains(harness.Code, needle) {
			t.Errorf("Unidbg iOS harness missing %q", needle)
		}
	}

	stealth := GenerateIOSStealthScript(IOSStealthOptions{
		BundleID:          "com.example.demoios",
		TargetBinary:      "DemoApp",
		CustomHidePaths:   []string{"/var/custom_jb"},
		CustomHideSchemes: []string{"customjb://"},
	})
	for _, needle := range []string{
		"PT_DENY_ATTACH",
		"ptrace",
		"sysctl",
		"P_TRACED",
		"getppid",
		"_dyld_image_count",
		"_dyld_get_image_name",
		"dladdr",
		"NSFileManager",
		"canOpenURL:",
		"/var/custom_jb",
		"customjb://",
	} {
		if !strings.Contains(stealth.Code, needle) {
			t.Errorf("iOS stealth script missing %q", needle)
		}
	}
	verifyNodeSyntax(t, "ios_stealth.js", stealth.Code)
}

// --- 5. Security & Correctness Audit Regressions -----------------------------

func TestAuditInjectionHardening(t *testing.T) {
	// 1. Adversarial JS comment/string injection via U+2028 / U+2029 / NUL / quotes
	evilPkg := "com.evil\u2028process.exit(1);//\u2029'\"\\\x00\x07"
	envScript := GenerateFridaEnvSnapshotScript(evilPkg)
	if strings.ContainsAny(envScript.Code, "\u2028\u2029\x00\x07") {
		t.Fatal("Frida env snapshot script contains raw U+2028/U+2029/control bytes")
	}
	verifyNodeSyntax(t, "evil_env_snapshot.js", envScript.Code)

	iosStealth := GenerateIOSStealthScript(IOSStealthOptions{
		BundleID:          evilPkg,
		TargetBinary:      "App\u2028throw new Error('pwned');//\x00",
		CustomHidePaths:   []string{"/tmp/bad\u2028'\"\\\x00path"},
		CustomHideSchemes: []string{"bad\u2029'scheme://"},
	})
	if strings.ContainsAny(iosStealth.Code, "\u2028\u2029\x00\x07") {
		t.Fatal("iOS stealth script contains raw U+2028/U+2029/control bytes")
	}
	verifyNodeSyntax(t, "evil_ios_stealth.js", iosStealth.Code)

	// 2. Adversarial Java JLS §3.3 Unicode escape breakout (\u000a / \u000d) & NUL bytes
	evilJavaLog := "java.lang.UnsupportedOperationException: callIntMethodV: com/evil/Foo->bar\\u000aRuntime.getRuntime();()I"
	diag := AnalyzeUnidbgLog(evilJavaLog)
	if strings.Contains(diag.AbstractJniSnippet, `\u000aRuntime`) {
		// In comments, backslash must be defanged so JLS §3.3 cannot execute \u000a.
		for _, line := range strings.Split(diag.AbstractJniSnippet, "\n") {
			if idx := strings.Index(line, "//"); idx >= 0 {
				if strings.Contains(line[idx:], `\u000a`) {
					t.Fatalf("Java // comment contains raw JLS §3.3 breakout sequence: %s", line)
				}
			}
		}
	}

	iosHarness := GenerateUnidbgIOSHarness(UnidbgIOSOptions{
		BundleID:   `com.evil\u000aRuntime.getRuntime().exec("id");//` + "\x00",
		BinaryPath: `/tmp/bin\u000d*/evil`,
		ObjCClass:  "OnlyClassWithoutSelector",
	})
	if strings.ContainsAny(iosHarness.Code, "\x00\u2028\u2029") {
		t.Fatal("Unidbg iOS harness contains raw control bytes")
	}
	for _, line := range strings.Split(iosHarness.Code, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") && (strings.Contains(line, `\u000a`) || strings.Contains(line, `\u000d`)) {
			t.Fatalf("Unidbg iOS harness // comment contains raw JLS §3.3 sequence: %s", line)
		}
	}
	// Incomplete ObjCClass without ObjCSelector must not fall through to Long.decode("")
	if !strings.Contains(iosHarness.Code, `TARGET_SYMBOL = "_sign_payload"`) {
		t.Errorf("expected fallback TARGET_SYMBOL when ObjCClass is set without ObjCSelector")
	}

	// 3. Adversarial Python injection with NUL byte + quote breakout
	evilBundle := &SymbolBundle{
		BinaryName: "lib\x00evil\"); __import__(\"os\").system(\"id\"); #",
		Arch:       "arm64\x00\n#injected",
		ImageBase:  "0x1000",
		Functions: []SymbolItem{
			{
				Name:      "fn\"); __import__(\"os\").system(\"id\"); #",
				Address:   "0x1234",
				Signature: "void f(\x00)",
				Comment:   "line1\n\x00\"'\\",
			},
		},
		Comments: []CommentItem{
			{
				Address: "0x1234",
				Text:    "cmt\"); __import__(\"os\").system(\"id\"); #\x00",
			},
		},
	}
	idaPy := ExportIDAPython(evilBundle)
	if strings.ContainsRune(idaPy, 0) {
		t.Fatal("ExportIDAPython output contains raw NUL byte")
	}
	verifyPythonSyntax(t, "evil_ida_bridge.py", idaPy)

	ghidraPy := ExportGhidraPython(evilBundle)
	if strings.ContainsRune(ghidraPy, 0) {
		t.Fatal("ExportGhidraPython output contains raw NUL byte")
	}
	verifyPythonSyntax(t, "evil_ghidra_bridge.py", ghidraPy)
}

func TestAuditAutoStubRegressions(t *testing.T) {
	rawLog := strings.Join([]string{
		`WARN [com.github.unidbg.linux.android.SystemPropertyHook] (SystemPropertyHook.java:42) - __system_property_get("ro.build.fingerprint")`,
		`WARN [SystemPropertyHook] (SystemPropertyHook.java:51) - key=ro.product.model`,
		`WARN [ARM64SyscallHandler] - openat dirfd=-100, pathname=/data/app/~~abc123==/com.example.app-xyz==/base.apk, oflags=0x0 => -2`,
		`java.lang.UnsupportedOperationException: android/content/pm/PackageInfo->versionCode:I`,
		`java.lang.UnsupportedOperationException: android/app/ActivityThread->getApplication()Landroid/app/Application;`,
		`java.lang.UnsupportedOperationException: callObjectMethodV: android/content/pm/Signature->toByteArray()[B`,
		`java.io.FileNotFoundException: /proc/self/status`,
	}, "\n")

	diag := AnalyzeUnidbgLog(rawLog)

	// 1. Log4j (SystemPropertyHook.java:42) must NOT capture SystemPropertyHook.java
	if len(diag.MissingSysProps) != 2 {
		t.Fatalf("expected 2 sys props, got %+v", diag.MissingSysProps)
	}
	for _, p := range diag.MissingSysProps {
		if strings.Contains(p.Key, "SystemPropertyHook") {
			t.Fatalf("false-positive sys prop key from logger prefix: %+v", p)
		}
	}
	if diag.MissingSysProps[0].Key != "ro.build.fingerprint" || diag.MissingSysProps[1].Key != "ro.product.model" {
		t.Errorf("unexpected sys props: %+v", diag.MissingSysProps)
	}

	// 2. Android 11+ /data/app/~~...==/... path preserved intact
	foundAndroid11Path := false
	for _, f := range diag.MissingFiles {
		if f.Path == "/data/app/~~abc123==/com.example.app-xyz==/base.apk" {
			foundAndroid11Path = true
		}
		if f.Path == "/proc/self/status" && strings.Contains(f.SuggestedContent, `\n`) {
			t.Errorf("SuggestedContent should store raw newlines, not escaped \\n: %q", f.SuggestedContent)
		}
	}
	if !foundAndroid11Path {
		t.Errorf("Android 11+ path with ~ and = was truncated or missing: %+v", diag.MissingFiles)
	}

	// 3. hexToBytes helper must be defined when Signature->toByteArray()[B is emitted
	if !strings.Contains(diag.AbstractJniSnippet, "private static byte[] hexToBytes(String hex)") {
		t.Error("AbstractJniSnippet missing hexToBytes helper definition")
	}

	// 4. PackageInfo->versionCode:I routed to getIntField (not getObjectField), and ActivityThread->getApplication() routed to callObjectMethodV
	for _, it := range diag.MissingJNI {
		if it.Signature == "android/content/pm/PackageInfo->versionCode:I" && it.Callback != CallbackGetIntField {
			t.Errorf("expected versionCode:I -> getIntField, got %q", it.Callback)
		}
		if it.Signature == "android/app/ActivityThread->getApplication()Landroid/app/Application;" && it.Callback != CallbackCallObjectMethodV {
			t.Errorf("expected ActivityThread->getApplication() -> callObjectMethodV, got %q", it.Callback)
		}
	}
	if !strings.Contains(diag.AbstractJniSnippet, "public int getIntField(") {
		t.Error("AbstractJniSnippet missing getIntField override")
	}

	// 5. IOResolverSnippet properly Java-escapes raw tabs and newlines
	if !strings.Contains(diag.IOResolverSnippet, `"Name:\tcom.example.app\nState:\tR (running)\nTracerPid:\t0\nUid:\t10240\t10240\t10240\t10240\n"`) {
		t.Errorf("IOResolverSnippet /proc/self/status not cleanly javaQuoted:\n%s", diag.IOResolverSnippet)
	}
}

func TestAuditJadxSecurityAndLinkingRegressions(t *testing.T) {
	tmp := t.TempDir()
	wsDir := filepath.Join(tmp, "ws")
	srcDir := filepath.Join(wsDir, "sources")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Default-package class starting with "L" (LoginActivity)
	loginJava := `public class LoginActivity {
    public native boolean check(int code);
    public native void localOnly();
}
`
	if err := os.WriteFile(filepath.Join(srcDir, "LoginActivity.java"), []byte(loginJava), 0o644); err != nil {
		t.Fatal(err)
	}

	// Outside host file + symlink inside workspace trying to exfiltrate via SearchSource & LinkJavaToNative
	outsideSecret := filepath.Join(tmp, "host_secret.java")
	if err := os.WriteFile(outsideSecret, []byte("public class SecretLeak { public static final String TOKEN = \"TOP_SECRET_MARKER\"; public native void leaked(); }"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideSecret, filepath.Join(srcDir, "SecretLeak.java")); err != nil {
		t.Fatalf("symlink failed: %v", err)
	}

	// 1. SearchSource must NOT read through escaping symlinks
	hits, err := SearchSource(wsDir, "TOP_SECRET_MARKER", 10)
	if err != nil {
		t.Fatalf("SearchSource failed: %v", err)
	}
	if len(hits) != 0 {
		t.Fatalf("SearchSource leaked outside symlink contents: %+v", hits)
	}

	// 2. Empty FQCN ".java" / "foo/.java" rejected by ReadClassSource
	for _, bad := range []string{".java", "com/.java", "com/..java"} {
		if _, err := ReadClassSource(wsDir, bad); err == nil {
			t.Errorf("expected ReadClassSource(%q) to fail", bad)
		}
	}

	// 3. MangleJNIName must NOT corrupt default-package LoginActivity -> oginActivity
	shortName, longName := MangleJNIName("LoginActivity", "check", "(I)Z")
	if shortName != "Java_LoginActivity_check" || longName != "Java_LoginActivity_check__I" {
		t.Errorf("MangleJNIName corrupted LoginActivity: short=%q long=%q", shortName, longName)
	}
	// Descriptor form LLoginActivity; still strips L...;
	descShort, _ := MangleJNIName("LLoginActivity;", "check", "(I)Z")
	if descShort != "Java_LoginActivity_check" {
		t.Errorf("MangleJNIName failed on descriptor LLoginActivity;: %q", descShort)
	}

	// 4. LinkJavaToNative must ignore STB_LOCAL static ELF symbols AND escaping symlinks
	soPath := filepath.Join(tmp, "libcheck.so")
	elfBytes := buildTestELF64(t, []testELFSym{
		{name: "Java_LoginActivity_check", addr: 0x2000, size: 32, local: false},
		{name: "Java_LoginActivity_localOnly", addr: 0x2100, size: 32, local: true},
	})
	if err := os.WriteFile(soPath, elfBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := LinkJavaToNative(wsDir, soPath, "")
	if err != nil {
		t.Fatalf("LinkJavaToNative failed: %v", err)
	}
	if rep.TotalNativeMethods != 2 {
		t.Fatalf("expected 2 native methods (symlinked SecretLeak excluded), got %d: %+v", rep.TotalNativeMethods, rep.Bindings)
	}
	if rep.StaticCount != 1 || rep.UnresolvedCount != 1 {
		t.Fatalf("expected 1 static_export (check) and 1 unresolved (localOnly STB_LOCAL), got %+v", rep)
	}
}

func TestAuditIOSBplistFallbackAndHardening(t *testing.T) {
	tmp := t.TempDir()

	// Mach-O containing N_STAB debug symbol alongside real export
	machoBytes := buildSyntheticMachO64(t, synthMachOOpts{
		cpu:         macho.CpuArm64,
		pie:         true,
		nx:          true,
		cryptID:     0,
		minOSMajor:  16,
		minOSMinor:  0,
		dylibs:      []string{"/usr/lib/libSystem.B.dylib"},
		imports:     []string{"_objc_release"},
		exports:     []string{"_real_export"},
		stabs:       []string{"/Users/dev/debug_stab.c"},
		objcClasses: []string{"FallbackRunner"},
		objcMethods: []string{"run"},
	})

	// IPA with binary plist (bplist00) AND renamed executable ("RenamedExec" != "MyApp")
	ipaPath := filepath.Join(tmp, "RenamedBplist.ipa")
	writeZipArchive(t, ipaPath, map[string][]byte{
		"Payload/MyApp.app/Info.plist":  []byte("bplist00\x00\x01\x02stub"),
		"Payload/MyApp.app/RenamedExec": machoBytes,
	})

	rep, err := AnalyzeIOSBinary(ipaPath)
	if err != nil {
		t.Fatalf("AnalyzeIOSBinary(bplist + renamed binary) failed: %v", err)
	}
	if rep.MainBinaryName != "RenamedExec" {
		t.Errorf("expected MainBinaryName=RenamedExec, got %q", rep.MainBinaryName)
	}
	if rep.InfoPlist == nil || rep.InfoPlist.RawFormat != "bplist" {
		t.Errorf("expected bplist InfoPlist, got %+v", rep.InfoPlist)
	}
	for _, exp := range rep.ExportedSymbols {
		if strings.Contains(exp, "debug_stab.c") {
			t.Errorf("N_STAB debug symbol leaked into ExportedSymbols: %v", rep.ExportedSymbols)
		}
	}

	// Deeply nested XML plist (> maxPlistDepth) must fail gracefully instead of recursing unbounded
	var deep strings.Builder
	deep.WriteString(`<?xml version="1.0"?><plist version="1.0">`)
	for i := 0; i < 80; i++ {
		deep.WriteString("<dict><key>k</key>")
	}
	deep.WriteString("<string>v</string>")
	for i := 0; i < 80; i++ {
		deep.WriteString("</dict>")
	}
	deep.WriteString("</plist>")
	pInfo, pWarn := parseInfoPlist([]byte(deep.String()))
	if pInfo != nil || !strings.Contains(pWarn, "nesting depth") {
		t.Errorf("expected depth limit error for deeply nested XML plist, got info=%+v warn=%q", pInfo, pWarn)
	}
}

// --- Syntax Verification Helpers ---------------------------------------------

func verifyNodeSyntax(t *testing.T, name, code string) {
	t.Helper()
	nodeBin, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not found in PATH; skipping JS syntax check")
	}
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(code), 0o644); err != nil {
		t.Fatalf("write temp JS %s: %v", name, err)
	}
	out, err := exec.Command(nodeBin, "--check", p).CombinedOutput()
	if err != nil {
		t.Fatalf("node --check failed for %s: %v\noutput: %s", name, err, string(out))
	}
}

func verifyPythonSyntax(t *testing.T, name, code string) {
	t.Helper()
	pyBin, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not found in PATH; skipping Python syntax check")
	}
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(code), 0o644); err != nil {
		t.Fatalf("write temp Python %s: %v", name, err)
	}
	out, err := exec.Command(pyBin, "-m", "py_compile", p).CombinedOutput()
	if err != nil {
		t.Fatalf("python3 -m py_compile failed for %s: %v\noutput: %s", name, err, string(out))
	}
}

// --- Synthetic Fixture Builders ----------------------------------------------

type testELFSym struct {
	name  string
	addr  uint64
	size  uint64
	local bool
}

func buildTestELF64(t *testing.T, syms []testELFSym) []byte {
	t.Helper()

	shstrtab := []byte{0}
	addShStr := func(s string) uint32 {
		off := uint32(len(shstrtab))
		shstrtab = append(shstrtab, s...)
		shstrtab = append(shstrtab, 0)
		return off
	}
	offShstr := addShStr(".shstrtab")
	offDynstr := addShStr(".dynstr")
	offDynsym := addShStr(".dynsym")
	offText := addShStr(".text")

	dynstr := []byte{0}
	var dynsym bytes.Buffer
	writeSym := func(nameOff uint32, info byte, shndx uint16, val, size uint64) {
		var s elf.Sym64
		s.Name = nameOff
		s.Info = info
		s.Shndx = shndx
		s.Value = val
		s.Size = size
		_ = binary.Write(&dynsym, binary.LittleEndian, s)
	}
	writeSym(0, 0, 0, 0, 0) // STN_UNDEF
	for _, sym := range syms {
		nameOff := uint32(len(dynstr))
		dynstr = append(dynstr, sym.name...)
		dynstr = append(dynstr, 0)
		bind := elf.STB_GLOBAL
		if sym.local {
			bind = elf.STB_LOCAL
		}
		writeSym(nameOff, elf.ST_INFO(bind, elf.STT_FUNC), 4, sym.addr, sym.size)
	}

	textData := make([]byte, 0x100)
	for i := 0; i < len(textData); i += 4 {
		binary.LittleEndian.PutUint32(textData[i:], 0xd65f03c0) // ARM64 RET
	}

	var out bytes.Buffer
	out.Write(make([]byte, 64)) // ELF64 header placeholder

	appendSec := func(data []byte) (uint64, uint64) {
		for out.Len()%8 != 0 {
			out.WriteByte(0)
		}
		off := uint64(out.Len())
		out.Write(data)
		return off, uint64(len(data))
	}

	shstrOff, shstrSize := appendSec(shstrtab)
	dynstrOff, dynstrSize := appendSec(dynstr)
	dynsymOff, dynsymSize := appendSec(dynsym.Bytes())
	textOff, textSize := appendSec(textData)

	for out.Len()%8 != 0 {
		out.WriteByte(0)
	}
	shOff := uint64(out.Len())

	headers := []elf.Section64{
		{},
		{Name: offShstr, Type: uint32(elf.SHT_STRTAB), Off: shstrOff, Size: shstrSize, Addralign: 1},
		{Name: offDynstr, Type: uint32(elf.SHT_STRTAB), Flags: uint64(elf.SHF_ALLOC), Off: dynstrOff, Size: dynstrSize, Addralign: 1},
		{Name: offDynsym, Type: uint32(elf.SHT_DYNSYM), Flags: uint64(elf.SHF_ALLOC), Off: dynsymOff, Size: dynsymSize, Link: 2, Info: 1, Addralign: 8, Entsize: 24},
		{Name: offText, Type: uint32(elf.SHT_PROGBITS), Flags: uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), Addr: 0x1000, Off: textOff, Size: textSize, Addralign: 4},
	}
	for _, h := range headers {
		_ = binary.Write(&out, binary.LittleEndian, h)
	}

	raw := out.Bytes()
	var ehdr elf.Header64
	copy(ehdr.Ident[:4], []byte{0x7f, 'E', 'L', 'F'})
	ehdr.Ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	ehdr.Ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	ehdr.Ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	ehdr.Type = uint16(elf.ET_DYN)
	ehdr.Machine = uint16(elf.EM_AARCH64)
	ehdr.Version = uint32(elf.EV_CURRENT)
	ehdr.Shoff = shOff
	ehdr.Ehsize = 64
	ehdr.Shentsize = 64
	ehdr.Shnum = uint16(len(headers))
	ehdr.Shstrndx = 1

	var hbuf bytes.Buffer
	_ = binary.Write(&hbuf, binary.LittleEndian, ehdr)
	copy(raw[:64], hbuf.Bytes())
	return raw
}

func writeZipArchive(t *testing.T, zipPath string, files map[string][]byte) {
	t.Helper()
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("create zip %s: %v", zipPath, err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := w.Write(content); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
}

func buildMinimalSyntheticDEX(classDesc, methodName, sig string, native bool) []byte {
	// Strings:
	// 0: classDesc (e.g. "Lcom/example/fallback/CryptoNative;")
	// 1: "Ljava/lang/String;"
	// 2: methodName
	// 3: "LL" (shorty)
	strs := []string{classDesc, "Ljava/lang/String;", methodName, "LL"}
	var strData bytes.Buffer
	strOffs := make([]uint32, len(strs))

	// Layout:
	// [0..112): DEX header
	// string_ids (4*4=16) @ 112
	// type_ids (2*4=8) @ 128
	// proto_ids (1*12=12) @ 136
	// method_ids (1*8=8) @ 148
	// class_defs (1*32=32) @ 156
	// type_list @ 188 (size=1, uint16 type_idx=1, pad 2 -> 8 bytes)
	// class_data @ 196
	// string_data @ 224
	const (
		strIDsOff    = 112
		typeIDsOff   = 128
		protoIDsOff  = 136
		methIDsOff   = 148
		classDefsOff = 156
		typeListOff  = 188
		classDataOff = 196
		strDataBase  = 224
	)

	for i, s := range strs {
		strOffs[i] = uint32(strDataBase + strData.Len())
		strData.WriteByte(byte(len(s))) // ULEB128 length (< 128)
		strData.WriteString(s)
		strData.WriteByte(0)
	}

	buf := make([]byte, strDataBase+strData.Len())
	le := binary.LittleEndian

	copy(buf[0:8], []byte{'d', 'e', 'x', '\n', '0', '3', '5', 0})
	le.PutUint32(buf[32:36], uint32(len(buf))) // file_size
	le.PutUint32(buf[36:40], 112)              // header_size
	le.PutUint32(buf[40:44], 0x12345678)       // endian_tag
	le.PutUint32(buf[56:60], uint32(len(strs)))
	le.PutUint32(buf[60:64], strIDsOff)
	le.PutUint32(buf[64:68], 2) // type_ids_size
	le.PutUint32(buf[68:72], typeIDsOff)
	le.PutUint32(buf[72:76], 1) // proto_ids_size
	le.PutUint32(buf[76:80], protoIDsOff)
	le.PutUint32(buf[88:92], 1) // method_ids_size
	le.PutUint32(buf[92:96], methIDsOff)
	le.PutUint32(buf[96:100], 1) // class_defs_size
	le.PutUint32(buf[100:104], classDefsOff)

	// string_ids
	for i, off := range strOffs {
		le.PutUint32(buf[strIDsOff+i*4:strIDsOff+i*4+4], off)
	}
	// type_ids: 0 -> str 0 (classDesc), 1 -> str 1 (String)
	le.PutUint32(buf[typeIDsOff:typeIDsOff+4], 0)
	le.PutUint32(buf[typeIDsOff+4:typeIDsOff+8], 1)
	// proto_ids: shorty=3, return_type=1, params_off=typeListOff
	le.PutUint32(buf[protoIDsOff:protoIDsOff+4], 3)
	le.PutUint32(buf[protoIDsOff+4:protoIDsOff+8], 1)
	le.PutUint32(buf[protoIDsOff+8:protoIDsOff+12], typeListOff)
	// method_ids: class_idx=0, proto_idx=0, name_idx=2
	le.PutUint16(buf[methIDsOff:methIDsOff+2], 0)
	le.PutUint16(buf[methIDsOff+2:methIDsOff+4], 0)
	le.PutUint32(buf[methIDsOff+4:methIDsOff+8], 2)
	// class_defs: class_idx=0, class_data_off=classDataOff
	le.PutUint32(buf[classDefsOff:classDefsOff+4], 0)
	le.PutUint32(buf[classDefsOff+24:classDefsOff+28], classDataOff)
	// type_list: count=1, type_idx=1
	le.PutUint32(buf[typeListOff:typeListOff+4], 1)
	le.PutUint16(buf[typeListOff+4:typeListOff+6], 1)
	// class_data: 0 static fields, 0 inst fields, 1 direct method, 0 virtual methods
	cd := []byte{0, 0, 1, 0}
	cd = append(cd, 0) // method_idx_diff = 0
	if native {
		// access_flags = ACC_PUBLIC (0x1) | ACC_STATIC (0x8) | ACC_NATIVE (0x100) = 0x109 -> ULEB128: 0x89, 0x02
		cd = append(cd, 0x89, 0x02)
	} else {
		cd = append(cd, 0x01)
	}
	cd = append(cd, 0) // code_off = 0
	copy(buf[classDataOff:], cd)
	copy(buf[strDataBase:], strData.Bytes())
	return buf
}

type synthMachOOpts struct {
	cpu         macho.Cpu
	pie         bool
	nx          bool
	cryptID     uint32
	minOSMajor  uint32
	minOSMinor  uint32
	dylibs      []string
	imports     []string
	exports     []string
	stabs       []string
	objcClasses []string
	objcMethods []string
}

func buildSyntheticMachO64(t *testing.T, opts synthMachOOpts) []byte {
	t.Helper()
	le := binary.LittleEndian

	var classNamesBuf, methNamesBuf bytes.Buffer
	for _, c := range opts.objcClasses {
		classNamesBuf.WriteString(c)
		classNamesBuf.WriteByte(0)
	}
	for _, m := range opts.objcMethods {
		methNamesBuf.WriteString(m)
		methNamesBuf.WriteByte(0)
	}

	// Build __DATA/__objc_classlist (placeholder 8-byte pointers).
	classListData := make([]byte, len(opts.objcClasses)*8)

	// Build symbol table + string table.
	strtab := []byte{0}
	var nlists bytes.Buffer
	addNlist := func(name string, ntype uint8, sect uint8, val uint64) {
		strOff := uint32(len(strtab))
		strtab = append(strtab, name...)
		strtab = append(strtab, 0)
		var nl macho.Nlist64
		nl.Name = strOff
		nl.Type = ntype
		nl.Sect = sect
		nl.Value = val
		_ = binary.Write(&nlists, le, nl)
	}
	for _, imp := range opts.imports {
		addNlist(imp, 0x01, 0, 0) // N_EXT | N_UNDF
	}
	for i, exp := range opts.exports {
		val := uint64(0x100004000 + i*0x40)
		addNlist(exp, 0x0f, 1, val) // N_EXT | N_SECT
	}
	for i, st := range opts.stabs {
		val := uint64(0x100005000 + i*0x20)
		addNlist(st, 0x25, 1, val) // N_STAB (0x20) | N_EXT (0x01) | N_SECT
	}

	// Prepare load commands (first compute exact load command bytes, then fixup file offsets).
	var dylibCmds [][]byte
	for _, lib := range opts.dylibs {
		nameBytes := append([]byte(lib), 0)
		cmdSize := 24 + len(nameBytes)
		for cmdSize%8 != 0 {
			cmdSize++
		}
		buf := make([]byte, cmdSize)
		le.PutUint32(buf[0:4], uint32(macho.LoadCmdDylib))
		le.PutUint32(buf[4:8], uint32(cmdSize))
		le.PutUint32(buf[8:12], 24) // name offset
		le.PutUint32(buf[12:16], 2) // timestamp
		le.PutUint32(buf[16:20], 0x00010000)
		le.PutUint32(buf[20:24], 0x00010000)
		copy(buf[24:], nameBytes)
		dylibCmds = append(dylibCmds, buf)
	}

	// LC_ENCRYPTION_INFO_64 (24 bytes)
	encCmd := make([]byte, 24)
	le.PutUint32(encCmd[0:4], lcEncryptionInfo64)
	le.PutUint32(encCmd[4:8], 24)
	le.PutUint32(encCmd[8:12], 0x4000)
	le.PutUint32(encCmd[12:16], 0x4000)
	le.PutUint32(encCmd[16:20], opts.cryptID)

	// LC_BUILD_VERSION (24 bytes)
	bvCmd := make([]byte, 24)
	le.PutUint32(bvCmd[0:4], lcBuildVersion)
	le.PutUint32(bvCmd[4:8], 24)
	le.PutUint32(bvCmd[8:12], 2) // PLATFORM_IOS
	le.PutUint32(bvCmd[12:16], (opts.minOSMajor<<16)|(opts.minOSMinor<<8))
	le.PutUint32(bvCmd[16:20], (16<<16)|(0<<8))
	le.PutUint32(bvCmd[20:24], 0)

	// Segment sizes:
	// __TEXT segment (72) + 2 sections (2*80=160) = 232 bytes
	// __DATA segment (72) + 1 section (80) = 152 bytes
	// LC_SYMTAB = 24 bytes
	const (
		machoHdrSize = 32
		textSegSize  = 72 + 2*80
		dataSegSize  = 72 + 1*80
		symtabSize   = 24
	)

	sizeofCmds := textSegSize + dataSegSize + symtabSize + len(encCmd) + len(bvCmd)
	for _, dc := range dylibCmds {
		sizeofCmds += len(dc)
	}
	ncmds := uint32(5 + len(dylibCmds))

	// Place payload sections after header + load commands (aligned to 8).
	payloadOff := machoHdrSize + sizeofCmds
	for payloadOff%8 != 0 {
		payloadOff++
	}

	classNamesOff := uint32(payloadOff)
	classNamesBytes := classNamesBuf.Bytes()
	methNamesOff := classNamesOff + uint32(len(classNamesBytes))
	methNamesBytes := methNamesBuf.Bytes()
	classListOff := methNamesOff + uint32(len(methNamesBytes))
	for classListOff%8 != 0 {
		classListOff++
	}
	symOff := classListOff + uint32(len(classListData))
	for symOff%8 != 0 {
		symOff++
	}
	strOff := symOff + uint32(nlists.Len())
	totalSize := int(strOff) + len(strtab)

	out := make([]byte, totalSize)

	// Write Mach-O 64-bit header
	var flags uint32
	if opts.pie {
		flags |= mhFlagPIE
	}
	if !opts.nx {
		flags |= mhFlagAllowStackExec
	}
	le.PutUint32(out[0:4], macho.Magic64)
	le.PutUint32(out[4:8], uint32(opts.cpu))
	le.PutUint32(out[8:12], 0) // subcpu
	le.PutUint32(out[12:16], uint32(macho.TypeExec))
	le.PutUint32(out[16:20], ncmds)
	le.PutUint32(out[20:24], uint32(sizeofCmds))
	le.PutUint32(out[24:28], flags)
	le.PutUint32(out[28:32], 0)

	pos := machoHdrSize
	writeSeg64 := func(segName string, vmAddr, fileOff, fileSize uint64, nsect uint32) {
		var seg macho.Segment64
		seg.Cmd = macho.LoadCmdSegment64
		seg.Len = uint32(72 + nsect*80)
		copy(seg.Name[:], segName)
		seg.Addr = vmAddr
		seg.Memsz = fileSize
		seg.Offset = fileOff
		seg.Filesz = fileSize
		seg.Maxprot = 7
		seg.Prot = 5
		seg.Nsect = nsect
		var b bytes.Buffer
		_ = binary.Write(&b, le, seg)
		copy(out[pos:], b.Bytes())
		pos += 72
	}
	writeSec64 := func(secName, segName string, addr, size uint64, off uint32) {
		var sec macho.Section64
		copy(sec.Name[:], secName)
		copy(sec.Seg[:], segName)
		sec.Addr = addr
		sec.Size = size
		sec.Offset = off
		sec.Align = 3
		var b bytes.Buffer
		_ = binary.Write(&b, le, sec)
		copy(out[pos:], b.Bytes())
		pos += 80
	}

	textFilesz := uint64(methNamesOff+uint32(len(methNamesBytes))) - uint64(classNamesOff)
	writeSeg64("__TEXT", 0x100000000, uint64(classNamesOff), textFilesz, 2)
	writeSec64("__objc_classname", "__TEXT", 0x100001000, uint64(len(classNamesBytes)), classNamesOff)
	writeSec64("__objc_methname", "__TEXT", 0x100002000, uint64(len(methNamesBytes)), methNamesOff)

	writeSeg64("__DATA", 0x100008000, uint64(classListOff), uint64(len(classListData)), 1)
	writeSec64("__objc_classlist", "__DATA", 0x100008000, uint64(len(classListData)), classListOff)

	// LC_SYMTAB
	var symCmd macho.SymtabCmd
	symCmd.Cmd = macho.LoadCmdSymtab
	symCmd.Len = symtabSize
	symCmd.Symoff = symOff
	symCmd.Nsyms = uint32(len(opts.imports) + len(opts.exports) + len(opts.stabs))
	symCmd.Stroff = strOff
	symCmd.Strsize = uint32(len(strtab))
	var sb bytes.Buffer
	_ = binary.Write(&sb, le, symCmd)
	copy(out[pos:], sb.Bytes())
	pos += symtabSize

	copy(out[pos:], encCmd)
	pos += len(encCmd)
	copy(out[pos:], bvCmd)
	pos += len(bvCmd)
	for _, dc := range dylibCmds {
		copy(out[pos:], dc)
		pos += len(dc)
	}

	copy(out[classNamesOff:], classNamesBytes)
	copy(out[methNamesOff:], methNamesBytes)
	copy(out[classListOff:], classListData)
	copy(out[symOff:], nlists.Bytes())
	copy(out[strOff:], strtab)

	return out
}
