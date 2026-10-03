package trace

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/overkazaf/cap/internal/types"
)

// writeTestZip creates a zip file at path containing entries (name ->
// content), returning the path for convenience.
func writeTestZip(t *testing.T, path string, entries map[string][]byte) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create(%s): %v", path, err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	// Deterministic order so DexCount/offset-dependent assertions don't flake.
	for _, name := range sortedKeys(entries) {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip Create(%s): %v", name, err)
		}
		if _, err := w.Write(entries[name]); err != nil {
			t.Fatalf("zip Write(%s): %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip Close: %v", err)
	}
	return path
}

func sortedKeys(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func TestBuildSearchTerms(t *testing.T) {
	tests := []struct {
		name string
		flow *types.Flow
		want []string
	}{
		{
			name: "nil flow",
			flow: nil,
			want: nil,
		},
		{
			name: "path host and segments",
			flow: &types.Flow{
				Method: "POST",
				URL:    "https://api.example.com/api/v1/login?foo=bar",
				Host:   "api.example.com",
				Path:   "/api/v1/login",
			},
			want: []string{
				"https://api.example.com/api/v1/login?foo=bar",
				"api.example.com/api/v1/login",
				"/api/v1/login",
				"api/v1/login",
				"api.example.com",
			},
		},
		{
			name: "path derived from URL when Path field is empty",
			flow: &types.Flow{
				Method: "GET",
				URL:    "https://cdn.example.com/static/sdk/v2/sign.js",
				Host:   "cdn.example.com",
			},
			want: []string{
				"https://cdn.example.com/static/sdk/v2/sign.js",
				"cdn.example.com/static/sdk/v2/sign.js",
				"/static/sdk/v2/sign.js",
				"static/sdk/v2/sign.js",
				"cdn.example.com",
			},
		},
		{
			name: "host plus multi-segment path",
			flow: &types.Flow{
				URL:  "http://x.io/a/bb/ccc",
				Host: "x.io",
				Path: "/a/bb/ccc",
			},
			want: []string{
				"http://x.io/a/bb/ccc",
				"x.io/a/bb/ccc",
				"/a/bb/ccc",
				"a/bb/ccc",
				"x.io",
			},
		},
		{
			name: "short terms filtered and empty host skips host-only terms",
			flow: &types.Flow{
				URL:  "https://y.io/ab",
				Host: "",
				Path: "/ab",
			},
			// "/ab" (len 3) clears minSearchTermLen, but "ab" (len 2) does
			// not; Host is empty so neither "host+path" nor the bare-host
			// term are added at all.
			want: []string{
				"https://y.io/ab",
				"/ab",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildSearchTerms(tt.flow)
			if !slices.Equal(got, tt.want) {
				t.Errorf("buildSearchTerms() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestExtractPrintableStrings(t *testing.T) {
	t.Run("finds runs at start, middle, and end", func(t *testing.T) {
		data := []byte("abcd\x00\x01\x02efgh\x00ij\x00wxyz")
		// "abcd" (0-3), "efgh" (7-10), "ij" too short (2<4, dropped),
		// "wxyz" (15-18).
		runs := extractPrintableStrings(data, 4)

		if len(runs) != 3 {
			t.Fatalf("len(runs) = %d, want 3 (%+v)", len(runs), runs)
		}
		if runs[0].value != "abcd" || runs[0].offset != 0 {
			t.Errorf("runs[0] = %+v, want {0 abcd}", runs[0])
		}
		if runs[1].value != "efgh" || runs[1].offset != 7 {
			t.Errorf("runs[1] = %+v, want {7 efgh}", runs[1])
		}
		if runs[2].value != "wxyz" {
			t.Errorf("runs[2].value = %q, want %q", runs[2].value, "wxyz")
		}
	})

	t.Run("empty input", func(t *testing.T) {
		if runs := extractPrintableStrings(nil, 4); len(runs) != 0 {
			t.Errorf("extractPrintableStrings(nil) = %+v, want empty", runs)
		}
	})

	t.Run("entire input printable with no terminator", func(t *testing.T) {
		runs := extractPrintableStrings([]byte("/api/v1/login"), 4)
		if len(runs) != 1 || runs[0].value != "/api/v1/login" || runs[0].offset != 0 {
			t.Errorf("runs = %+v, want single run covering whole input", runs)
		}
	})

	t.Run("default minLen when non-positive", func(t *testing.T) {
		// "ab" (len 2) must be dropped under the default minimum (4).
		runs := extractPrintableStrings([]byte("ab\x00abcd"), 0)
		if len(runs) != 1 || runs[0].value != "abcd" {
			t.Errorf("runs = %+v, want only \"abcd\" kept under default minLen", runs)
		}
	})
}

func TestSearchDexStrings(t *testing.T) {
	dir := t.TempDir()

	classesDex := bytes.Join([][]byte{
		{0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00}, // dex magic-ish junk
		[]byte("com/example/LoginApi"),
		[]byte("/api/v1/login"),
		[]byte("okhttp3/Request$Builder"),
		{0x00, 0x01, 0x02, 0x03},
		[]byte("unrelated/Noise"),
	}, []byte{0x00})

	classes2Dex := bytes.Join([][]byte{
		{0x64, 0x65, 0x78, 0x0a},
		[]byte("api.example.com"),
		[]byte("Content-Type"),
	}, []byte{0x00})

	apkPath := writeTestZip(t, filepath.Join(dir, "app.apk"), map[string][]byte{
		"classes.dex":         classesDex,
		"classes2.dex":        classes2Dex,
		"AndroidManifest.xml": []byte("not a dex file, must be ignored"),
	})

	t.Run("finds matches with surrounding context across multiple dex files", func(t *testing.T) {
		matches, err := searchDexStrings(apkPath, []string{"/api/v1/login", "api.example.com"})
		if err != nil {
			t.Fatalf("searchDexStrings: %v", err)
		}
		if len(matches) != 2 {
			t.Fatalf("len(matches) = %d, want 2 (%+v)", len(matches), matches)
		}

		login := matches[0]
		if login.DexFile != "classes.dex" {
			t.Errorf("login.DexFile = %q, want %q", login.DexFile, "classes.dex")
		}
		if login.String != "/api/v1/login" {
			t.Errorf("login.String = %q, want %q", login.String, "/api/v1/login")
		}
		wantOffset := int64(bytes.Index(classesDex, []byte("/api/v1/login")))
		if login.Offset != wantOffset {
			t.Errorf("login.Offset = %d, want %d", login.Offset, wantOffset)
		}
		if !slices.Contains(login.Context, "com/example/LoginApi") {
			t.Errorf("login.Context = %v, want it to contain the preceding class name", login.Context)
		}
		if !slices.Contains(login.Context, "okhttp3/Request$Builder") {
			t.Errorf("login.Context = %v, want it to contain the following string", login.Context)
		}

		host := matches[1]
		if host.DexFile != "classes2.dex" || host.String != "api.example.com" {
			t.Errorf("host match = %+v, want {classes2.dex api.example.com ...}", host)
		}
	})

	t.Run("no matching terms yields no matches, no error", func(t *testing.T) {
		matches, err := searchDexStrings(apkPath, []string{"totally-absent-term"})
		if err != nil {
			t.Fatalf("searchDexStrings: %v", err)
		}
		if len(matches) != 0 {
			t.Errorf("matches = %+v, want none", matches)
		}
	})

	t.Run("terms shorter than the minimum are ignored, not errored", func(t *testing.T) {
		matches, err := searchDexStrings(apkPath, []string{"ab"})
		if err != nil {
			t.Fatalf("searchDexStrings: %v", err)
		}
		if len(matches) != 0 {
			t.Errorf("matches = %+v, want none for a too-short term", matches)
		}
	})

	t.Run("missing APK returns an error", func(t *testing.T) {
		if _, err := searchDexStrings(filepath.Join(dir, "does-not-exist.apk"), []string{"/api/v1/login"}); err == nil {
			t.Error("searchDexStrings(missing apk) = nil error, want non-nil")
		}
	})

	t.Run("caps the number of matches returned", func(t *testing.T) {
		matches, err := searchDexStringsLimit(apkPath, []string{"/api/v1/login", "api.example.com"}, 1)
		if err != nil {
			t.Fatalf("searchDexStringsLimit: %v", err)
		}
		if len(matches) != 1 {
			t.Fatalf("len(matches) = %d, want 1", len(matches))
		}
	})
}

// --- AndroidManifest.xml (binary XML) test fixture builder --------------
//
// This encodes a minimal but structurally real Android binary XML
// document: an 8-byte ResChunk_header-wrapped UTF-16 string pool followed
// by one ResXMLTree StartElement chunk per element. The exact chunk layout
// (8-byte chunk header; a 16-byte common node header of
// lineNumber+comment on top of that; a 20-byte attrExt struct; 20 bytes
// per attribute) was cross-checked against a real AndroidManifest.xml
// pulled from a production APK and decoded with `aapt dump xmltree` before
// parseAndroidManifest was written -- see that function's doc comment.

type axmlAttr struct {
	name     string
	strVal   string // used when dataType == androidTypeString
	dataType byte
	data     uint32
}

func strAttr(name, val string) axmlAttr {
	return axmlAttr{name: name, strVal: val, dataType: androidTypeString}
}
func intAttr(name string, val uint32) axmlAttr {
	return axmlAttr{name: name, dataType: androidTypeIntDec, data: val}
}
func refAttr(name string, val uint32) axmlAttr {
	return axmlAttr{name: name, dataType: androidTypeReference, data: val}
}

type axmlElem struct {
	name  string
	attrs []axmlAttr
}

// buildFakeManifest encodes elems as a binary AndroidManifest.xml document.
func buildFakeManifest(t *testing.T, elems []axmlElem) []byte {
	t.Helper()

	var pool []string
	index := make(map[string]int)
	intern := func(s string) int {
		if i, ok := index[s]; ok {
			return i
		}
		i := len(pool)
		pool = append(pool, s)
		index[s] = i
		return i
	}
	for _, e := range elems {
		intern(e.name)
		for _, a := range e.attrs {
			intern(a.name)
			if a.dataType == androidTypeString {
				intern(a.strVal)
			}
		}
	}

	stringPool := encodeUTF16StringPool(pool)

	var body bytes.Buffer
	for _, e := range elems {
		body.Write(encodeStartElement(t, e, index))
	}

	total := 8 + len(stringPool) + body.Len()
	var out bytes.Buffer
	writeChunkHeader(t, &out, 0x0003, 8, total)
	out.Write(stringPool)
	out.Write(body.Bytes())
	return out.Bytes()
}

func writeChunkHeader(t *testing.T, buf *bytes.Buffer, chunkType, headerSize uint16, size int) {
	t.Helper()
	mustWrite(t, buf, chunkType)
	mustWrite(t, buf, headerSize)
	mustWrite(t, buf, uint32(size))
}

func mustWrite(t *testing.T, buf *bytes.Buffer, v any) {
	t.Helper()
	if err := binary.Write(buf, binary.LittleEndian, v); err != nil {
		t.Fatalf("binary.Write(%v): %v", v, err)
	}
}

func encodeUTF16StringPool(pool []string) []byte {
	var data bytes.Buffer
	offs := make([]uint32, len(pool))
	for i, s := range pool {
		offs[i] = uint32(data.Len())
		binary.Write(&data, binary.LittleEndian, uint16(len(s))) // length (ASCII-only fixtures: runes==bytes)
		for _, r := range s {
			binary.Write(&data, binary.LittleEndian, uint16(r))
		}
		binary.Write(&data, binary.LittleEndian, uint16(0)) // NUL terminator
	}
	for data.Len()%4 != 0 { // 4-byte pad, matching real aapt output
		data.WriteByte(0)
	}

	const headerLen = 28
	stringsStart := headerLen + len(pool)*4
	total := stringsStart + data.Len()

	var out bytes.Buffer
	binary.Write(&out, binary.LittleEndian, uint16(0x0001))
	binary.Write(&out, binary.LittleEndian, uint16(headerLen))
	binary.Write(&out, binary.LittleEndian, uint32(total))
	binary.Write(&out, binary.LittleEndian, uint32(len(pool))) // stringCount
	binary.Write(&out, binary.LittleEndian, uint32(0))         // styleCount
	binary.Write(&out, binary.LittleEndian, uint32(0))         // flags: UTF-16, unsorted
	binary.Write(&out, binary.LittleEndian, uint32(stringsStart))
	binary.Write(&out, binary.LittleEndian, uint32(0)) // stylesStart
	for _, o := range offs {
		binary.Write(&out, binary.LittleEndian, o)
	}
	out.Write(data.Bytes())
	return out.Bytes()
}

func encodeStartElement(t *testing.T, e axmlElem, index map[string]int) []byte {
	t.Helper()
	const nodeHeaderLen = 16 // 8-byte chunk header + lineNumber(4) + comment(4)
	const attrExtLen = 20
	const attrLen = 20

	size := nodeHeaderLen + attrExtLen + attrLen*len(e.attrs)

	var out bytes.Buffer
	writeChunkHeader(t, &out, 0x0102, nodeHeaderLen, size)
	mustWrite(t, &out, uint32(0))            // lineNumber
	mustWrite(t, &out, int32(-1))            // comment
	mustWrite(t, &out, int32(-1))            // ns
	mustWrite(t, &out, int32(index[e.name])) // name
	mustWrite(t, &out, uint16(attrExtLen))   // attributeStart
	mustWrite(t, &out, uint16(attrLen))      // attributeSize
	mustWrite(t, &out, uint16(len(e.attrs))) // attributeCount
	mustWrite(t, &out, uint16(0))            // idIndex
	mustWrite(t, &out, uint16(0))            // classIndex
	mustWrite(t, &out, uint16(0))            // styleIndex

	for _, a := range e.attrs {
		rawValue := int32(-1)
		data := a.data
		if a.dataType == androidTypeString {
			rawValue = int32(index[a.strVal])
			data = uint32(index[a.strVal])
		}
		mustWrite(t, &out, int32(-1))            // ns
		mustWrite(t, &out, int32(index[a.name])) // name
		mustWrite(t, &out, rawValue)
		mustWrite(t, &out, uint16(8))  // typedValue.size
		mustWrite(t, &out, uint8(0))   // res0
		mustWrite(t, &out, a.dataType) // dataType
		mustWrite(t, &out, data)
	}
	return out.Bytes()
}

func TestExtractAPKInfo(t *testing.T) {
	fullManifestElems := []axmlElem{
		{name: "manifest", attrs: []axmlAttr{strAttr("package", "com.example.app")}},
		{name: "uses-sdk", attrs: []axmlAttr{intAttr("minSdkVersion", 21), intAttr("targetSdkVersion", 33)}},
		{name: "uses-permission", attrs: []axmlAttr{strAttr("name", "android.permission.INTERNET")}},
		{name: "uses-permission", attrs: []axmlAttr{strAttr("name", "android.permission.CAMERA")}},
		{name: "application", attrs: []axmlAttr{refAttr("networkSecurityConfig", 0x7f140001)}},
		{name: "activity", attrs: []axmlAttr{strAttr("name", "com.example.app.MainActivity")}},
		{name: "activity", attrs: []axmlAttr{strAttr("name", "com.example.app.SettingsActivity")}},
	}

	t.Run("full manifest via the binary XML parser", func(t *testing.T) {
		dir := t.TempDir()
		apkPath := writeTestZip(t, filepath.Join(dir, "app.apk"), map[string][]byte{
			"AndroidManifest.xml":       buildFakeManifest(t, fullManifestElems),
			"classes.dex":               []byte("dex1"),
			"classes2.dex":              []byte("dex2"),
			"lib/arm64-v8a/libfoo.so":   []byte("so1"),
			"lib/armeabi-v7a/libfoo.so": []byte("so2"),
			"lib/arm64-v8a/libbar.so":   []byte("so3"),
			"resources.arsc":            []byte("not interesting"),
		})

		info, err := extractAPKInfo(apkPath)
		if err != nil {
			t.Fatalf("extractAPKInfo: %v", err)
		}

		if info.Package != "com.example.app" {
			t.Errorf("Package = %q, want %q", info.Package, "com.example.app")
		}
		if info.MinSDK != "21" {
			t.Errorf("MinSDK = %q, want %q", info.MinSDK, "21")
		}
		if info.TargetSDK != "33" {
			t.Errorf("TargetSDK = %q, want %q", info.TargetSDK, "33")
		}
		wantPerms := []string{"android.permission.CAMERA", "android.permission.INTERNET"}
		if !slices.Equal(info.Permissions, wantPerms) {
			t.Errorf("Permissions = %v, want %v", info.Permissions, wantPerms)
		}
		wantActivities := []string{"com.example.app.MainActivity", "com.example.app.SettingsActivity"}
		if !slices.Equal(info.Activities, wantActivities) {
			t.Errorf("Activities = %v, want %v", info.Activities, wantActivities)
		}
		wantSO := []string{"lib/arm64-v8a/libbar.so", "lib/arm64-v8a/libfoo.so", "lib/armeabi-v7a/libfoo.so"}
		if !slices.Equal(info.SOFiles, wantSO) {
			t.Errorf("SOFiles = %v, want %v", info.SOFiles, wantSO)
		}
		if info.DexCount != 2 {
			t.Errorf("DexCount = %d, want 2", info.DexCount)
		}
		if !info.HasNSConfig {
			t.Error("HasNSConfig = false, want true (application has networkSecurityConfig attr)")
		}
	})

	t.Run("network_security_config detected via resource file name when the attribute is absent", func(t *testing.T) {
		dir := t.TempDir()
		elemsNoNSAttr := []axmlElem{
			{name: "manifest", attrs: []axmlAttr{strAttr("package", "com.example.app")}},
		}
		apkPath := writeTestZip(t, filepath.Join(dir, "app.apk"), map[string][]byte{
			"AndroidManifest.xml":                 buildFakeManifest(t, elemsNoNSAttr),
			"res/xml/network_security_config.xml": []byte("<network-security-config/>"),
		})

		info, err := extractAPKInfo(apkPath)
		if err != nil {
			t.Fatalf("extractAPKInfo: %v", err)
		}
		if !info.HasNSConfig {
			t.Error("HasNSConfig = false, want true (res/xml/network_security_config.xml present)")
		}
	})

	t.Run("malformed manifest falls back to the printable-string heuristic", func(t *testing.T) {
		dir := t.TempDir()
		garbage := bytes.Join([][]byte{
			{0xff, 0xd8, 0x00, 0x01, 0x02}, // not a binary-XML magic
			[]byte("com.example.fallback.MainActivity"),
			{0x00, 0x00},
			[]byte("com.example.fallback.SplashActivity"),
			{0x00, 0x00},
			[]byte("android.permission.INTERNET"),
			{0x00, 0x00},
			[]byte("android.permission.CAMERA"),
		}, []byte{0x00})

		apkPath := writeTestZip(t, filepath.Join(dir, "app.apk"), map[string][]byte{
			"AndroidManifest.xml": garbage,
		})

		info, err := extractAPKInfo(apkPath)
		if err != nil {
			t.Fatalf("extractAPKInfo: %v", err)
		}
		if info.Package != "com.example.fallback" {
			t.Errorf("Package = %q, want %q (voted from common prefix of the two Activity names)", info.Package, "com.example.fallback")
		}
		wantPerms := []string{"android.permission.CAMERA", "android.permission.INTERNET"}
		if !slices.Equal(info.Permissions, wantPerms) {
			t.Errorf("Permissions = %v, want %v", info.Permissions, wantPerms)
		}
		wantActivities := []string{"com.example.fallback.MainActivity", "com.example.fallback.SplashActivity"}
		if !slices.Equal(info.Activities, wantActivities) {
			t.Errorf("Activities = %v, want %v", info.Activities, wantActivities)
		}
	})

	t.Run("truncated manifest degrades gracefully without panicking", func(t *testing.T) {
		dir := t.TempDir()
		full := buildFakeManifest(t, fullManifestElems)
		truncated := full[:len(full)/2]

		apkPath := writeTestZip(t, filepath.Join(dir, "app.apk"), map[string][]byte{
			"AndroidManifest.xml": truncated,
		})

		info, err := extractAPKInfo(apkPath) // must not panic
		if err != nil {
			t.Fatalf("extractAPKInfo: %v", err)
		}
		if info == nil {
			t.Fatal("extractAPKInfo returned nil info with nil error")
		}
	})

	t.Run("missing APK returns an error", func(t *testing.T) {
		if _, err := extractAPKInfo(filepath.Join(t.TempDir(), "missing.apk")); err == nil {
			t.Error("extractAPKInfo(missing apk) = nil error, want non-nil")
		}
	})
}

func TestExtractSOFilesTo(t *testing.T) {
	dir := t.TempDir()
	apkPath := writeTestZip(t, filepath.Join(dir, "app.apk"), map[string][]byte{
		"lib/arm64-v8a/libfoo.so":   []byte("arm64 foo"),
		"lib/armeabi-v7a/libfoo.so": []byte("armeabi foo"),
		"classes.dex":               []byte("not a so file"),
	})

	destDir := filepath.Join(dir, "extracted")
	paths, err := extractSOFilesTo(apkPath, destDir)
	if err != nil {
		t.Fatalf("extractSOFilesTo: %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("len(paths) = %d, want 2 (%v)", len(paths), paths)
	}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Errorf("ReadFile(%s): %v", p, err)
		}
		if len(data) == 0 {
			t.Errorf("extracted file %s is empty", p)
		}
	}
}

// writeJavaFile creates path (and any missing parent directories) with
// content, mirroring internal/context's test helper of the same shape.
func writeJavaFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}

func TestSearchJavaSource(t *testing.T) {
	t.Run("retrofit annotation with method extraction", func(t *testing.T) {
		dir := t.TempDir()
		relFile := filepath.Join("com", "example", "api", "LoginApi.java")
		writeJavaFile(t, filepath.Join(dir, relFile), `package com.example.api;

public interface LoginApi {
    @POST("/api/v1/login")
    Call<LoginResp> login(@Body LoginReq req);
}
`)

		refs := searchJavaSource(dir, []string{"/api/v1/login"})
		if len(refs) != 1 {
			t.Fatalf("len(refs) = %d, want 1 (%+v)", len(refs), refs)
		}
		ref := refs[0]
		if ref.File != filepath.ToSlash(relFile) {
			t.Errorf("File = %q, want %q", ref.File, filepath.ToSlash(relFile))
		}
		if ref.Class != "com.example.api.LoginApi" {
			t.Errorf("Class = %q, want %q", ref.Class, "com.example.api.LoginApi")
		}
		if ref.Line != 4 {
			t.Errorf("Line = %d, want 4", ref.Line)
		}
		if ref.Annotation != "POST /api/v1/login" {
			t.Errorf("Annotation = %q, want %q", ref.Annotation, "POST /api/v1/login")
		}
		if ref.Method != "login" {
			t.Errorf("Method = %q, want %q", ref.Method, "login")
		}
		if ref.MatchedTerm != "/api/v1/login" {
			t.Errorf("MatchedTerm = %q, want %q", ref.MatchedTerm, "/api/v1/login")
		}
		if ref.CallsNative {
			t.Error("CallsNative = true, want false (no native declarations in this file)")
		}
	})

	t.Run("OkHttp url() call tagged and enclosing method found", func(t *testing.T) {
		dir := t.TempDir()
		relFile := filepath.Join("com", "example", "net", "Uploader.java")
		writeJavaFile(t, filepath.Join(dir, relFile), `package com.example.net;

public class Uploader {
    public void upload(byte[] data) {
        Request req = new Request.Builder()
            .url("https://api.example.com/upload")
            .post(RequestBody.create(data))
            .build();
    }
}
`)

		refs := searchJavaSource(dir, []string{"https://api.example.com/upload", "api.example.com"})
		if len(refs) != 1 {
			t.Fatalf("len(refs) = %d, want 1 (%+v)", len(refs), refs)
		}
		ref := refs[0]
		if ref.Annotation != "OkHttp" {
			t.Errorf("Annotation = %q, want %q", ref.Annotation, "OkHttp")
		}
		if ref.Method != "upload" {
			t.Errorf("Method = %q, want %q (enclosing method)", ref.Method, "upload")
		}
		if ref.MatchedTerm != "https://api.example.com/upload" {
			t.Errorf("MatchedTerm = %q, want the more specific term to win", ref.MatchedTerm)
		}
	})

	t.Run("native declarations and loadLibrary are attributed to matches in the same file", func(t *testing.T) {
		dir := t.TempDir()
		relFile := filepath.Join("com", "example", "crypto", "Signer.java")
		writeJavaFile(t, filepath.Join(dir, relFile), `package com.example.crypto;

public class Signer {
    static {
        System.loadLibrary("signcore");
    }

    public static native String nativeSign(String input);

    public String sign(String input) {
        return "/api/v1/sign" + nativeSign(input);
    }
}
`)

		refs := searchJavaSource(dir, []string{"/api/v1/sign"})
		if len(refs) != 1 {
			t.Fatalf("len(refs) = %d, want 1 (%+v)", len(refs), refs)
		}
		ref := refs[0]
		if !ref.CallsNative {
			t.Error("CallsNative = false, want true")
		}
		if !slices.Contains(ref.NativeMethods, "nativeSign") {
			t.Errorf("NativeMethods = %v, want it to contain %q", ref.NativeMethods, "nativeSign")
		}
		if !slices.Contains(ref.NativeMethods, "libsigncore.so") {
			t.Errorf("NativeMethods = %v, want it to contain %q", ref.NativeMethods, "libsigncore.so")
		}
	})

	t.Run("no matching terms yields no refs", func(t *testing.T) {
		dir := t.TempDir()
		writeJavaFile(t, filepath.Join(dir, "A.java"), "package a;\nclass A {}\n")
		if refs := searchJavaSource(dir, []string{"/not/present"}); len(refs) != 0 {
			t.Errorf("refs = %+v, want none", refs)
		}
	})

	t.Run("no search terms yields no refs, no panic", func(t *testing.T) {
		dir := t.TempDir()
		writeJavaFile(t, filepath.Join(dir, "A.java"), "package a;\nclass A {}\n")
		if refs := searchJavaSource(dir, nil); len(refs) != 0 {
			t.Errorf("refs = %+v, want none", refs)
		}
	})

	t.Run("nonexistent directory yields no refs, no error", func(t *testing.T) {
		if refs := searchJavaSource(filepath.Join(t.TempDir(), "missing"), []string{"/api"}); len(refs) != 0 {
			t.Errorf("refs = %+v, want none", refs)
		}
	})
}

// writeFakeTool creates an executable shell script at dir/name that prints
// output to stdout and exits with code exitCode. On a platform without a
// POSIX shell (there is none relevant to this repo's supported OSes) tests
// calling this skip themselves rather than failing for an unrelated reason.
func writeFakeTool(t *testing.T, dir, name, output string, exitCode int) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake tool script requires a POSIX shell")
	}
	path := filepath.Join(dir, name)
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s' '%s'\nexit %d\n", output, exitCode)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
	return path
}

func TestDecompileJadx(t *testing.T) {
	t.Run("skips re-running when outDir already exists", func(t *testing.T) {
		dir := t.TempDir()
		outDir := filepath.Join(dir, "out")
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}

		// A jadx path that would error if actually invoked -- proves the
		// pre-existing outDir short-circuits before any exec happens.
		err := decompileJadx(filepath.Join(dir, "does-not-exist"), "app.apk", outDir, time.Second)
		if err != nil {
			t.Errorf("decompileJadx() = %v, want nil (should skip, not invoke the missing tool)", err)
		}
	})

	t.Run("successful run creates outDir via the tool", func(t *testing.T) {
		dir := t.TempDir()
		outDir := filepath.Join(dir, "out")
		tool := writeFakeExecScript(t, dir, "fake-jadx-ok", `mkdir -p "$2"`, 0)

		if err := decompileJadx(tool, "app.apk", outDir, time.Second); err != nil {
			t.Fatalf("decompileJadx: %v", err)
		}
		if fi, err := os.Stat(outDir); err != nil || !fi.IsDir() {
			t.Errorf("outDir %s was not created by the tool", outDir)
		}
	})

	t.Run("tool failure returns a descriptive error", func(t *testing.T) {
		dir := t.TempDir()
		outDir := filepath.Join(dir, "out")
		tool := writeFakeExecScript(t, dir, "fake-jadx-fail", `echo "boom: bad apk"`, 1)

		err := decompileJadx(tool, "app.apk", outDir, time.Second)
		if err == nil {
			t.Fatal("decompileJadx() = nil, want an error")
		}
		if !strings.Contains(err.Error(), "boom: bad apk") {
			t.Errorf("error = %q, want it to include the tool's output", err.Error())
		}
	})

	t.Run("timeout is enforced even if the tool spawns a stuck grandchild", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("fake tool script requires a POSIX shell")
		}
		dir := t.TempDir()
		outDir := filepath.Join(dir, "out")
		// The shell forks "sleep" as a child rather than exec-replacing
		// itself, so killing the direct child alone (without WaitDelay)
		// would leave CombinedOutput blocked on the pipe until sleep exits.
		tool := writeFakeExecScript(t, dir, "fake-jadx-hang", `(sleep 2 &) ; sleep 2`, 0)

		start := time.Now()
		if err := decompileJadx(tool, "app.apk", outDir, 50*time.Millisecond); err == nil {
			t.Error("decompileJadx() = nil, want a timeout error")
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("took %v, want it bounded well under the 2s sleep", elapsed)
		}
	})
}

// writeFakeExecScript creates an executable shell script at dir/name whose
// body is bodyScript, exiting with exitCode. Used to stand in for jadx or
// r2 (bodyScript can reference "$@"/"$2"/etc per whichever tool's argument
// shape the test needs, e.g. jadx's "-d $2" output directory).
func writeFakeExecScript(t *testing.T, dir, name, bodyScript string, exitCode int) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake tool script requires a POSIX shell")
	}
	path := filepath.Join(dir, name)
	script := fmt.Sprintf("#!/bin/sh\n%s\nexit %d\n", bodyScript, exitCode)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
	return path
}

func TestDecodeR2Analysis(t *testing.T) {
	t.Run("decodes two back-to-back JSON arrays (izzj then aflj output)", func(t *testing.T) {
		// This is the literal shape `r2 -q -c "izzj; aa; aflj" file`
		// produces: `aa` itself prints nothing, so the combined output is
		// just the strings array immediately followed by the functions
		// array -- verified against a real .so with a real r2 build.
		combined := `[{"vaddr":100,"paddr":100,"string":"hello"}]` +
			`[{"offset":4096,"name":"sym.JNI_OnLoad"}]`

		strs, funcs, err := decodeR2Analysis([]byte(combined))
		if err != nil {
			t.Fatalf("decodeR2Analysis: %v", err)
		}
		if len(strs) != 1 || strs[0].String != "hello" || strs[0].Vaddr != 100 {
			t.Errorf("strs = %+v, want one entry {100 100 hello}", strs)
		}
		if len(funcs) != 1 || funcs[0].Name != "sym.JNI_OnLoad" || funcs[0].Offset != 4096 {
			t.Errorf("funcs = %+v, want one entry {4096 sym.JNI_OnLoad}", funcs)
		}
	})

	t.Run("malformed output is an error, not a panic", func(t *testing.T) {
		if _, _, err := decodeR2Analysis([]byte("not json at all")); err == nil {
			t.Error("decodeR2Analysis(garbage) = nil error, want non-nil")
		}
	})

	t.Run("truncated output (first array only) is an error", func(t *testing.T) {
		if _, _, err := decodeR2Analysis([]byte(`[{"string":"x"}]`)); err == nil {
			t.Error("decodeR2Analysis(one array) = nil error, want non-nil (functions array missing)")
		}
	})
}

func TestIsInterestingNativeString(t *testing.T) {
	tests := []struct {
		name  string
		s     string
		terms []string
		want  bool
	}{
		{"matches a crypto keyword", "AES/CBC/PKCS5Padding", nil, true},
		{"matches sign as a whole word", "sign_params_and_secret", nil, true},
		{"matches a flow search term", "/api/v1/user/profile", []string{"/api/v1/user/profile"}, true},
		{"matches a URL", "https://api.example.com/upload", nil, true},
		{"mangled C++ symbol is excluded even though it contains sign", "_ZNKSt6__ndk110moneypunctIcLb0EE16do_negative_signEv", nil, false},
		{"sign embedded without a word boundary does not match", "AssignmentOperator", nil, false},
		{"boring string matches nothing", "hello world", nil, false},
		{"empty string is never interesting", "", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isInterestingNativeString(tt.s, tt.terms); got != tt.want {
				t.Errorf("isInterestingNativeString(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestExtractCallTargets(t *testing.T) {
	t.Run("pulls the target symbol off each call op, ignoring non-calls", func(t *testing.T) {
		// Matches the real shape of `r2 -q -c "aa; pdfj @ sym.X" file`.
		pdfj := `{"name":"sym.JNI_OnLoad","size":52,"addr":236416,"ops":[
			{"offset":236416,"type":"mov","disasm":"mov x0, x1"},
			{"offset":236420,"type":"call","disasm":"bl sym.imp.__stack_chk_fail"},
			{"offset":236424,"type":"call","disasm":"bl sym.imp.MD5_Update"},
			{"offset":236428,"type":"call","disasm":"bl sym.imp.__stack_chk_fail"}
		]}`

		calls := extractCallTargets([]byte(pdfj))
		want := []string{"sym.imp.__stack_chk_fail", "sym.imp.MD5_Update"}
		if !slices.Equal(calls, want) {
			t.Errorf("calls = %v, want %v (deduped, in order, non-calls ignored)", calls, want)
		}
	})

	t.Run("malformed input yields no calls, no panic", func(t *testing.T) {
		if calls := extractCallTargets([]byte("not json")); len(calls) != 0 {
			t.Errorf("calls = %v, want none", calls)
		}
	})
}

func TestBuildNativeRefs(t *testing.T) {
	strs := []r2StringEntry{
		{Vaddr: 100, String: "https://api.example.com/sign"},
		{Vaddr: 200, String: "AES/CBC/PKCS5Padding"},
		{Vaddr: 300, String: "hello world"}, // not interesting
	}
	funcs := []r2FunctionEntry{
		{Offset: 0x1000, Name: "sym.imp.memcpy"},
		{Offset: 0x2000, Name: "sym.JNI_OnLoad"},
		{Offset: 0x3000, Name: "sym.Java_com_example_Crypto_nativeHash"},
		{Offset: 0x4000, Name: "sym.nativeSign"}, // matches a known declared method
		{Offset: 0x5000, Name: "sym.unrelatedHelper"},
	}
	knownMethods := []string{"nativeSign"}

	t.Run("reports JNI_OnLoad, Java_* exports, and matched known methods", func(t *testing.T) {
		disasmCalls := map[string][]string{
			"sym.nativeSign": {"sym.imp.MD5_Update"},
		}
		refs := buildNativeRefs("libfoo.so", strs, funcs, knownMethods, nil, func(funcName string) []string {
			return disasmCalls[funcName]
		})

		byFunc := make(map[string]NativeRef, len(refs))
		for _, r := range refs {
			byFunc[r.Function] = r
		}

		onLoad, ok := byFunc["JNI_OnLoad"]
		if !ok {
			t.Fatalf("missing JNI_OnLoad ref, got %+v", refs)
		}
		if onLoad.Address != "0x2000" {
			t.Errorf("JNI_OnLoad.Address = %q, want %q", onLoad.Address, "0x2000")
		}
		if onLoad.SOFile != "libfoo.so" {
			t.Errorf("JNI_OnLoad.SOFile = %q, want %q", onLoad.SOFile, "libfoo.so")
		}
		if !slices.Contains(onLoad.Strings, "https://api.example.com/sign") || !slices.Contains(onLoad.Strings, "AES/CBC/PKCS5Padding") {
			t.Errorf("JNI_OnLoad.Strings = %v, want both interesting strings", onLoad.Strings)
		}
		if slices.Contains(onLoad.Strings, "hello world") {
			t.Errorf("JNI_OnLoad.Strings = %v, want the boring string excluded", onLoad.Strings)
		}

		javaExport, ok := byFunc["Java_com_example_Crypto_nativeHash"]
		if !ok {
			t.Fatalf("missing Java_* export ref, got %+v", refs)
		}
		if javaExport.Address != "0x3000" {
			t.Errorf("Java_* export.Address = %q, want %q", javaExport.Address, "0x3000")
		}

		signed, ok := byFunc["nativeSign"]
		if !ok {
			t.Fatalf("missing matched-known-method ref, got %+v", refs)
		}
		if !slices.Equal(signed.Calls, []string{"sym.imp.MD5_Update"}) {
			t.Errorf("nativeSign.Calls = %v, want [sym.imp.MD5_Update] (from disasm)", signed.Calls)
		}

		if _, ok := byFunc["memcpy"]; ok {
			t.Error("plain import memcpy should not be reported as its own NativeRef")
		}
		if _, ok := byFunc["unrelatedHelper"]; ok {
			t.Error("an unrelated, non-exported, non-matched function should not be reported")
		}

		wantImports := []string{"memcpy"}
		if !slices.Equal(onLoad.Imports, wantImports) {
			t.Errorf("Imports = %v, want %v", onLoad.Imports, wantImports)
		}
	})

	t.Run("falls back to a strings-only summary ref when no function matches", func(t *testing.T) {
		noMatchFuncs := []r2FunctionEntry{{Offset: 0x9000, Name: "sym.unrelatedHelper"}}
		refs := buildNativeRefs("libbar.so", strs, noMatchFuncs, nil, nil, nil)
		if len(refs) != 1 {
			t.Fatalf("len(refs) = %d, want 1 (%+v)", len(refs), refs)
		}
		if refs[0].Function != "" {
			t.Errorf("Function = %q, want empty (strings-only summary)", refs[0].Function)
		}
		if len(refs[0].Strings) == 0 {
			t.Error("Strings = empty, want the interesting strings carried through")
		}
	})

	t.Run("nothing interesting at all yields no refs", func(t *testing.T) {
		boring := []r2StringEntry{{Vaddr: 1, String: "hello world"}}
		boringFuncs := []r2FunctionEntry{{Offset: 1, Name: "sym.unrelatedHelper"}}
		if refs := buildNativeRefs("libbaz.so", boring, boringFuncs, nil, nil, nil); len(refs) != 0 {
			t.Errorf("refs = %+v, want none", refs)
		}
	})
}

func TestAnalyzeNative(t *testing.T) {
	dir := t.TempDir()
	soFile := filepath.Join(dir, "libfake.so")
	if err := os.WriteFile(soFile, []byte("not a real ELF, just a placeholder path"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	t.Run("nonexistent r2 binary is an error", func(t *testing.T) {
		if _, err := analyzeNative(filepath.Join(dir, "no-such-r2"), soFile, nil, nil, time.Second); err == nil {
			t.Error("analyzeNative() = nil error, want non-nil")
		}
	})

	t.Run("wires a real invocation's output through decodeR2Analysis/buildNativeRefs", func(t *testing.T) {
		// Always emits the izzj+aflj shape, regardless of the command
		// string r2 was invoked with -- sufficient to prove analyzeNative's
		// own glue (invoke, decode, build) works; buildNativeRefs/
		// decodeR2Analysis/extractCallTargets are already covered in
		// detail by their own dedicated tests above.
		fakeR2 := writeFakeExecScript(t, dir, "fake-r2", `cat <<'JSON'
[{"vaddr":1,"string":"https://api.example.com/sign"}]
[{"offset":4096,"name":"sym.JNI_OnLoad"}]
JSON`, 0)

		refs, err := analyzeNative(fakeR2, soFile, nil, nil, time.Second)
		if err != nil {
			t.Fatalf("analyzeNative: %v", err)
		}
		if len(refs) != 1 || refs[0].Function != "JNI_OnLoad" {
			t.Fatalf("refs = %+v, want one JNI_OnLoad ref", refs)
		}
		if refs[0].SOFile != "libfake.so" {
			t.Errorf("SOFile = %q, want %q", refs[0].SOFile, "libfake.so")
		}
	})

	t.Run("tool failure is an error", func(t *testing.T) {
		fakeR2 := writeFakeExecScript(t, dir, "fake-r2-fail", `echo "r2: cannot open file"`, 1)
		if _, err := analyzeNative(fakeR2, soFile, nil, nil, time.Second); err == nil {
			t.Error("analyzeNative() = nil error, want non-nil")
		}
	})
}

func TestBuildCallGraph(t *testing.T) {
	flow := &types.Flow{Method: "POST", URL: "https://api.example.com/api/v1/sign", Host: "api.example.com", Path: "/api/v1/sign"}

	t.Run("http to java edge for a plain match with no native involvement", func(t *testing.T) {
		javaRefs := []JavaRef{{Class: "com.example.api.SignApi", Method: "sign", Annotation: "POST /api/v1/sign"}}

		edges := buildCallGraph(flow, javaRefs, nil)

		want := []CallEdge{
			{From: "App", To: "POST /api/v1/sign", Type: "http", Label: "api.example.com"},
			{From: "POST /api/v1/sign", To: "com.example.api.SignApi.sign()", Type: "java_call", Label: "POST /api/v1/sign"},
		}
		if !slices.Equal(edges, want) {
			t.Errorf("edges = %+v, want %+v", edges, want)
		}
	})

	t.Run("java to native chain bridges the declared JNI symbol to its resolved .so:function", func(t *testing.T) {
		javaRefs := []JavaRef{{
			Class:         "com.example.crypto.Signer",
			Method:        "sign",
			CallsNative:   true,
			NativeMethods: []string{"libfoo.so", "nativeSign"},
		}}
		nativeRefs := []NativeRef{{
			SOFile:   "libfoo.so",
			Function: "nativeSign",
			Calls:    []string{"sym.imp.MD5_Update"},
		}}

		edges := buildCallGraph(flow, javaRefs, nativeRefs)

		javaNode := "com.example.crypto.Signer.sign()"
		wantEdges := []CallEdge{
			{From: "App", To: "POST /api/v1/sign", Type: "http", Label: "api.example.com"},
			{From: "POST /api/v1/sign", To: javaNode, Type: "java_call"},
			{From: javaNode, To: "libfoo.so", Type: "jni", Label: "loadLibrary"},
			{From: javaNode, To: "native:nativeSign", Type: "jni"},
			{From: "native:nativeSign", To: "libfoo.so:nativeSign", Type: "native_call", Label: "resolved"},
			{From: "libfoo.so:nativeSign", To: "sym.imp.MD5_Update", Type: "native_call"},
		}
		if !slices.Equal(edges, wantEdges) {
			t.Errorf("edges = %+v, want %+v", edges, wantEdges)
		}
	})

	t.Run("an orphan NativeRef (no declaring JavaRef) still contributes its own call edges", func(t *testing.T) {
		nativeRefs := []NativeRef{{SOFile: "libbar.so", Function: "JNI_OnLoad", Calls: []string{"sym.imp.RegisterNatives"}}}

		edges := buildCallGraph(flow, nil, nativeRefs)

		want := []CallEdge{
			{From: "App", To: "POST /api/v1/sign", Type: "http", Label: "api.example.com"},
			{From: "libbar.so:JNI_OnLoad", To: "sym.imp.RegisterNatives", Type: "native_call"},
		}
		if !slices.Equal(edges, want) {
			t.Errorf("edges = %+v, want %+v", edges, want)
		}
	})

	t.Run("nil flow does not panic", func(t *testing.T) {
		edges := buildCallGraph(nil, []JavaRef{{Class: "A", Method: "b"}}, nil)
		if len(edges) == 0 {
			t.Error("edges = empty, want at least the App->http edge")
		}
	})
}

func TestMermaidNodeID(t *testing.T) {
	tests := []struct{ in, want string }{
		{"App", "App"},
		{"POST /api/v1/sign", "POST_api_v1_sign"},
		{"libfoo.so:nativeSign", "libfoo_so_nativeSign"},
		{"123leading", "n123leading"},
		{"", "node"},
		{"///", "node"},
	}
	for _, tt := range tests {
		if got := mermaidNodeID(tt.in); got != tt.want {
			t.Errorf("mermaidNodeID(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestMermaidLabel(t *testing.T) {
	t.Run("escapes double quotes", func(t *testing.T) {
		if got := mermaidLabel(`say "hi"`); got != `say 'hi'` {
			t.Errorf("mermaidLabel = %q, want %q", got, `say 'hi'`)
		}
	})
	t.Run("collapses embedded newlines", func(t *testing.T) {
		if got := mermaidLabel("line1\nline2"); got != "line1 line2" {
			t.Errorf("mermaidLabel = %q, want %q", got, "line1 line2")
		}
	})
	t.Run("truncates very long labels", func(t *testing.T) {
		long := strings.Repeat("x", maxMermaidLabelLen+50)
		got := mermaidLabel(long)
		if len(got) != maxMermaidLabelLen {
			t.Errorf("len(mermaidLabel(long)) = %d, want %d", len(got), maxMermaidLabelLen)
		}
		if !strings.HasSuffix(got, "...") {
			t.Errorf("mermaidLabel(long) = %q, want it to end with an ellipsis", got)
		}
	})
	t.Run("short label is unchanged", func(t *testing.T) {
		if got := mermaidLabel("short"); got != "short" {
			t.Errorf("mermaidLabel = %q, want %q", got, "short")
		}
	})
}

func TestGenerateMermaid(t *testing.T) {
	t.Run("empty graph still emits the styled header", func(t *testing.T) {
		out := generateMermaid(nil)
		if !strings.HasPrefix(out, "graph TD\n") {
			t.Errorf("output does not start with \"graph TD\": %q", out)
		}
		for _, class := range []string{"http", "java", "jni", "native"} {
			if !strings.Contains(out, "classDef "+class+" ") {
				t.Errorf("output missing classDef for %q:\n%s", class, out)
			}
		}
	})

	t.Run("full HTTP -> Java -> JNI -> native chain", func(t *testing.T) {
		edges := []CallEdge{
			{From: "App", To: "POST /api/v1/sign", Type: "http", Label: "api.example.com"},
			{From: "POST /api/v1/sign", To: "com.example.crypto.Signer.sign()", Type: "java_call"},
			{From: "com.example.crypto.Signer.sign()", To: "native:nativeSign", Type: "jni"},
			{From: "native:nativeSign", To: "libfoo.so:nativeSign", Type: "native_call", Label: "resolved"},
			{From: "libfoo.so:nativeSign", To: "sym.imp.MD5_Update", Type: "native_call"},
		}
		out := generateMermaid(edges)
		lines := strings.Split(out, "\n")

		appID := mermaidNodeID("App")
		httpID := mermaidNodeID("POST /api/v1/sign")
		javaID := mermaidNodeID("com.example.crypto.Signer.sign()")
		jniID := mermaidNodeID("native:nativeSign")
		nativeID := mermaidNodeID("libfoo.so:nativeSign")
		callID := mermaidNodeID("sym.imp.MD5_Update")

		wantLines := []string{
			fmt.Sprintf(`    %s["App"] --> %s["POST /api/v1/sign"]:::http`, appID, httpID),
			fmt.Sprintf(`    %s --> %s["com.example.crypto.Signer.sign()"]:::java`, httpID, javaID),
			fmt.Sprintf(`    %s -.->|JNI| %s["native:nativeSign"]:::jni`, javaID, jniID),
			fmt.Sprintf(`    %s ==>|resolved| %s["libfoo.so:nativeSign"]:::native`, jniID, nativeID),
			fmt.Sprintf(`    %s ==> %s["sym.imp.MD5_Update"]:::native`, nativeID, callID),
		}
		for _, want := range wantLines {
			if !slices.Contains(lines, want) {
				t.Errorf("output missing line %q\nfull output:\n%s", want, out)
			}
		}
	})

	t.Run("a node is declared with its label+class only on first appearance", func(t *testing.T) {
		edges := []CallEdge{
			{From: "App", To: "shared", Type: "http"},
			{From: "shared", To: "other", Type: "java_call"},
			{From: "another", To: "shared", Type: "java_call"},
		}
		out := generateMermaid(edges)
		sharedID := mermaidNodeID("shared")
		if n := strings.Count(out, sharedID+`["shared"]`); n != 1 {
			t.Errorf(`output declares %q %d times, want exactly once:%s`, sharedID+`["shared"]`, n, out)
		}
	})

	t.Run("edge label with double quotes is escaped", func(t *testing.T) {
		// native_call is one of the two edge types (with jni) whose label
		// actually renders -- see the "full chain" subtest above for why
		// http/java_call deliberately never show one.
		edges := []CallEdge{{From: "App", To: "B", Type: "native_call", Label: `say "hi"`}}
		out := generateMermaid(edges)
		if strings.Contains(out, `"hi"`) {
			t.Errorf("output contains an unescaped embedded quote:\n%s", out)
		}
		if !strings.Contains(out, `say 'hi'`) {
			t.Errorf("output missing escaped label:\n%s", out)
		}
	})
}

func TestGenerateSummary(t *testing.T) {
	result := &TraceResult{
		Method:      "POST",
		URL:         "https://api.example.com/api/v1/sign",
		APKInfo:     &APKInfo{Package: "com.example.app"},
		DexStrings:  []DexMatch{{String: "/api/v1/sign"}},
		JavaTrace:   []JavaRef{{File: "com/example/SignApi.java", Line: 42}},
		NativeTrace: []NativeRef{{SOFile: "libfoo.so", Function: "nativeSign"}},
		ToolsUsed:   []string{"apk_info", "dex_search", "jadx"},
	}

	summary := generateSummary(result)

	for _, want := range []string{
		"POST", "https://api.example.com/api/v1/sign",
		"com.example.app",
		"com/example/SignApi.java",
	} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary missing %q:\n%s", want, summary)
		}
	}

	t.Run("nil result does not panic", func(t *testing.T) {
		if generateSummary(nil) != "" {
			t.Error("generateSummary(nil) != \"\"")
		}
	})
}

// stepCall records one StepCallback invocation, in order.
type stepCall struct{ step, detail string }

func TestTraceWithCallback(t *testing.T) {
	t.Run("hermetic success: dex search and apk info run, jadx/r2 skip gracefully", func(t *testing.T) {
		dir := t.TempDir()

		manifest := buildFakeManifest(t, []axmlElem{
			{name: "manifest", attrs: []axmlAttr{strAttr("package", "com.example.app")}},
		})
		classesDex := bytes.Join([][]byte{
			{0x64, 0x65, 0x78, 0x0a}, []byte("/api/v1/sign"), []byte("com/example/SignApi"),
		}, []byte{0x00})
		apkPath := writeTestZip(t, filepath.Join(dir, "app.apk"), map[string][]byte{
			"AndroidManifest.xml": manifest,
			"classes.dex":         classesDex,
		})

		flow := &types.Flow{ID: "f1", Method: "POST", URL: "https://api.example.com/api/v1/sign", Host: "api.example.com", Path: "/api/v1/sign"}
		opts := Options{
			APKPath:   apkPath,
			OutputDir: filepath.Join(dir, "out"),
			JadxPath:  filepath.Join(dir, "no-such-jadx"),
			R2Path:    filepath.Join(dir, "no-such-r2"),
		}

		var calls []stepCall
		result, err := Trace(flow, opts, func(step, detail string) {
			calls = append(calls, stepCall{step, detail})
		})
		if err != nil {
			t.Fatalf("Trace: %v", err)
		}

		if result.FlowID != "f1" {
			t.Errorf("FlowID = %q, want %q", result.FlowID, "f1")
		}
		if result.APKPath != apkPath {
			t.Errorf("APKPath = %q, want %q", result.APKPath, apkPath)
		}
		if result.APKInfo == nil || result.APKInfo.Package != "com.example.app" {
			t.Errorf("APKInfo = %+v, want Package com.example.app", result.APKInfo)
		}
		if len(result.DexStrings) == 0 {
			t.Error("DexStrings is empty, want at least the /api/v1/sign match")
		}
		if len(result.JavaTrace) != 0 {
			t.Errorf("JavaTrace = %+v, want empty (jadx unavailable)", result.JavaTrace)
		}
		if len(result.NativeTrace) != 0 {
			t.Errorf("NativeTrace = %+v, want empty (r2 unavailable)", result.NativeTrace)
		}
		if !strings.HasPrefix(result.Mermaid, "graph TD") {
			t.Errorf("Mermaid = %q, want it to start with \"graph TD\"", result.Mermaid)
		}
		if result.Summary == "" {
			t.Error("Summary is empty")
		}

		stepStatus := make(map[string]string, len(result.Steps))
		for _, s := range result.Steps {
			stepStatus[s.Name] = s.Status
		}
		wantStatus := map[string]string{
			"start":       "ok",
			"resolve_apk": "ok",
			"apk_info":    "ok",
			"dex_search":  "ok",
			"jadx_check":  "skip",
			"r2_check":    "skip",
			"done":        "ok",
		}
		for name, want := range wantStatus {
			got, ok := stepStatus[name]
			if !ok {
				t.Errorf("missing step %q in Steps = %+v", name, result.Steps)
				continue
			}
			if got != want {
				t.Errorf("step %q status = %q, want %q", name, got, want)
			}
		}

		if len(calls) != len(result.Steps) {
			t.Fatalf("callback invoked %d times, want once per step (%d)", len(calls), len(result.Steps))
		}
		if calls[0].step != "start" {
			t.Errorf("calls[0].step = %q, want %q", calls[0].step, "start")
		}
		if calls[len(calls)-1].step != "done" {
			t.Errorf("last call's step = %q, want %q", calls[len(calls)-1].step, "done")
		}
	})

	t.Run("nil callback does not panic and Steps are still recorded", func(t *testing.T) {
		dir := t.TempDir()
		apkPath := writeTestZip(t, filepath.Join(dir, "app.apk"), map[string][]byte{
			"classes.dex": []byte("dex-stub"),
		})
		flow := &types.Flow{URL: "https://x.io/a/b", Host: "x.io", Path: "/a/b"}
		opts := Options{
			APKPath:   apkPath,
			OutputDir: filepath.Join(dir, "out"),
			JadxPath:  filepath.Join(dir, "no-such-jadx"),
			R2Path:    filepath.Join(dir, "no-such-r2"),
		}

		result, err := Trace(flow, opts, nil)
		if err != nil {
			t.Fatalf("Trace: %v", err)
		}
		if len(result.Steps) == 0 {
			t.Error("Steps is empty even with a nil callback")
		}
	})

	t.Run("no APK path or package: returns an error but still a usable partial result", func(t *testing.T) {
		flow := &types.Flow{URL: "https://x.io/a", Host: "x.io", Path: "/a"}
		opts := Options{OutputDir: t.TempDir()}

		var calls []stepCall
		result, err := Trace(flow, opts, func(step, detail string) {
			calls = append(calls, stepCall{step, detail})
		})
		if err == nil {
			t.Fatal("Trace() = nil error, want non-nil (no APK available)")
		}
		if result == nil {
			t.Fatal("Trace() returned nil result alongside the error, want a usable partial result")
		}
		if len(calls) == 0 {
			t.Error("callback was never invoked")
		}
		if calls[len(calls)-1].step != "done" {
			t.Errorf("last call's step = %q, want %q", calls[len(calls)-1].step, "done")
		}
	})
}

func TestToolVersion(t *testing.T) {
	dir := t.TempDir()

	t.Run("available tool reports its first output line", func(t *testing.T) {
		tool := writeFakeTool(t, dir, "fake-jadx-ok", "jadx 1.4.7\nextra line\n", 0)
		version, ok := toolVersion(tool, time.Second, "--version")
		if !ok {
			t.Fatal("ok = false, want true")
		}
		if version != "jadx 1.4.7" {
			t.Errorf("version = %q, want %q", version, "jadx 1.4.7")
		}
	})

	t.Run("nonexistent binary is unavailable", func(t *testing.T) {
		if _, ok := toolVersion(filepath.Join(dir, "does-not-exist"), time.Second, "--version"); ok {
			t.Error("ok = true, want false")
		}
	})

	t.Run("empty path is unavailable", func(t *testing.T) {
		if _, ok := toolVersion("", time.Second, "--version"); ok {
			t.Error("ok = true, want false")
		}
	})

	t.Run("non-zero exit is unavailable", func(t *testing.T) {
		tool := writeFakeTool(t, dir, "fake-jadx-fail", "error\n", 1)
		if _, ok := toolVersion(tool, time.Second, "--version"); ok {
			t.Error("ok = true, want false")
		}
	})

	t.Run("exceeding the timeout is unavailable", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("fake tool script requires a POSIX shell")
		}
		path := filepath.Join(dir, "fake-sleep")
		if err := os.WriteFile(path, []byte("#!/bin/sh\nsleep 2\n"), 0o755); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		start := time.Now()
		if _, ok := toolVersion(path, 50*time.Millisecond, "--version"); ok {
			t.Error("ok = true, want false")
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("took %v, want it bounded by the 50ms timeout", elapsed)
		}
	})
}
