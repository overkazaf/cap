package unpin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMethodString(t *testing.T) {
	tests := []struct {
		m    Method
		want string
	}{
		{MethodFrida, "frida"},
		{MethodPatch, "patch"},
		{MethodMagisk, "magisk"},
		{Method(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.m.String(); got != tt.want {
			t.Errorf("Method(%d).String() = %q, want %q", tt.m, got, tt.want)
		}
	}
}

func TestGetFridaScript(t *testing.T) {
	script := GetFridaScript()
	if script == "" {
		t.Fatal("GetFridaScript() returned empty string")
	}

	required := []string{
		"Java.perform",
		"TrustManagerImpl",
		"CertificatePinner",
		"SSLContext",
		"WebViewClient",
		"Conscrypt",
		"cap unpin",
	}
	for _, kw := range required {
		if !strings.Contains(script, kw) {
			t.Errorf("Frida script missing expected keyword %q", kw)
		}
	}
}

func TestFridaUnpinRequiresPackage(t *testing.T) {
	_, err := FridaUnpin(FridaOptions{})
	if err == nil {
		t.Fatal("expected error for empty package name")
	}
}

func TestPatchAPKRequiresPath(t *testing.T) {
	_, err := PatchAPK(PatchOptions{})
	if err == nil {
		t.Fatal("expected error for empty APK path")
	}
}

func TestPatchAPKRequiresExistingFile(t *testing.T) {
	_, err := PatchAPK(PatchOptions{APKPath: "/nonexistent/path.apk"})
	if err == nil {
		t.Fatal("expected error for nonexistent APK")
	}
}

func TestPatchManifest_AddNew(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "AndroidManifest.xml")
	content := `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example">
    <application android:label="Test">
        <activity android:name=".MainActivity"/>
    </application>
</manifest>`
	os.WriteFile(manifest, []byte(content), 0644)

	if err := patchManifest(manifest); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(manifest)
	patched := string(data)
	if !strings.Contains(patched, `android:networkSecurityConfig="@xml/network_security_config"`) {
		t.Error("patched manifest missing networkSecurityConfig attribute")
	}
}

func TestPatchManifest_ReplaceExisting(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "AndroidManifest.xml")
	content := `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example">
    <application android:networkSecurityConfig="@xml/old_config" android:label="Test">
        <activity android:name=".MainActivity"/>
    </application>
</manifest>`
	os.WriteFile(manifest, []byte(content), 0644)

	if err := patchManifest(manifest); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(manifest)
	patched := string(data)
	if !strings.Contains(patched, `android:networkSecurityConfig="@xml/network_security_config"`) {
		t.Error("patched manifest missing updated networkSecurityConfig")
	}
	if strings.Contains(patched, "old_config") {
		t.Error("old config reference not replaced")
	}
}

func TestPatchManifest_NoApplication(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "AndroidManifest.xml")
	os.WriteFile(manifest, []byte(`<manifest/>`), 0644)

	err := patchManifest(manifest)
	if err == nil {
		t.Error("expected error for manifest without <application>")
	}
}

func TestNetworkSecurityConfig(t *testing.T) {
	if !strings.Contains(networkSecurityConfig, `<certificates src="user"`) {
		t.Error("config missing user cert trust")
	}
	if !strings.Contains(networkSecurityConfig, `<certificates src="system"`) {
		t.Error("config missing system cert trust")
	}
	if !strings.Contains(networkSecurityConfig, `cleartextTrafficPermitted="true"`) {
		t.Error("config missing cleartext traffic permission")
	}
}
