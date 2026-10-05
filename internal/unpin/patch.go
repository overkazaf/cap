package unpin

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// PatchOptions configures APK network-security-config patching.
type PatchOptions struct {
	APKPath   string // path to the original APK
	OutputDir string // directory for the patched APK (empty = same dir as input)
}

// networkSecurityConfig is an XML config that trusts both system and user
// CA certificates, and disables certificate pinning for all domains.
const networkSecurityConfig = `<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
`

// PatchAPK decompiles an APK with apktool, injects a permissive
// network_security_config.xml, references it in AndroidManifest.xml,
// rebuilds, and signs the patched APK with a debug key.
//
// Requires: apktool, zipalign (optional), apksigner or jarsigner.
func PatchAPK(opts PatchOptions) (*Result, error) {
	if opts.APKPath == "" {
		return nil, fmt.Errorf("APK path is required")
	}
	if _, err := os.Stat(opts.APKPath); err != nil {
		return nil, fmt.Errorf("APK not found: %w", err)
	}

	if !which("apktool") {
		return &Result{
			Method:  MethodPatch,
			Success: false,
			Message: "apktool not found in PATH — install from https://apktool.org/",
		}, nil
	}

	outDir := opts.OutputDir
	if outDir == "" {
		outDir = filepath.Dir(opts.APKPath)
	}

	base := strings.TrimSuffix(filepath.Base(opts.APKPath), filepath.Ext(opts.APKPath))
	workDir := filepath.Join(outDir, base+"-cap-unpin")
	patchedAPK := filepath.Join(outDir, base+"-unpinned.apk")

	// Decompile
	fmt.Println("[cap unpin] Decompiling APK...")
	if out, err := exec.Command("apktool", "d", "-f", "-o", workDir, opts.APKPath).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("apktool decode: %s\n%w", out, err)
	}

	// Inject network_security_config.xml
	fmt.Println("[cap unpin] Injecting network_security_config.xml...")
	resXMLDir := filepath.Join(workDir, "res", "xml")
	if err := os.MkdirAll(resXMLDir, 0755); err != nil {
		return nil, fmt.Errorf("mkdir res/xml: %w", err)
	}
	nscPath := filepath.Join(resXMLDir, "network_security_config.xml")
	if err := os.WriteFile(nscPath, []byte(networkSecurityConfig), 0644); err != nil {
		return nil, fmt.Errorf("write network_security_config: %w", err)
	}

	// Patch AndroidManifest.xml to reference the config
	manifestPath := filepath.Join(workDir, "AndroidManifest.xml")
	if err := patchManifest(manifestPath); err != nil {
		return nil, fmt.Errorf("patch manifest: %w", err)
	}

	// Rebuild
	fmt.Println("[cap unpin] Rebuilding APK...")
	unsignedAPK := filepath.Join(outDir, base+"-unsigned.apk")
	if out, err := exec.Command("apktool", "b", "-o", unsignedAPK, workDir).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("apktool build: %s\n%w", out, err)
	}

	// Zipalign (optional but recommended)
	alignedAPK := unsignedAPK
	if which("zipalign") {
		fmt.Println("[cap unpin] Zipaligning...")
		aligned := filepath.Join(outDir, base+"-aligned.apk")
		if _, err := exec.Command("zipalign", "-f", "4", unsignedAPK, aligned).CombinedOutput(); err == nil {
			alignedAPK = aligned
			os.Remove(unsignedAPK)
		}
	}

	// Sign
	fmt.Println("[cap unpin] Signing APK...")
	if err := signAPK(alignedAPK, patchedAPK); err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	// Cleanup intermediate files
	if alignedAPK != patchedAPK {
		os.Remove(alignedAPK)
	}
	os.RemoveAll(workDir)

	return &Result{
		Method:  MethodPatch,
		Success: true,
		Message: fmt.Sprintf("Patched APK written to %s\nInstall: adb install -r %s", patchedAPK, patchedAPK),
		Output:  patchedAPK,
	}, nil
}

// patchManifest ensures AndroidManifest.xml has
// android:networkSecurityConfig="@xml/network_security_config" on the
// <application> element.
func patchManifest(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	content := string(data)
	if strings.Contains(content, "networkSecurityConfig") {
		// Replace existing reference
		// Find the existing attribute and replace its value
		idx := strings.Index(content, "android:networkSecurityConfig")
		if idx >= 0 {
			// Find the end of the attribute value
			eqIdx := strings.Index(content[idx:], "=")
			if eqIdx >= 0 {
				attrStart := idx + eqIdx + 1
				// Skip whitespace
				for attrStart < len(content) && content[attrStart] == ' ' {
					attrStart++
				}
				if attrStart < len(content) && content[attrStart] == '"' {
					endQuote := strings.Index(content[attrStart+1:], "\"")
					if endQuote >= 0 {
						end := attrStart + 1 + endQuote + 1
						content = content[:idx] + `android:networkSecurityConfig="@xml/network_security_config"` + content[end:]
					}
				}
			}
		}
	} else {
		// Add to <application> element
		appIdx := strings.Index(content, "<application")
		if appIdx < 0 {
			return fmt.Errorf("<application> element not found in manifest")
		}
		// Insert after "<application"
		insertAt := appIdx + len("<application")
		content = content[:insertAt] +
			` android:networkSecurityConfig="@xml/network_security_config"` +
			content[insertAt:]
	}

	return os.WriteFile(path, []byte(content), 0644)
}

func signAPK(input, output string) error {
	// Try uber-apk-signer first (easiest, no keystore needed)
	if which("uber-apk-signer") {
		out, err := exec.Command("uber-apk-signer", "-a", input, "-o", filepath.Dir(output)).CombinedOutput()
		if err == nil {
			// uber-apk-signer appends -aligned-debugSigned, rename to our desired name
			signed := strings.TrimSuffix(input, ".apk") + "-aligned-debugSigned.apk"
			if _, err := os.Stat(signed); err == nil {
				return os.Rename(signed, output)
			}
			return fmt.Errorf("uber-apk-signer output not found: %s", out)
		}
	}

	// Try apksigner with a debug keystore
	if which("apksigner") {
		ks, err := ensureDebugKeystore()
		if err != nil {
			return err
		}
		// Copy input to output first since apksigner signs in place
		data, err := os.ReadFile(input)
		if err != nil {
			return err
		}
		if err := os.WriteFile(output, data, 0644); err != nil {
			return err
		}
		out, err := exec.Command("apksigner", "sign",
			"--ks", ks,
			"--ks-pass", "pass:android",
			"--ks-key-alias", "androiddebugkey",
			output,
		).CombinedOutput()
		if err != nil {
			return fmt.Errorf("apksigner: %s\n%w", out, err)
		}
		return nil
	}

	// Fallback to jarsigner
	if which("jarsigner") {
		ks, err := ensureDebugKeystore()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(input)
		if err != nil {
			return err
		}
		if err := os.WriteFile(output, data, 0644); err != nil {
			return err
		}
		out, err := exec.Command("jarsigner",
			"-keystore", ks,
			"-storepass", "android",
			"-keypass", "android",
			output,
			"androiddebugkey",
		).CombinedOutput()
		if err != nil {
			return fmt.Errorf("jarsigner: %s\n%w", out, err)
		}
		return nil
	}

	return fmt.Errorf("no signing tool found — install apksigner, uber-apk-signer, or jarsigner")
}

// ensureDebugKeystore creates a debug keystore at ~/.cap/debug.keystore
// if one doesn't already exist.
func ensureDebugKeystore() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	ksDir := filepath.Join(home, ".cap")
	ksPath := filepath.Join(ksDir, "debug.keystore")

	if _, err := os.Stat(ksPath); err == nil {
		return ksPath, nil
	}

	if err := os.MkdirAll(ksDir, 0755); err != nil {
		return "", err
	}

	if !which("keytool") {
		return "", fmt.Errorf("keytool not found — install a JDK")
	}

	out, err := exec.Command("keytool",
		"-genkeypair",
		"-alias", "androiddebugkey",
		"-keypass", "android",
		"-keystore", ksPath,
		"-storepass", "android",
		"-dname", "CN=cap,OU=cap,O=cap,L=Unknown,S=Unknown,C=US",
		"-keyalg", "RSA",
		"-keysize", "2048",
		"-validity", "10000",
	).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("keytool: %s\n%w", out, err)
	}
	return ksPath, nil
}
