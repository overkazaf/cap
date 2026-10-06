package cli

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/overkazaf/cap/internal/android"
	"github.com/overkazaf/cap/internal/unpin"
)

func newUnpinCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "unpin",
		Short: "Bypass SSL certificate pinning on Android apps",
		Long: `Bypass SSL/TLS certificate pinning using one of three strategies:

  frida     — Runtime hooking via Frida (no APK modification, needs frida-server)
  patch     — Rewrite the APK's network_security_config.xml (no root needed)
  magisk    — System-wide Magisk module (promotes user certs to system store)
  codeshare — Search Frida CodeShare for scripts matching the target app

Examples:
  cap unpin frida --pkg com.example.app --spawn
  cap unpin patch --apk ./target.apk
  cap unpin magisk
  cap unpin codeshare --pkg com.example.app
  cap unpin codeshare --query "flutter ssl pinning"`,
	}

	cmd.AddCommand(
		newUnpinFridaCmd(),
		newUnpinPatchCmd(),
		newUnpinMagiskCmd(),
		newUnpinCodeShareCmd(),
		newUnpinScriptCmd(),
	)

	return cmd
}

func newUnpinFridaCmd() *cobra.Command {
	var (
		serial  string
		pkg     string
		spawn   bool
		dryRun  bool
	)

	cmd := &cobra.Command{
		Use:   "frida",
		Short: "Bypass pinning via Frida runtime hooks",
		Long: `Deploy a comprehensive Frida script that hooks common SSL pinning
implementations at runtime. Covers:

  - TrustManagerImpl (Android platform)
  - X509TrustManager (custom)
  - OkHttp3 CertificatePinner
  - SSLContext.init
  - WebViewClient.onReceivedSslError
  - Conscrypt / BoringSSL
  - Flutter / Dart BoringSSL
  - Apache HTTP client
  - TrustKit, Appcelerator, Cordova
  - NetworkSecurityConfig / PinSet`,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := unpin.FridaOptions{
				Serial:  serial,
				Package: pkg,
				Spawn:   spawn,
			}

			if dryRun {
				r, err := unpin.FridaUnpin(opts)
				if err != nil {
					return err
				}
				fmt.Println(r.Message)
				return nil
			}

			r, err := unpin.FridaSpawn(opts)
			if err != nil {
				return err
			}
			fmt.Println(r.Message)
			return nil
		},
	}

	cmd.Flags().StringVarP(&serial, "serial", "s", "", "device serial (auto-detect if omitted)")
	cmd.Flags().StringVar(&pkg, "pkg", "", "target app package name")
	cmd.Flags().BoolVarP(&spawn, "spawn", "f", false, "spawn the app (vs. attach to running process)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "write script and print command without running frida")
	_ = cmd.MarkFlagRequired("pkg")

	return cmd
}

func newUnpinPatchCmd() *cobra.Command {
	var (
		apkPath   string
		outputDir string
	)

	cmd := &cobra.Command{
		Use:   "patch",
		Short: "Patch an APK to trust user CA certificates",
		Long: `Decompile the target APK, inject a permissive network_security_config.xml
that trusts both system and user CA certificates, rebuild and sign.

Requires: apktool, keytool (JDK), and optionally zipalign + apksigner.
Does not require root on the device.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := unpin.PatchAPK(unpin.PatchOptions{
				APKPath:   apkPath,
				OutputDir: outputDir,
			})
			if err != nil {
				return err
			}
			fmt.Println(r.Message)
			return nil
		},
	}

	cmd.Flags().StringVar(&apkPath, "apk", "", "path to the APK to patch")
	cmd.Flags().StringVarP(&outputDir, "output", "o", "", "output directory (default: same as input)")
	_ = cmd.MarkFlagRequired("apk")

	return cmd
}

func newUnpinMagiskCmd() *cobra.Command {
	var (
		serial string
		remove bool
	)

	cmd := &cobra.Command{
		Use:   "magisk",
		Short: "Deploy a system-wide Magisk unpinning module",
		Long: `Install a Magisk module that promotes user-installed CA certificates to
the system trust store on boot. This makes all apps trust cap's MITM
certificate without needing per-app patching.

Requires: rooted device with Magisk. Reboot after install.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if remove {
				r, err := unpin.MagiskUnpinRemove(serial)
				if err != nil {
					return err
				}
				fmt.Println(r.Message)
				return nil
			}

			r, err := unpin.MagiskUnpin(unpin.MagiskOptions{
				Serial: serial,
			})
			if err != nil {
				return err
			}
			fmt.Println(r.Message)
			return nil
		},
	}

	cmd.Flags().StringVarP(&serial, "serial", "s", "", "device serial (auto-detect if omitted)")
	cmd.Flags().BoolVar(&remove, "remove", false, "remove the Magisk unpinning module")

	return cmd
}

func newUnpinCodeShareCmd() *cobra.Command {
	var (
		serial   string
		pkg      string
		query    string
		download string
		apkPath  string
	)

	cmd := &cobra.Command{
		Use:   "codeshare",
		Short: "Search Frida CodeShare for scripts matching the target app",
		Long: `Fingerprint the target app (from device or local APK) to detect its
framework (Flutter, React Native, Xamarin, etc.), pinning libraries
(OkHttp, TrustKit, Conscrypt), and security features, then search
Frida CodeShare for relevant bypass scripts.

Use --query for a direct keyword search, or --pkg to auto-detect
the app's characteristics and search accordingly.

Use --download to fetch a specific script by its slug.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Mode 1: Download a specific script
			if download != "" {
				return runCodeShareDownload(download)
			}

			// Mode 2: Direct keyword search
			if query != "" {
				return runCodeShareSearch(query)
			}

			// Mode 3: Auto-detect from device/APK
			if pkg != "" {
				return runCodeShareAuto(serial, pkg, apkPath)
			}

			return fmt.Errorf("provide --pkg, --query, or --download")
		},
	}

	cmd.Flags().StringVarP(&serial, "serial", "s", "", "device serial (auto-detect if omitted)")
	cmd.Flags().StringVar(&pkg, "pkg", "", "target app package name (fingerprints from device)")
	cmd.Flags().StringVarP(&query, "query", "q", "", "direct keyword search on CodeShare")
	cmd.Flags().StringVar(&download, "download", "", "download a script by slug (e.g. @user/project)")
	cmd.Flags().StringVar(&apkPath, "apk", "", "path to local APK for fingerprinting (instead of device)")

	return cmd
}

func runCodeShareSearch(query string) error {
	client := unpin.NewCodeShareClient()
	results, err := client.Search(query)
	if err != nil {
		return err
	}
	if len(results) == 0 {
		fmt.Printf("No results for %q\n", query)
		return nil
	}
	fmt.Printf("Found %d script(s) for %q:\n\n", len(results), query)
	for i, e := range results {
		fmt.Printf("  %d. %s\n", i+1, e.Title)
		if e.Author != "" {
			fmt.Printf("     Author: %s", e.Author)
		}
		if e.Likes != "" {
			fmt.Printf("  Likes: %s", e.Likes)
		}
		if e.Views != "" {
			fmt.Printf("  Views: %s", e.Views)
		}
		fmt.Println()
		if e.Description != "" {
			fmt.Printf("     %s\n", e.Description)
		}
		fmt.Printf("     Slug: %s\n", e.Slug)
		fmt.Println()
	}
	fmt.Println("Download a script: cap unpin codeshare --download <slug>")
	return nil
}

func runCodeShareDownload(slug string) error {
	scriptPath, err := unpin.DownloadScript(slug, "")
	if err != nil {
		return err
	}
	fmt.Printf("Script saved to %s\n", scriptPath)
	fmt.Printf("Run: frida -l %s -f <package>\n", scriptPath)
	return nil
}

func runCodeShareAuto(serial, pkg, apkPath string) error {
	fmt.Printf("[cap] Fingerprinting %s...\n", pkg)

	var soFiles, classes []string

	if apkPath != "" {
		// Fingerprint from local APK using trace.APKInfo
		soFiles, classes = fingerprintLocalAPK(apkPath)
	} else {
		// Fingerprint from device
		soFiles, classes = fingerprintFromDevice(serial, pkg)
	}

	fp := unpin.BuildFingerprint(pkg, soFiles, classes)

	// Print detected characteristics
	if len(fp.Frameworks) > 0 {
		fmt.Printf("[cap] Frameworks:  %s\n", join(fp.Frameworks))
	}
	if len(fp.Pinning) > 0 {
		fmt.Printf("[cap] Pinning:     %s\n", join(fp.Pinning))
	}
	if len(fp.Security) > 0 {
		fmt.Printf("[cap] Security:    %s\n", join(fp.Security))
	}

	queries := fp.TopSearchQueries(5)
	fmt.Printf("[cap] Searching CodeShare with %d queries...\n", len(queries))

	results, err := unpin.SearchForApp(fp)
	if err != nil {
		return err
	}
	if len(results) == 0 {
		fmt.Println("[cap] No matching scripts found on CodeShare")
		fmt.Println("[cap] Try cap's built-in unpinning: cap unpin frida --pkg " + pkg)
		return nil
	}

	limit := 10
	if len(results) < limit {
		limit = len(results)
	}
	fmt.Printf("\nTop %d matching script(s):\n\n", limit)
	for i := 0; i < limit; i++ {
		e := results[i]
		fmt.Printf("  %d. %s\n", i+1, e.Title)
		if e.Description != "" {
			fmt.Printf("     %s\n", e.Description)
		}
		fmt.Printf("     Slug: %s\n\n", e.Slug)
	}
	fmt.Println("Download: cap unpin codeshare --download <slug>")
	return nil
}

func fingerprintLocalAPK(apkPath string) (soFiles, classes []string) {
	// Use archive/zip to list SO files and scan DEX for class names
	r, err := openZip(apkPath)
	if err != nil {
		return
	}
	defer r.Close()

	for _, f := range r.File {
		if hasSuffix(f.Name, ".so") {
			soFiles = append(soFiles, f.Name)
		}
		if hasSuffix(f.Name, ".dex") {
			// Scan DEX for known class name patterns
			rc, err := f.Open()
			if err != nil {
				continue
			}
			data, err := readAll(rc)
			rc.Close()
			if err != nil {
				continue
			}
			// Look for class signatures in DEX bytes
			for _, pattern := range []string{
				"okhttp3/CertificatePinner",
				"trustkit",
				"conscrypt",
				"rootbeer",
				"fridadetect",
				"safetynet",
				"playintegrity",
				"flutter",
				"react/bridge",
				"xamarin",
				"apache/http/conn/ssl",
			} {
				if containsBytes(data, []byte(pattern)) {
					classes = append(classes, pattern)
				}
			}
		}
	}
	return
}

func fingerprintFromDevice(serial, pkg string) (soFiles, classes []string) {
	// Get native libs from device
	out, err := androidShell(serial, fmt.Sprintf("pm path %s", pkg))
	if err != nil {
		return
	}
	apkPath := ""
	for _, line := range splitLines(out) {
		if hasPrefix(line, "package:") {
			apkPath = trimPrefix(line, "package:")
			break
		}
	}
	if apkPath != "" {
		libOut, _ := androidShell(serial, fmt.Sprintf("ls %s/lib/arm64/ 2>/dev/null || ls %s/lib/arm/ 2>/dev/null", apkPath, apkPath))
		for _, line := range splitLines(libOut) {
			line = trimSpace(line)
			if hasSuffix(line, ".so") {
				soFiles = append(soFiles, line)
			}
		}
	}

	// Scan running app's loaded classes via grep on dex data
	dexOut, _ := androidShell(serial, fmt.Sprintf("cat /proc/$(pidof %s)/maps 2>/dev/null | grep dex | head -5", pkg))
	if dexOut != "" {
		classes = append(classes, "runtime-loaded")
	}

	// Check for common framework indicators
	checks := map[string]string{
		"flutter":      fmt.Sprintf("ls %s/lib/*/libflutter.so 2>/dev/null", apkPath),
		"react-native": fmt.Sprintf("ls %s/lib/*/libreactnativejni.so 2>/dev/null || ls %s/lib/*/libhermes.so 2>/dev/null", apkPath, apkPath),
		"xamarin":      fmt.Sprintf("ls %s/lib/*/libmono*.so 2>/dev/null", apkPath),
	}
	for tag, cmd := range checks {
		if out, _ := androidShell(serial, cmd); out != "" && !hasPrefix(out, "ls:") {
			classes = append(classes, tag)
		}
	}

	return
}

// Thin wrappers to keep imports minimal in this file
func androidShell(serial, cmd string) (string, error) {
	return android.AdbShell(serial, cmd)
}

func openZip(path string) (*zip.ReadCloser, error) {
	return zip.OpenReader(path)
}

func readAll(r io.Reader) ([]byte, error) {
	return io.ReadAll(r)
}

func containsBytes(data, pattern []byte) bool {
	return bytes.Contains(data, pattern)
}

func splitLines(s string) []string     { return strings.Split(s, "\n") }
func hasPrefix(s, p string) bool       { return strings.HasPrefix(strings.TrimSpace(s), p) }
func hasSuffix(s, p string) bool       { return strings.HasSuffix(strings.TrimSpace(s), p) }
func trimPrefix(s, p string) string    { return strings.TrimPrefix(strings.TrimSpace(s), p) }
func trimSpace(s string) string        { return strings.TrimSpace(s) }
func join(ss []string) string          { return strings.Join(ss, ", ") }

func newUnpinScriptCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "script",
		Short: "Print the raw Frida unpinning script to stdout",
		Long:  "Output the JavaScript source of cap's built-in SSL unpinning script, for use with frida -l or custom tooling.",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print(unpin.GetFridaScript())
		},
	}
	return cmd
}
