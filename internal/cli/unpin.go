package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/overkazaf/cap/internal/unpin"
)

func newUnpinCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "unpin",
		Short: "Bypass SSL certificate pinning on Android apps",
		Long: `Bypass SSL/TLS certificate pinning using one of three strategies:

  frida   — Runtime hooking via Frida (no APK modification, needs frida-server)
  patch   — Rewrite the APK's network_security_config.xml (no root needed)
  magisk  — System-wide Magisk module (promotes user certs to system store)

Examples:
  cap unpin frida --pkg com.example.app --spawn
  cap unpin patch --apk ./target.apk
  cap unpin magisk`,
	}

	cmd.AddCommand(
		newUnpinFridaCmd(),
		newUnpinPatchCmd(),
		newUnpinMagiskCmd(),
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
