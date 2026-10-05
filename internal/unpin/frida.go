package unpin

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// FridaOptions configures Frida-based unpinning.
type FridaOptions struct {
	Serial  string // ADB device serial (empty = auto)
	Package string // target app package name
	Spawn   bool   // spawn the app (vs. attach to running process)
	ScriptDir string // directory to write the script to (empty = temp)
}

// fridaScript is a comprehensive SSL-pinning bypass that hooks the most
// common pinning implementations found in Android apps. It covers:
//
//   - TrustManagerImpl (Android platform-level pinning)
//   - X509TrustManager (custom implementations)
//   - OkHttp3 CertificatePinner
//   - OkHttp3 CertificatePinner$Builder (prevent pin addition)
//   - SSLContext.init (force permissive TrustManager)
//   - WebViewClient.onReceivedSslError (proceed on SSL errors)
//   - Conscrypt/BoringSSL (modern Android TLS)
//   - Apache HTTP client (legacy apps)
//   - Flutter/Dart BoringSSL (ssl_crypto_x509_session_verify_cert_chain)
//   - React Native OkHttp pinning
//   - TrustKit (iOS-port for Android)
//   - Appcelerator Titanium
//   - PhoneGap/Cordova sslCertificateChecker
const fridaScript = `'use strict';

// ─── cap SSL Unpinning Script ───────────────────────────────────────
// Comprehensive bypass for common Android SSL-pinning implementations.

Java.perform(function () {
    var X509Certificate = Java.use('java.security.cert.X509Certificate');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');

    // ── 1. TrustManagerImpl (platform pinning, Android 7+) ──────────
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function () {
            //console.log('[cap] TrustManagerImpl.verifyChain bypassed');
            return arguments[0];
        };
        console.log('[cap unpin] ✓ TrustManagerImpl.verifyChain');
    } catch (e) {
        //console.log('[cap unpin] TrustManagerImpl not found: ' + e);
    }

    // ── 2. Custom X509TrustManager implementations ──────────────────
    try {
        var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var TrustManagers = Java.use('javax.net.ssl.TrustManagerFactory');

        var EmptyTrustManager = Java.registerClass({
            name: 'cap.EmptyTrustManager',
            implements: [TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () {
                    return [];
                },
            },
        });
        console.log('[cap unpin] ✓ EmptyTrustManager registered');
    } catch (e) {
        //console.log('[cap unpin] EmptyTrustManager: ' + e);
    }

    // ── 3. SSLContext.init — force permissive TrustManager ──────────
    try {
        SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;',
            '[Ljavax.net.ssl.TrustManager;',
            'java.security.SecureRandom'
        ).implementation = function (km, tm, sr) {
            //console.log('[cap] SSLContext.init intercepted');
            var EmptyTM = Java.use('cap.EmptyTrustManager');
            this.init(km, [EmptyTM.$new()], sr);
        };
        console.log('[cap unpin] ✓ SSLContext.init');
    } catch (e) {
        //console.log('[cap unpin] SSLContext.init: ' + e);
    }

    // ── 4. OkHttp3 CertificatePinner.check ──────────────────────────
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function () {
            //console.log('[cap] OkHttp3 CertificatePinner.check bypassed for: ' + arguments[0]);
        };
        console.log('[cap unpin] ✓ okhttp3.CertificatePinner.check');
    } catch (e) {
        //console.log('[cap unpin] OkHttp3 CertificatePinner: ' + e);
    }

    // Some apps use the older check(String, Certificate[]) overload
    try {
        var CertificatePinner2 = Java.use('okhttp3.CertificatePinner');
        CertificatePinner2.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function () {
            //console.log('[cap] OkHttp3 CertificatePinner.check (cert[]) bypassed');
        };
        console.log('[cap unpin] ✓ okhttp3.CertificatePinner.check (cert[])');
    } catch (e) {}

    // ── 5. OkHttp3 CertificatePinner$Builder.add ────────────────────
    // Prevent pins from being added in the first place
    try {
        var Builder = Java.use('okhttp3.CertificatePinner$Builder');
        Builder.add.implementation = function (hostname) {
            //console.log('[cap] CertificatePinner.Builder.add blocked for: ' + hostname);
            return this;
        };
        console.log('[cap unpin] ✓ okhttp3.CertificatePinner$Builder.add');
    } catch (e) {}

    // ── 6. WebViewClient.onReceivedSslError ─────────────────────────
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
            //console.log('[cap] WebViewClient SSL error overridden');
            handler.proceed();
        };
        console.log('[cap unpin] ✓ WebViewClient.onReceivedSslError');
    } catch (e) {}

    // ── 7. Conscrypt / OpenSSLSocketImpl ─────────────────────────────
    try {
        var OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
        OpenSSLSocketImpl.verifyCertificateChain.implementation = function () {
            //console.log('[cap] Conscrypt verifyCertificateChain bypassed');
        };
        console.log('[cap unpin] ✓ Conscrypt OpenSSLSocketImpl');
    } catch (e) {}

    // Conscrypt platform variant (Android 14+)
    try {
        var ConscryptPlatform = Java.use('com.android.org.conscrypt.Platform');
        ConscryptPlatform.checkServerTrusted.overload(
            'javax.net.ssl.X509TrustManager',
            '[Ljava.security.cert.X509Certificate;',
            'java.lang.String',
            'com.android.org.conscrypt.AbstractConscryptSocket'
        ).implementation = function (tm, chain, authType, socket) {
            //console.log('[cap] Conscrypt Platform.checkServerTrusted bypassed');
        };
        console.log('[cap unpin] ✓ Conscrypt Platform.checkServerTrusted');
    } catch (e) {}

    // ── 8. Apache HTTP client (legacy apps) ─────────────────────────
    try {
        var AbstractVerifier = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
        AbstractVerifier.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;', 'boolean').implementation = function () {
            //console.log('[cap] Apache AbstractVerifier bypassed');
        };
        console.log('[cap unpin] ✓ Apache HTTP AbstractVerifier');
    } catch (e) {}

    // ── 9. HostnameVerifier ─────────────────────────────────────────
    try {
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
        var SSLSession = Java.use('javax.net.ssl.SSLSession');

        Java.enumerateClassLoaders({
            onMatch: function (loader) {
                try {
                    Java.classFactory.loader = loader;
                    var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
                    HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (verifier) {
                        //console.log('[cap] setDefaultHostnameVerifier intercepted');
                    };
                } catch (e) {}
            },
            onComplete: function () {},
        });
        console.log('[cap unpin] ✓ HostnameVerifier');
    } catch (e) {}

    // ── 10. TrustKit (popular pinning library) ──────────────────────
    try {
        var TrustKit = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
        TrustKit.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function () {
            return true;
        };
        TrustKit.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function () {
            return true;
        };
        console.log('[cap unpin] ✓ TrustKit OkHostnameVerifier');
    } catch (e) {}

    // ── 11. Appcelerator Titanium ───────────────────────────────────
    try {
        var PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');
        PinningTrustManager.checkServerTrusted.implementation = function () {};
        console.log('[cap unpin] ✓ Appcelerator PinningTrustManager');
    } catch (e) {}

    // ── 12. PhoneGap / Cordova sslCertificateChecker ────────────────
    try {
        var Checker = Java.use('nl.xservices.plugins.SslCertificateChecker');
        Checker.execute.implementation = function (action, args, cb) {
            cb.success('CONNECTION_SECURE');
            return true;
        };
        console.log('[cap unpin] ✓ Cordova SslCertificateChecker');
    } catch (e) {}

    // ── 13. Network Security Config (programmatic pinning) ──────────
    try {
        var NetworkSecurityConfig = Java.use('android.security.net.config.NetworkSecurityConfig');
        NetworkSecurityConfig.isCleartextTrafficPermitted.implementation = function () {
            return true;
        };
        console.log('[cap unpin] ✓ NetworkSecurityConfig.isCleartextTrafficPermitted');
    } catch (e) {}

    try {
        var PinSet = Java.use('android.security.net.config.PinSet');
        PinSet.isPinningEnforced.implementation = function () {
            return false;
        };
        console.log('[cap unpin] ✓ PinSet.isPinningEnforced');
    } catch (e) {}

    console.log('[cap unpin] SSL unpinning hooks loaded');
});

// ── 14. Flutter / Dart BoringSSL (native layer) ─────────────────────
// Flutter uses BoringSSL directly via dart:io, bypassing Java TLS.
// We hook the native ssl_crypto_x509_session_verify_cert_chain.
try {
    var flutter_module = Process.findModuleByName('libflutter.so');
    if (flutter_module) {
        var found = false;
        // Pattern: ssl_crypto_x509_session_verify_cert_chain return value patch
        var symbols = flutter_module.enumerateExports();
        for (var i = 0; i < symbols.length; i++) {
            if (symbols[i].name.indexOf('ssl_crypto_x509_session_verify_cert_chain') >= 0) {
                Interceptor.replace(symbols[i].address, new NativeCallback(function () {
                    return 1;
                }, 'int', ['pointer', 'pointer']));
                found = true;
                break;
            }
        }
        // If symbol not exported, try pattern scan for the function prologue
        if (!found) {
            var ranges = flutter_module.enumerateRanges('r-x');
            for (var j = 0; j < ranges.length; j++) {
                // x509_session_verify_cert_chain typically starts with a
                // specific prologue and returns 0 (failure) or 1 (success).
                // Hook the verify callback to always return 1.
                var results = Memory.scanSync(ranges[j].base, ranges[j].size,
                    '55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 ec');
                // This is x86_64; ARM64 would need a different pattern.
                // We keep it best-effort.
            }
        }
        if (found) {
            console.log('[cap unpin] ✓ Flutter BoringSSL');
        }
    }
} catch (e) {
    //console.log('[cap unpin] Flutter BoringSSL: ' + e);
}
`

// FridaUnpin deploys a Frida SSL-unpinning script to the target app.
// It writes the script to disk and returns the frida command to run,
// or spawns frida directly if the frida binary is available.
func FridaUnpin(opts FridaOptions) (*Result, error) {
	if opts.Package == "" {
		return nil, fmt.Errorf("package name is required for Frida unpinning")
	}

	if !which("frida") {
		return &Result{
			Method:  MethodFrida,
			Success: false,
			Message: "frida not found in PATH — install with: pip install frida-tools",
		}, nil
	}

	dir := opts.ScriptDir
	if dir == "" {
		dir = os.TempDir()
	}
	scriptPath := filepath.Join(dir, "cap-unpin.js")
	if err := os.WriteFile(scriptPath, []byte(fridaScript), 0644); err != nil {
		return nil, fmt.Errorf("write frida script: %w", err)
	}

	args := []string{"-l", scriptPath}
	if opts.Serial != "" {
		args = append(args, "-D", opts.Serial)
	}
	if opts.Spawn {
		args = append(args, "-f", opts.Package)
	} else {
		args = append(args, opts.Package)
	}

	cmd := fmt.Sprintf("frida %s", strings.Join(args, " "))

	return &Result{
		Method:  MethodFrida,
		Success: true,
		Message: fmt.Sprintf("Frida script written to %s\nRun: %s", scriptPath, cmd),
		Output:  scriptPath,
	}, nil
}

// FridaSpawn writes the script and spawns frida, attaching to the target
// app. It blocks until frida exits.
func FridaSpawn(opts FridaOptions) (*Result, error) {
	if opts.Package == "" {
		return nil, fmt.Errorf("package name is required")
	}
	if !which("frida") {
		return &Result{
			Method:  MethodFrida,
			Success: false,
			Message: "frida not found in PATH — install with: pip install frida-tools",
		}, nil
	}

	dir := opts.ScriptDir
	if dir == "" {
		dir = os.TempDir()
	}
	scriptPath := filepath.Join(dir, "cap-unpin.js")
	if err := os.WriteFile(scriptPath, []byte(fridaScript), 0644); err != nil {
		return nil, fmt.Errorf("write frida script: %w", err)
	}

	fridaArgs := []string{"-l", scriptPath}
	if opts.Serial != "" {
		fridaArgs = append(fridaArgs, "-D", opts.Serial)
	}
	if opts.Spawn {
		fridaArgs = append(fridaArgs, "-f", opts.Package, "--no-pause")
	} else {
		fridaArgs = append(fridaArgs, opts.Package)
	}

	fmt.Printf("Starting frida with unpinning for %s...\n", opts.Package)
	c := newFridaCmd(fridaArgs...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin

	if err := c.Run(); err != nil {
		return &Result{
			Method:  MethodFrida,
			Success: false,
			Message: fmt.Sprintf("frida exited: %v", err),
			Output:  scriptPath,
		}, nil
	}

	return &Result{
		Method:  MethodFrida,
		Success: true,
		Message: "frida session ended",
		Output:  scriptPath,
	}, nil
}

func newFridaCmd(args ...string) *exec.Cmd {
	return exec.Command("frida", args...)
}

// GetFridaScript returns the raw JS source for the unpinning script,
// useful for callers that want to embed or modify it.
func GetFridaScript() string {
	return fridaScript
}
