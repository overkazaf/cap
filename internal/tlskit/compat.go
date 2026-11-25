package tlskit

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// DefaultCronetOptions returns recommended local-proxy compatibility options
// for Cronet and OkHttp applications.
func DefaultCronetOptions() CronetOptions {
	return CronetOptions{
		DisableQUIC:              true,
		ConfigureOkHttpProtocols: true,
		LogAltSvcHeaders:         true,
	}
}

// DefaultMTLSObserverOptions returns recommended diagnostic observer options
// for mutual TLS troubleshooting.
func DefaultMTLSObserverOptions() MTLSObserverOptions {
	return MTLSObserverOptions{
		ObserveKeyStore:     true,
		ObserveKeyManager:   true,
		ObserveSSLContext:   true,
		ObserveCertificates: true,
		MaxAliasesPerStore:  32,
	}
}

// GenerateFlutterProxyDebugScript generates a clean Frida JavaScript helper
// for debugging your own Flutter application through cap's local MITM proxy.
//
// It logs libflutter.so / Flutter load base addresses, prints local proxy
// routing hints, and optionally attaches to a user-specified local symbol
// offset (OffsetHex) or named BoringSSL verification symbol (VerifySymbol).
// All interpolated strings and comments are strictly sanitized against JS
// breakout.
func GenerateFlutterProxyDebugScript(opts FlutterDebugOptions) *GeneratedCompatScript {
	platform := strings.ToLower(strings.TrimSpace(opts.Platform))
	if platform != "ios" {
		platform = "android"
	}

	modName := strings.TrimSpace(opts.ModuleName)
	if modName == "" {
		if platform == "ios" {
			modName = "Flutter"
		} else {
			modName = "libflutter.so"
		}
	}

	proxyHost := strings.TrimSpace(opts.ProxyHost)
	if proxyHost == "" {
		proxyHost = "127.0.0.1"
	}
	proxyPort := opts.ProxyPort
	if proxyPort <= 0 || proxyPort > 65535 {
		proxyPort = 8080
	}

	verifySymbol := strings.TrimSpace(opts.VerifySymbol)
	if verifySymbol == "" {
		verifySymbol = "ssl_crypto_x509_session_verify_cert_chain"
	}

	var notes []string
	var warnings []string

	normalizedOffset := ""
	if rawOff := strings.TrimSpace(opts.OffsetHex); rawOff != "" {
		if cleanOff, ok := sanitizeHexOffset(rawOff); ok {
			normalizedOffset = cleanOff
		} else {
			warnings = append(warnings, fmt.Sprintf("ignored invalid OffsetHex %q (expected 1-16 hex digits with optional 0x prefix)", jsComment(rawOff)))
		}
	}

	if normalizedOffset != "" {
		notes = append(notes, fmt.Sprintf("Configured user-supplied BoringSSL offset %s relative to %s base.", normalizedOffset, modName))
	} else {
		notes = append(notes, fmt.Sprintf("Will search exported/debug symbol %q inside %s and log module base for local symbol offset calculation.", verifySymbol, modName))
	}
	notes = append(notes, fmt.Sprintf("Local cap MITM proxy hint: http://%s:%d (for Android devices, run `adb reverse tcp:%d tcp:%d`).", proxyHost, proxyPort, proxyPort, proxyPort))

	var b strings.Builder
	b.WriteString("'use strict';\n\n")
	b.WriteString("// ─── cap Local-Proxy Diagnostic Helper: Flutter BoringSSL ───────────\n")
	b.WriteString("// Authorized local debugging helper for routing your own Flutter build\n")
	b.WriteString("// through cap's local MITM proxy.\n")
	if pkg := strings.TrimSpace(opts.PackageName); pkg != "" {
		fmt.Fprintf(&b, "// Target Package: %s\n", jsComment(pkg))
	}
	fmt.Fprintf(&b, "// Platform:       %s\n", jsComment(platform))
	fmt.Fprintf(&b, "// Module:         %s\n", jsComment(modName))
	fmt.Fprintf(&b, "// Local Proxy:    %s:%d\n", jsComment(proxyHost), proxyPort)
	if normalizedOffset != "" {
		fmt.Fprintf(&b, "// OffsetHex:      %s\n", jsComment(normalizedOffset))
	} else {
		fmt.Fprintf(&b, "// Verify Symbol:  %s\n", jsComment(verifySymbol))
	}
	b.WriteString("\n")

	fmt.Fprintf(&b, "const CONFIG = {\n")
	fmt.Fprintf(&b, "    packageName: %s,\n", jsString(strings.TrimSpace(opts.PackageName)))
	fmt.Fprintf(&b, "    platform: %s,\n", jsString(platform))
	fmt.Fprintf(&b, "    moduleName: %s,\n", jsString(modName))
	fmt.Fprintf(&b, "    proxyHost: %s,\n", jsString(proxyHost))
	fmt.Fprintf(&b, "    proxyPort: %d,\n", proxyPort)
	if normalizedOffset != "" {
		fmt.Fprintf(&b, "    offsetHex: %s,\n", jsString(normalizedOffset))
	} else {
		b.WriteString("    offsetHex: null,\n")
	}
	fmt.Fprintf(&b, "    verifySymbol: %s,\n", jsString(verifySymbol))
	fmt.Fprintf(&b, "    forceAllowLocalVerify: %s\n", jsBool(opts.ForceAllowLocalVerify))
	b.WriteString("};\n\n")

	b.WriteString(`const state = {
    attached: false
};

function emit(event, payload) {
    const msg = Object.assign({
        cap_cat: 'tls_compat',
        kind: 'flutter_proxy_debug',
        event: event,
        module: CONFIG.moduleName
    }, payload || {});
    send(msg);
}

function logProxyHints() {
    const proxyURL = 'http://' + CONFIG.proxyHost + ':' + CONFIG.proxyPort;
    emit('proxy_hint', {
        proxy_url: proxyURL,
        proxy_host: CONFIG.proxyHost,
        proxy_port: CONFIG.proxyPort,
        adb_reverse_hint: 'adb reverse tcp:' + CONFIG.proxyPort + ' tcp:' + CONFIG.proxyPort,
        dart_hint: 'HttpClient.findProxy = (_) => "PROXY ' + CONFIG.proxyHost + ':' + CONFIG.proxyPort + '"'
    });
    console.log('[cap tlskit] Flutter local proxy hint: ' + proxyURL);
}

function resolveTargetAddress(mod) {
    if (CONFIG.offsetHex !== null) {
        return {
            addr: mod.base.add(ptr(CONFIG.offsetHex)),
            resolvedBy: 'offset',
            label: CONFIG.moduleName + '+' + CONFIG.offsetHex
        };
    }

    const exported = Module.findExportByName(mod.name, CONFIG.verifySymbol);
    if (exported) {
        return {
            addr: exported,
            resolvedBy: 'export',
            label: mod.name + '!' + CONFIG.verifySymbol
        };
    }

    try {
        const syms = mod.enumerateSymbols();
        for (let i = 0; i < syms.length; i++) {
            const sym = syms[i];
            if (sym.name === CONFIG.verifySymbol || sym.name.indexOf(CONFIG.verifySymbol) !== -1) {
                return {
                    addr: sym.address,
                    resolvedBy: 'symbol',
                    label: mod.name + '!' + sym.name
                };
            }
        }
    } catch (err) {
        emit('symbol_enum_error', { error: String(err) });
    }

    return null;
}

function attachFlutterModule(mod) {
    if (!mod || state.attached) {
        return;
    }
    state.attached = true;

    emit('module_loaded', {
        name: mod.name,
        base: mod.base.toString(),
        size: mod.size,
        path: mod.path || ''
    });
    console.log('[cap tlskit] ' + mod.name + ' loaded @ ' + mod.base + ' (size=' + mod.size + ')');

    const target = resolveTargetAddress(mod);
    if (!target) {
        emit('target_unresolved', {
            verify_symbol: CONFIG.verifySymbol,
            hint: 'Provide local build OffsetHex for ' + mod.name + ' to hook BoringSSL cert verification.'
        });
        console.log('[cap tlskit] Symbol not exported; supply OffsetHex for local Flutter debug build.');
        return;
    }

    const relOffset = target.addr.sub(mod.base).toString();
    try {
        Interceptor.attach(target.addr, {
            onEnter(args) {
                this.calledAt = Date.now();
                this.sslPtr = args[0] ? args[0].toString() : '0x0';
            },
            onLeave(retval) {
                const original = retval.toInt32();
                let overridden = false;
                if (CONFIG.forceAllowLocalVerify) {
                    retval.replace(ptr(0x1));
                    overridden = true;
                }
                emit('verify_hook', {
                    target: target.label,
                    resolved_by: target.resolvedBy,
                    relative_offset: relOffset,
                    ssl_ptr: this.sslPtr,
                    original_retval: original,
                    local_verify_overridden: overridden
                });
            }
        });
        emit('hook_installed', {
            target: target.label,
            resolved_by: target.resolvedBy,
            address: target.addr.toString(),
            relative_offset: relOffset,
            force_allow_local_verify: CONFIG.forceAllowLocalVerify
        });
        console.log('[cap tlskit] Hooked ' + target.label + ' @ ' + target.addr + ' (+' + relOffset + ')');
    } catch (err) {
        emit('hook_error', { target: target.label, error: String(err) });
    }
}

function watchModuleLoad() {
    const existing = Process.findModuleByName(CONFIG.moduleName);
    if (existing) {
        attachFlutterModule(existing);
        return;
    }

    const loaders = CONFIG.platform === 'ios' ? ['dlopen'] : ['dlopen', 'android_dlopen_ext'];
    loaders.forEach(function (loaderName) {
        const loaderAddr = Module.findExportByName(null, loaderName);
        if (!loaderAddr) {
            return;
        }
        Interceptor.attach(loaderAddr, {
            onEnter(args) {
                this.matched = false;
                try {
                    if (args[0] && !args[0].isNull()) {
                        const pathStr = String(args[0].readCString() || '');
                        if (pathStr.indexOf(CONFIG.moduleName) !== -1) {
                            this.matched = true;
                        }
                    }
                } catch (_) {}
            },
            onLeave() {
                if (this.matched && !state.attached) {
                    const mod = Process.findModuleByName(CONFIG.moduleName);
                    if (mod) {
                        attachFlutterModule(mod);
                    }
                }
            }
        });
    });

    emit('waiting_for_module', {
        module: CONFIG.moduleName,
        loaders: loaders
    });
}

logProxyHints();
watchModuleLoad();
`)

	return &GeneratedCompatScript{
		ID:          "tlskit:flutter-proxy-debug",
		Name:        "Flutter Local Proxy Diagnostic Helper",
		Kind:        "flutter_proxy_debug",
		Description: "Logs Flutter engine load base, emits local cap proxy hints, and hooks a configured local BoringSSL verify offset/symbol.",
		PackageName: strings.TrimSpace(opts.PackageName),
		Code:        b.String(),
		Notes:       notes,
		Warnings:    warnings,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

// GenerateCronetHTTP2Script generates a clean Frida JavaScript helper for
// local-proxy compatibility with Cronet and OkHttp applications.
//
// It disables QUIC in CronetEngine$Builder so HTTP/3 traffic falls back to
// HTTP/2 over TCP through cap's MITM proxy, configures OkHttp HTTP/2 + HTTP/1.1
// protocol negotiation, and logs Alt-Svc headers via send().
func GenerateCronetHTTP2Script(opts CronetOptions) *GeneratedCompatScript {
	if !opts.DisableQUIC && !opts.ConfigureOkHttpProtocols && !opts.LogAltSvcHeaders {
		defaults := DefaultCronetOptions()
		opts.DisableQUIC = defaults.DisableQUIC
		opts.ConfigureOkHttpProtocols = defaults.ConfigureOkHttpProtocols
		opts.LogAltSvcHeaders = defaults.LogAltSvcHeaders
	}

	pkg := strings.TrimSpace(opts.PackageName)
	proxyHint := strings.TrimSpace(opts.ProxyHint)

	var notes []string
	if opts.DisableQUIC {
		notes = append(notes, "Hooks CronetEngine$Builder.enableQuic(false) so HTTP/3 falls back cleanly to HTTP/2 over cap's TCP MITM proxy.")
	}
	if opts.ConfigureOkHttpProtocols {
		notes = append(notes, "Hooks OkHttpClient$Builder.protocols(...) to ensure HTTP_2 and HTTP_1_1 remain enabled for local proxy inspection.")
	}
	if opts.LogAltSvcHeaders {
		notes = append(notes, "Logs Alt-Svc response headers observed across OkHttp, Cronet, and HttpURLConnection via send().")
	}

	var b strings.Builder
	b.WriteString("'use strict';\n\n")
	b.WriteString("// ─── cap Local-Proxy Compatibility: Cronet / OkHttp HTTP/2 ─────────\n")
	b.WriteString("// Forces QUIC/HTTP3 fallback to HTTP/2 over TCP for local MITM proxy\n")
	b.WriteString("// diagnostics and logs Alt-Svc upgrade advertisements.\n")
	if pkg != "" {
		fmt.Fprintf(&b, "// Target Package: %s\n", jsComment(pkg))
	}
	if proxyHint != "" {
		fmt.Fprintf(&b, "// Local Proxy:    %s\n", jsComment(proxyHint))
	}
	b.WriteString("\n")

	fmt.Fprintf(&b, "const CONFIG = {\n")
	fmt.Fprintf(&b, "    packageName: %s,\n", jsString(pkg))
	fmt.Fprintf(&b, "    proxyHint: %s,\n", jsString(proxyHint))
	fmt.Fprintf(&b, "    disableQuic: %s,\n", jsBool(opts.DisableQUIC))
	fmt.Fprintf(&b, "    configureOkHttpProtocols: %s,\n", jsBool(opts.ConfigureOkHttpProtocols))
	fmt.Fprintf(&b, "    logAltSvcHeaders: %s\n", jsBool(opts.LogAltSvcHeaders))
	b.WriteString("};\n\n")

	b.WriteString(`function emit(event, payload) {
    send(Object.assign({
        cap_cat: 'tls_compat',
        kind: 'cronet_http2',
        event: event
    }, payload || {}));
}

function hookCronetBuilder(className) {
    try {
        const Builder = Java.use(className);
        if (Builder.enableQuic) {
            Builder.enableQuic.overload('boolean').implementation = function (requested) {
                emit('cronet_enable_quic', {
                    class_name: className,
                    requested: Boolean(requested),
                    applied: false
                });
                return this.enableQuic(false);
            };
        }
        if (Builder.enableHttp2) {
            Builder.enableHttp2.overload('boolean').implementation = function (requested) {
                emit('cronet_enable_http2', {
                    class_name: className,
                    requested: Boolean(requested),
                    applied: true
                });
                return this.enableHttp2(true);
            };
        }
        if (Builder.addQuicHint) {
            Builder.addQuicHint.overload('java.lang.String', 'int', 'int').implementation = function (host, port, altPort) {
                emit('cronet_quic_hint_skipped', {
                    class_name: className,
                    host: String(host || ''),
                    port: port,
                    alt_port: altPort
                });
                return this;
            };
        }
        emit('hook_installed', { target: className });
        console.log('[cap tlskit] Cronet QUIC->HTTP/2 fallback active on ' + className);
    } catch (_) {}
}

function hookOkHttpProtocols() {
    try {
        const Builder = Java.use('okhttp3.OkHttpClient$Builder');
        const Protocol = Java.use('okhttp3.Protocol');
        const ArrayList = Java.use('java.util.ArrayList');

        const buildCompatProtocols = function () {
            const list = ArrayList.$new();
            try {
                list.add(Protocol.HTTP_2.value);
            } catch (_) {}
            try {
                list.add(Protocol.HTTP_1_1.value);
            } catch (_) {}
            return list;
        };

        Builder.protocols.overload('java.util.List').implementation = function (protocols) {
            const incoming = [];
            try {
                if (protocols) {
                    const size = protocols.size();
                    for (let i = 0; i < size; i++) {
                        incoming.push(String(protocols.get(i)));
                    }
                }
            } catch (_) {}

            const compat = buildCompatProtocols();
            emit('okhttp_protocols_configured', {
                requested: incoming,
                applied: ['h2', 'http/1.1']
            });
            return this.protocols(compat);
        };

        Builder.build.overload().implementation = function () {
            try {
                this.protocols(buildCompatProtocols());
            } catch (_) {}
            return this.build();
        };

        emit('hook_installed', { target: 'okhttp3.OkHttpClient$Builder' });
        console.log('[cap tlskit] OkHttp HTTP/2 + HTTP/1.1 protocol compatibility active');
    } catch (_) {}
}

function hookAltSvcLogging() {
    // 1. OkHttp Response.header / Headers.get
    try {
        const Headers = Java.use('okhttp3.Headers');
        Headers.get.overload('java.lang.String').implementation = function (name) {
            const val = this.get(name);
            if (name && String(name).toLowerCase() === 'alt-svc' && val !== null) {
                emit('alt_svc', { source: 'okhttp3.Headers', value: String(val) });
            }
            return val;
        };
    } catch (_) {}

    try {
        const Response = Java.use('okhttp3.Response');
        Response.headers.overload().implementation = function () {
            const hdrs = this.headers();
            try {
                if (hdrs) {
                    const altSvc = hdrs.get('Alt-Svc');
                    if (altSvc !== null) {
                        const reqUrl = this.request() ? String(this.request().url()) : '';
                        emit('alt_svc', { source: 'okhttp3.Response', url: reqUrl, value: String(altSvc) });
                    }
                }
            } catch (_) {}
            return hdrs;
        };
    } catch (_) {}

    // 2. Cronet UrlResponseInfo headers
    try {
        const UrlResponseInfo = Java.use('org.chromium.net.UrlResponseInfo');
        UrlResponseInfo.getAllHeadersAsList.overload().implementation = function () {
            const list = this.getAllHeadersAsList();
            try {
                if (list) {
                    const url = String(this.getUrl() || '');
                    const size = list.size();
                    for (let i = 0; i < size; i++) {
                        const entry = list.get(i);
                        const k = String(entry.getKey() || '');
                        if (k.toLowerCase() === 'alt-svc') {
                            emit('alt_svc', { source: 'cronet.UrlResponseInfo', url: url, value: String(entry.getValue() || '') });
                        }
                    }
                }
            } catch (_) {}
            return list;
        };
    } catch (_) {}

    // 3. Standard HttpURLConnection fallback
    try {
        const URLConn = Java.use('java.net.URLConnection');
        URLConn.getHeaderField.overload('java.lang.String').implementation = function (name) {
            const val = this.getHeaderField(name);
            if (name && String(name).toLowerCase() === 'alt-svc' && val !== null) {
                emit('alt_svc', { source: 'java.net.URLConnection', value: String(val) });
            }
            return val;
        };
    } catch (_) {}
}

Java.perform(function () {
    emit('started', {
        package_name: CONFIG.packageName,
        proxy_hint: CONFIG.proxyHint,
        disable_quic: CONFIG.disableQuic,
        configure_okhttp_protocols: CONFIG.configureOkHttpProtocols,
        log_alt_svc_headers: CONFIG.logAltSvcHeaders
    });

    if (CONFIG.disableQuic) {
        hookCronetBuilder('org.chromium.net.CronetEngine$Builder');
        hookCronetBuilder('org.chromium.net.ExperimentalCronetEngine$Builder');
    }
    if (CONFIG.configureOkHttpProtocols) {
        hookOkHttpProtocols();
    }
    if (CONFIG.logAltSvcHeaders) {
        hookAltSvcLogging();
    }
});
`)

	return &GeneratedCompatScript{
		ID:          "tlskit:cronet-http2-compat",
		Name:        "Cronet & OkHttp HTTP/2 Proxy Compatibility",
		Kind:        "cronet_http2",
		Description: "Disables QUIC in Cronet so HTTP/3 falls back to HTTP/2 over cap's local MITM proxy, configures OkHttp HTTP/2+HTTP/1.1 protocols, and logs Alt-Svc headers.",
		PackageName: pkg,
		Code:        b.String(),
		Notes:       notes,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

// GenerateMTLSObserverScript generates a strictly diagnostic Frida JavaScript
// observer that logs KeyStore types and alias names, KeyManagerFactory
// algorithms, SSLContext protocols, and peer/client X.509 certificate metadata
// (Subject, Issuer, Serial) via send().
//
// Security invariant: the generated observer NEVER reads, logs, or exports raw
// private keys or plaintext passwords.
func GenerateMTLSObserverScript(opts MTLSObserverOptions) *GeneratedCompatScript {
	if !opts.ObserveKeyStore && !opts.ObserveKeyManager && !opts.ObserveSSLContext && !opts.ObserveCertificates {
		defaults := DefaultMTLSObserverOptions()
		opts.ObserveKeyStore = defaults.ObserveKeyStore
		opts.ObserveKeyManager = defaults.ObserveKeyManager
		opts.ObserveSSLContext = defaults.ObserveSSLContext
		opts.ObserveCertificates = defaults.ObserveCertificates
	}
	maxAliases := opts.MaxAliasesPerStore
	if maxAliases <= 0 {
		maxAliases = 32
	}
	if maxAliases > 256 {
		maxAliases = 256
	}

	pkg := strings.TrimSpace(opts.PackageName)
	notes := []string{
		"Strictly read-only diagnostic observer: does not modify TLS verification or extract private keys/passwords.",
		"Emits KeyStore type/alias metadata, KeyManagerFactory algorithms, SSLContext protocols, and public X.509 Subject/Issuer/Serial via send().",
	}

	var b strings.Builder
	b.WriteString("'use strict';\n\n")
	b.WriteString("// ─── cap Strictly Diagnostic mTLS Observer ──────────────────────────\n")
	b.WriteString("// Read-only observer for KeyStore metadata, KeyManagerFactory,\n")
	b.WriteString("// SSLContext protocols, and public X.509 certificate metadata.\n")
	b.WriteString("// NEVER reads or logs raw private keys or plaintext passwords.\n")
	if pkg != "" {
		fmt.Fprintf(&b, "// Target Package: %s\n", jsComment(pkg))
	}
	b.WriteString("\n")

	fmt.Fprintf(&b, "const CONFIG = {\n")
	fmt.Fprintf(&b, "    packageName: %s,\n", jsString(pkg))
	fmt.Fprintf(&b, "    observeKeyStore: %s,\n", jsBool(opts.ObserveKeyStore))
	fmt.Fprintf(&b, "    observeKeyManager: %s,\n", jsBool(opts.ObserveKeyManager))
	fmt.Fprintf(&b, "    observeSSLContext: %s,\n", jsBool(opts.ObserveSSLContext))
	fmt.Fprintf(&b, "    observeCertificates: %s,\n", jsBool(opts.ObserveCertificates))
	fmt.Fprintf(&b, "    maxAliasesPerStore: %d\n", maxAliases)
	b.WriteString("};\n\n")

	b.WriteString(`function emit(event, payload) {
    send(Object.assign({
        cap_cat: 'mtls_observer',
        kind: 'mtls_observer',
        event: event
    }, payload || {}));
}

function summarizeCert(cert) {
    if (!cert) {
        return null;
    }
    try {
        const X509 = Java.use('java.security.cert.X509Certificate');
        const x509 = Java.cast(cert, X509);
        const subject = x509.getSubjectX500Principal ? String(x509.getSubjectX500Principal().getName()) : String(x509.getSubjectDN());
        const issuer = x509.getIssuerX500Principal ? String(x509.getIssuerX500Principal().getName()) : String(x509.getIssuerDN());
        const serial = x509.getSerialNumber ? String(x509.getSerialNumber().toString(16)).toUpperCase() : '';
        return {
            subject: subject,
            issuer: issuer,
            serial: serial,
            not_before: x509.getNotBefore ? String(x509.getNotBefore()) : '',
            not_after: x509.getNotAfter ? String(x509.getNotAfter()) : '',
            sig_alg: x509.getSigAlgName ? String(x509.getSigAlgName()) : ''
        };
    } catch (_) {
        return { type: String(cert.getType ? cert.getType() : 'unknown') };
    }
}

function summarizeCertArray(certs) {
    const out = [];
    if (!certs) {
        return out;
    }
    try {
        for (let i = 0; i < certs.length; i++) {
            const info = summarizeCert(certs[i]);
            if (info) {
                out.push(info);
            }
        }
    } catch (_) {}
    return out;
}

function observeKeyStoreAPI() {
    try {
        const KeyStore = Java.use('java.security.KeyStore');

        KeyStore.getInstance.overload('java.lang.String').implementation = function (storeType) {
            const ks = this.getInstance(storeType);
            emit('keystore_instance', { keystore_type: String(storeType || '') });
            return ks;
        };

        KeyStore.getInstance.overload('java.lang.String', 'java.lang.String').implementation = function (storeType, provider) {
            const ks = this.getInstance(storeType, provider);
            emit('keystore_instance', {
                keystore_type: String(storeType || ''),
                provider: String(provider || '')
            });
            return ks;
        };

        KeyStore.load.overload('java.io.InputStream', '[C').implementation = function (stream, secretChars) {
            this.load(stream, secretChars);
            const aliases = [];
            const certSummaries = [];
            try {
                const en = this.aliases();
                while (en && en.hasMoreElements() && aliases.length < CONFIG.maxAliasesPerStore) {
                    const alias = String(en.nextElement());
                    let entryKind = 'other';
                    try {
                        if (this.isKeyEntry(alias)) {
                            entryKind = 'key_entry';
                        } else if (this.isCertificateEntry(alias)) {
                            entryKind = 'cert_entry';
                        }
                    } catch (_) {}
                    aliases.push({ alias: alias, kind: entryKind });
                    if (CONFIG.observeCertificates) {
                        try {
                            const pubCert = this.getCertificate(alias);
                            if (pubCert) {
                                certSummaries.push(Object.assign({ alias: alias }, summarizeCert(pubCert)));
                            }
                        } catch (_) {}
                    }
                }
            } catch (_) {}

            emit('keystore_load', {
                keystore_type: String(this.getType()),
                has_stream: stream !== null,
                credential_present: secretChars !== null,
                alias_count: aliases.length,
                aliases: aliases,
                certificates: certSummaries
            });
        };

        emit('hook_installed', { target: 'java.security.KeyStore' });
    } catch (_) {}
}

function observeKeyManagerFactoryAPI() {
    try {
        const KMF = Java.use('javax.net.ssl.KeyManagerFactory');

        KMF.getInstance.overload('java.lang.String').implementation = function (algorithm) {
            const kmf = this.getInstance(algorithm);
            emit('key_manager_factory_instance', { algorithm: String(algorithm || '') });
            return kmf;
        };

        KMF.init.overload('java.security.KeyStore', '[C').implementation = function (ks, secretChars) {
            this.init(ks, secretChars);
            emit('key_manager_factory_init', {
                algorithm: String(this.getAlgorithm()),
                keystore_type: ks ? String(ks.getType()) : '',
                credential_present: secretChars !== null
            });
        };

        emit('hook_installed', { target: 'javax.net.ssl.KeyManagerFactory' });
    } catch (_) {}
}

function observeSSLContextAPI() {
    try {
        const SSLContext = Java.use('javax.net.ssl.SSLContext');

        SSLContext.getInstance.overload('java.lang.String').implementation = function (protocol) {
            const ctx = this.getInstance(protocol);
            emit('ssl_context_instance', { protocol: String(protocol || '') });
            return ctx;
        };

        SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;',
            '[Ljavax.net.ssl.TrustManager;',
            'java.security.SecureRandom'
        ).implementation = function (kms, tms, sr) {
            const kmClasses = [];
            if (kms) {
                for (let i = 0; i < kms.length; i++) {
                    if (kms[i]) {
                        kmClasses.push(String(kms[i].$className || 'KeyManager'));
                    }
                }
            }
            emit('ssl_context_init', {
                protocol: String(this.getProtocol()),
                key_manager_count: kms ? kms.length : 0,
                key_manager_classes: kmClasses,
                trust_manager_count: tms ? tms.length : 0
            });
            return this.init(kms, tms, sr);
        };

        emit('hook_installed', { target: 'javax.net.ssl.SSLContext' });
    } catch (_) {}
}

function observeSessionCertificatesAPI() {
    try {
        const SSLSocket = Java.use('javax.net.ssl.SSLSocket');
        SSLSocket.startHandshake.overload().implementation = function () {
            this.startHandshake();
            try {
                const session = this.getSession();
                if (session) {
                    let peerCerts = [];
                    let localCerts = [];
                    try {
                        peerCerts = summarizeCertArray(session.getPeerCertificates());
                    } catch (_) {}
                    try {
                        localCerts = summarizeCertArray(session.getLocalCertificates());
                    } catch (_) {}
                    emit('tls_handshake_certs', {
                        peer_host: String(session.getPeerHost() || ''),
                        peer_port: session.getPeerPort(),
                        protocol: String(session.getProtocol() || ''),
                        cipher_suite: String(session.getCipherSuite() || ''),
                        peer_certificates: peerCerts,
                        client_certificates: localCerts
                    });
                }
            } catch (_) {}
        };
        emit('hook_installed', { target: 'javax.net.ssl.SSLSocket.startHandshake' });
    } catch (_) {}

    try {
        const HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.getLocalCertificates.overload().implementation = function () {
            const certs = this.getLocalCertificates();
            emit('https_client_certs', {
                url: String(this.getURL() || ''),
                client_certificates: summarizeCertArray(certs)
            });
            return certs;
        };
        HttpsURLConnection.getServerCertificates.overload().implementation = function () {
            const certs = this.getServerCertificates();
            emit('https_peer_certs', {
                url: String(this.getURL() || ''),
                peer_certificates: summarizeCertArray(certs)
            });
            return certs;
        };
        emit('hook_installed', { target: 'javax.net.ssl.HttpsURLConnection' });
    } catch (_) {}
}

Java.perform(function () {
    emit('started', {
        package_name: CONFIG.packageName,
        mode: 'diagnostic_readonly'
    });

    if (CONFIG.observeKeyStore) {
        observeKeyStoreAPI();
    }
    if (CONFIG.observeKeyManager) {
        observeKeyManagerFactoryAPI();
    }
    if (CONFIG.observeSSLContext) {
        observeSSLContextAPI();
    }
    if (CONFIG.observeCertificates) {
        observeSessionCertificatesAPI();
    }
});
`)

	return &GeneratedCompatScript{
		ID:          "tlskit:mtls-observer",
		Name:        "mTLS Diagnostic Observer (Read-Only)",
		Kind:        "mtls_observer",
		Description: "Strictly diagnostic observer for KeyStore types/aliases, KeyManagerFactory algorithms, SSLContext protocols, and peer/client X.509 certificate metadata.",
		PackageName: pkg,
		Code:        b.String(),
		Notes:       notes,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

// jsString encodes s as a safe double-quoted JavaScript string literal,
// preventing quote, newline, U+2028/U+2029, and </script> breakout.
func jsString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	out := string(b)
	out = strings.ReplaceAll(out, "\u2028", `\u2028`)
	out = strings.ReplaceAll(out, "\u2029", `\u2029`)
	out = strings.ReplaceAll(out, "</", `<\/`)
	return out
}

// jsComment sanitizes s for safe single-line JavaScript comments, preventing
// newline / U+2028 / U+2029 / block-comment breakout.
func jsComment(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\r' || r == '\n' || r == '\u2028' || r == '\u2029' || r == '\t':
			b.WriteByte(' ')
		case r < 0x20 || r == 0x7f:
			// drop non-printable ASCII control bytes
		default:
			b.WriteRune(r)
		}
	}
	cleaned := strings.TrimSpace(b.String())
	cleaned = strings.ReplaceAll(cleaned, "*/", "* /")
	cleaned = strings.ReplaceAll(cleaned, "/*", "/ *")
	cleaned = strings.ReplaceAll(cleaned, "</", "< /")
	if runes := []rune(cleaned); len(runes) > 240 {
		cleaned = string(runes[:240])
	}
	return cleaned
}

func jsBool(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

// sanitizeHexOffset validates a hexadecimal offset string (optional 0x prefix
// followed by 1..16 hex digits) and normalizes it to "0x<lowercase>".
func sanitizeHexOffset(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	if len(s) == 0 || len(s) > 16 {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return "", false
		}
	}
	return "0x" + strings.ToLower(s), true
}
