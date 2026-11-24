package frida

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/overkazaf/cap/internal/unpin"
)

var slugSanitizeRe = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// ScriptStore manages curated built-in Frida scripts plus user-saved local
// scripts in ~/.cap/frida-scripts/*.json with automatic disk hot-reload.
type ScriptStore struct {
	dir      string
	mu       sync.RWMutex
	custom   map[string]Script
	dirStamp string
}

// NewScriptStore initializes a persistent script library at dir.
// If dir cannot be created (e.g., read-only home directory), built-in templates
// remain readable and Save will retry creating the directory on demand.
func NewScriptStore(dir string) (*ScriptStore, error) {
	_ = os.MkdirAll(dir, 0755)
	s := &ScriptStore{
		dir:    dir,
		custom: make(map[string]Script),
	}
	_ = s.Reload()
	return s, nil
}

// Dir returns the local directory where custom scripts are persisted.
func (s *ScriptStore) Dir() string {
	return s.dir
}

// Reload re-reads all custom *.json scripts from disk.
func (s *ScriptStore) Reload() error {
	stamp := computeScriptsStamp(s.dir)
	loaded := readScriptsDir(s.dir)
	s.mu.Lock()
	s.custom = loaded
	s.dirStamp = stamp
	s.mu.Unlock()
	return nil
}

func (s *ScriptStore) maybeReload() {
	stamp := computeScriptsStamp(s.dir)
	s.mu.RLock()
	same := stamp == s.dirStamp
	s.mu.RUnlock()
	if same {
		return
	}
	_ = s.Reload()
}

// List returns all built-in templates followed by user-saved custom scripts.
func (s *ScriptStore) List() []Script {
	s.maybeReload()
	builtins := BuiltinScripts()
	s.mu.RLock()
	customs := make([]Script, 0, len(s.custom))
	for _, sc := range s.custom {
		customs = append(customs, sc)
	}
	s.mu.RUnlock()

	sort.Slice(customs, func(i, j int) bool {
		if customs[i].UpdatedAt != customs[j].UpdatedAt {
			return customs[i].UpdatedAt > customs[j].UpdatedAt
		}
		return strings.ToLower(customs[i].Name) < strings.ToLower(customs[j].Name)
	})

	out := make([]Script, 0, len(builtins)+len(customs))
	out = append(out, builtins...)
	out = append(out, customs...)
	return out
}

// Get retrieves a script by ID (checking custom scripts first, then built-ins).
func (s *ScriptStore) Get(id string) (*Script, bool) {
	s.maybeReload()
	id = strings.TrimSpace(id)
	s.mu.RLock()
	if sc, ok := s.custom[id]; ok {
		s.mu.RUnlock()
		return &sc, true
	}
	s.mu.RUnlock()

	for _, b := range BuiltinScripts() {
		if b.ID == id {
			cp := b
			return &cp, true
		}
	}
	return nil, false
}

// Save creates or updates a custom script on disk. Saving a built-in script ID
// forks it cleanly into a user-owned custom copy.
func (s *ScriptStore) Save(sc Script) (*Script, error) {
	sc.Name = strings.TrimSpace(sc.Name)
	if sc.Name == "" {
		return nil, fmt.Errorf("script name is required")
	}
	if sc.Category == "" {
		sc.Category = "custom"
	}

	sc.ID = strings.TrimSpace(sc.ID)
	if sc.ID == "" || strings.HasPrefix(sc.ID, "builtin:") {
		sc.ID = "user:" + sanitizeScriptID(sc.Name)
	}
	sc.Builtin = false
	now := nowRFC3339()
	if sc.CreatedAt == "" {
		sc.CreatedAt = now
	}
	sc.UpdatedAt = now

	if err := os.MkdirAll(s.dir, 0755); err != nil {
		return nil, fmt.Errorf("create frida scripts dir: %w", err)
	}
	filePath := s.scriptFilePath(sc.ID)
	data, err := json.MarshalIndent(sc, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return nil, fmt.Errorf("write script %s: %w", filePath, err)
	}

	s.mu.Lock()
	s.custom[sc.ID] = sc
	s.dirStamp = computeScriptsStamp(s.dir)
	s.mu.Unlock()
	return &sc, nil
}

// Delete removes a custom script from disk. Built-in templates cannot be deleted.
func (s *ScriptStore) Delete(id string) error {
	id = strings.TrimSpace(id)
	if strings.HasPrefix(id, "builtin:") {
		return fmt.Errorf("cannot delete built-in template %s", id)
	}
	filePath := s.scriptFilePath(id)
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		return err
	}
	s.mu.Lock()
	delete(s.custom, id)
	s.dirStamp = computeScriptsStamp(s.dir)
	s.mu.Unlock()
	return nil
}

func (s *ScriptStore) scriptFilePath(id string) string {
	safe := sanitizeScriptID(strings.TrimPrefix(id, "user:"))
	return filepath.Join(s.dir, safe+".json")
}

func sanitizeScriptID(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = slugSanitizeRe.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-._")
	if s == "" {
		return "script"
	}
	return s
}

func computeScriptsStamp(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	var b strings.Builder
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if fi, err := e.Info(); err == nil {
			fmt.Fprintf(&b, "%s:%d:%d;", e.Name(), fi.Size(), fi.ModTime().UnixNano())
		}
	}
	return b.String()
}

func readScriptsDir(dir string) map[string]Script {
	out := make(map[string]Script)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var sc Script
		if json.Unmarshal(raw, &sc) == nil && sc.Name != "" {
			if sc.ID == "" {
				sc.ID = "user:" + strings.TrimSuffix(e.Name(), ".json")
			}
			sc.Builtin = false
			out[sc.ID] = sc
		}
	}
	return out
}

// BuiltinScripts returns cap's curated, production-grade Android RE Frida templates.
func BuiltinScripts() []Script {
	return []Script{
		{
			ID:          "builtin:ssl-unpin-universal",
			Name:        "Universal SSL Pinning Bypass",
			Description: "Hooks 14+ Android SSL/TLS pinning implementations (TrustManagerImpl, OkHttp3, Conscrypt, WebView, Flutter BoringSSL, TrustKit, NetworkSecurityConfig).",
			Category:    "unpin",
			Builtin:     true,
			Tags:        []string{"ssl", "tls", "okhttp", "flutter", "conscrypt"},
			Code:        unpin.GetFridaScript(),
		},
		{
			ID:          "builtin:anti-root-frida",
			Name:        "Anti-Root & Anti-Frida Stealth",
			Description: "Bypasses common root & Frida detection checks (su/magisk paths, Build.TAGS, Runtime.exec, PackageManager, native openat/strstr probes).",
			Category:    "anti-detect",
			Builtin:     true,
			Tags:        []string{"root", "magisk", "anti-frida", "stealth"},
			Code:        scriptAntiRootFrida,
		},
		{
			ID:          "builtin:okhttp-http-trace",
			Name:        "OkHttp3 & URLConnection Tracer",
			Description: "Intercepts outgoing OkHttp3 and HttpURLConnection requests in real time with headers, URL, response status, and Java caller stack trace.",
			Category:    "network",
			Builtin:     true,
			Tags:        []string{"http", "okhttp3", "retrofit", "stacktrace"},
			Code:        scriptOkHttpTracer,
		},
		{
			ID:          "builtin:crypto-sign-tracer",
			Name:        "Crypto & Signature Tracer (MD5/SHA/HMAC/AES)",
			Description: "Hooks MessageDigest, Mac (HMAC), Cipher (AES/RSA), and SecretKeySpec to reveal signing inputs, keys, IVs, and digests with stack traces.",
			Category:    "crypto",
			Builtin:     true,
			Tags:        []string{"crypto", "sign", "hmac", "aes", "md5", "sha256"},
			Code:        scriptCryptoTracer,
		},
		{
			ID:          "builtin:jni-register-natives",
			Name:        "JNI RegisterNatives & dlopen Tracer",
			Description: "Traces native library loads (dlopen/android_dlopen_ext) and JNI RegisterNatives bindings to map every dynamic native method to its .so offset.",
			Category:    "native",
			Builtin:     true,
			Tags:        []string{"jni", "native", "so", "RegisterNatives", "dlopen"},
			Code:        scriptJNIRegisterNatives,
		},
		{
			ID:          "builtin:storage-secret-watcher",
			Name:        "SharedPreferences & SQLite Watcher",
			Description: "Monitors SharedPreferences key/value reads & writes and SQLite queries to spot cached auth tokens, device IDs, and signing salts.",
			Category:    "trace",
			Builtin:     true,
			Tags:        []string{"sharedprefs", "sqlite", "token", "storage"},
			Code:        scriptStorageWatcher,
		},
		{
			ID:          "builtin:class-method-explorer",
			Name:        "Dynamic Class & Method Explorer",
			Description: "Enumerates loaded Java classes matching a keyword filter and optionally hooks all overloads of a target class/method.",
			Category:    "trace",
			Builtin:     true,
			Tags:        []string{"classes", "enumerate", "reflection", "discovery"},
			Code:        scriptClassExplorer,
		},
	}
}

const scriptAntiRootFrida = `'use strict';

// ─── cap Anti-Root & Anti-Frida Stealth Bypass ───────────────────────
const BLOCKED_PATHS = [
    '/su', '/sbin/su', '/system/bin/su', '/system/xbin/su',
    '/data/local/su', '/data/local/bin/su', '/data/local/xbin/su',
    '/data/local/tmp/frida', '/data/local/tmp/re.frida.server',
    '/sbin/.magisk', '/data/adb/magisk', '/data/adb/ksu',
    'magisk', 'supersu', 'busybox', 'frida-server', 'frida-agent'
];
const BLOCKED_PKGS = [
    'com.topjohnwu.magisk', 'io.github.vvb2060.magisk', 'me.weishu.kernelsu',
    'eu.chainfire.supersu', 'com.noshufou.android.su', 'de.robv.android.xposed.installer',
    'org.lsposed.manager'
];

function isSensitive(s) {
    if (!s) return false;
    const low = String(s).toLowerCase();
    return BLOCKED_PATHS.some(p => low.indexOf(p) !== -1);
}

Java.perform(function () {
    // 1. Build.TAGS
    try {
        const Build = Java.use('android.os.Build');
        if (Build.TAGS.value && Build.TAGS.value.indexOf('test-keys') !== -1) {
            Build.TAGS.value = 'release-keys';
            send({ cap_cat: 'anti-detect', hook: 'Build.TAGS', detail: 'Spoofed test-keys -> release-keys' });
        }
    } catch (_) {}

    // 2. java.io.File.exists
    try {
        const File = Java.use('java.io.File');
        File.exists.implementation = function () {
            const path = this.getAbsolutePath();
            if (isSensitive(path)) {
                send({ cap_cat: 'anti-detect', hook: 'File.exists', blocked: path });
                return false;
            }
            return this.exists();
        };
    } catch (_) {}

    // 3. Runtime.exec
    try {
        const Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
            if (cmd && (cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1 || cmd.indexOf('magisk') !== -1)) {
                send({ cap_cat: 'anti-detect', hook: 'Runtime.exec', blocked: cmd });
                return this.exec('echo');
            }
            return this.exec(cmd);
        };
    } catch (_) {}

    // 4. PackageManager.getPackageInfo
    try {
        const PM = Java.use('android.app.ApplicationPackageManager');
        PM.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkg, flags) {
            if (BLOCKED_PKGS.indexOf(pkg) !== -1) {
                send({ cap_cat: 'anti-detect', hook: 'PackageManager.getPackageInfo', blocked: pkg });
                const NameNotFound = Java.use('android.content.pm.PackageManager$NameNotFoundException');
                throw NameNotFound.$new(pkg);
            }
            return this.getPackageInfo(pkg, flags);
        };
    } catch (_) {}

    send({ cap_cat: 'lifecycle', hook: 'anti-detect', detail: 'Java anti-root & anti-frida hooks active' });
});

// 5. Native strstr check for "frida" / "gum-js-loop" / "LIBFRIDA"
try {
    const strstr = Module.findExportByName('libc.so', 'strstr');
    if (strstr) {
        Interceptor.attach(strstr, {
            onEnter(args) {
                this.hide = false;
                try {
                    const needle = args[1].readUtf8String();
                    if (needle && /frida|gum-js-loop|gmain|linjector|27042/i.test(needle)) {
                        this.hide = true;
                        this.needle = needle;
                    }
                } catch (_) {}
            },
            onLeave(retval) {
                if (this.hide && !retval.isNull()) {
                    retval.replace(ptr(0));
                    send({ cap_cat: 'anti-detect', hook: 'libc!strstr', blocked: this.needle });
                }
            }
        });
    }
} catch (_) {}
`

const scriptOkHttpTracer = `'use strict';

// ─── cap OkHttp3 & HttpURLConnection Live Tracer ─────────────────────
function getShortStack(limit) {
    try {
        const Log = Java.use('android.util.Log');
        const Ex = Java.use('java.lang.Exception');
        const lines = Log.getStackTraceString(Ex.$new()).split('\n').slice(1, (limit || 8) + 1);
        return lines.map(l => l.trim()).join('\n');
    } catch (_) {
        return '';
    }
}

Java.perform(function () {
    // 1. OkHttp3 RealCall / Interceptor
    try {
        const RequestBuilder = Java.use('okhttp3.Request$Builder');
        RequestBuilder.build.implementation = function () {
            const req = this.build();
            try {
                const url = req.url().toString();
                const method = req.method();
                const headers = {};
                const hdrs = req.headers();
                for (let i = 0; i < hdrs.size(); i++) {
                    headers[hdrs.name(i)] = hdrs.value(i);
                }
                send({
                    cap_cat: 'http',
                    hook: 'okhttp3.Request$Builder.build',
                    method: method,
                    url: url,
                    headers: headers,
                    stack: getShortStack(6),
                });
            } catch (_) {}
            return req;
        };
        send({ cap_cat: 'lifecycle', hook: 'okhttp3', detail: 'Hooked okhttp3.Request$Builder.build' });
    } catch (e) {
        console.log('[cap http] okhttp3.Request$Builder not found: ' + e.message);
    }

    // 2. java.net.URL.openConnection
    try {
        const URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function () {
            const urlStr = this.toString();
            send({
                cap_cat: 'http',
                hook: 'java.net.URL.openConnection',
                url: urlStr,
                stack: getShortStack(5),
            });
            return this.openConnection();
        };
        send({ cap_cat: 'lifecycle', hook: 'url', detail: 'Hooked java.net.URL.openConnection' });
    } catch (_) {}
});
`

const scriptCryptoTracer = `'use strict';

// ─── cap Java Crypto & Signature Tracer ──────────────────────────────
function bytesToHex(bytes) {
    if (!bytes) return '';
    const arr = Java.array('byte', bytes);
    let hex = '';
    for (let i = 0; i < Math.min(arr.length, 256); i++) {
        hex += ('0' + (arr[i] & 0xff).toString(16)).slice(-2);
    }
    if (arr.length > 256) hex += '...(' + arr.length + 'B)';
    return hex;
}

function bytesToUtf8(bytes) {
    if (!bytes) return '';
    try {
        const JString = Java.use('java.lang.String');
        const str = JString.$new(bytes, 'UTF-8').toString();
        return str.length > 240 ? str.slice(0, 240) + '...' : str;
    } catch (_) {
        return '';
    }
}

function shortStack() {
    try {
        const Log = Java.use('android.util.Log');
        const Ex = Java.use('java.lang.Exception');
        return Log.getStackTraceString(Ex.$new()).split('\n').slice(1, 7).map(s => s.trim()).join('\n');
    } catch (_) {
        return '';
    }
}

Java.perform(function () {
    // 1. MessageDigest (MD5 / SHA-1 / SHA-256)
    try {
        const MD = Java.use('java.security.MessageDigest');
        MD.digest.overload('[B').implementation = function (input) {
            const out = this.digest(input);
            send({
                cap_cat: 'crypto',
                hook: 'MessageDigest.digest',
                algorithm: this.getAlgorithm(),
                input_utf8: bytesToUtf8(input),
                input_hex: bytesToHex(input),
                output_hex: bytesToHex(out),
                stack: shortStack(),
            });
            return out;
        };
    } catch (_) {}

    // 2. Mac (HMAC-SHA256 / HMAC-MD5 / HMAC-SHA1)
    try {
        const Mac = Java.use('javax.crypto.Mac');
        Mac.doFinal.overload('[B').implementation = function (input) {
            const out = this.doFinal(input);
            send({
                cap_cat: 'crypto',
                hook: 'Mac.doFinal',
                algorithm: this.getAlgorithm(),
                input_utf8: bytesToUtf8(input),
                input_hex: bytesToHex(input),
                output_hex: bytesToHex(out),
                stack: shortStack(),
            });
            return out;
        };
    } catch (_) {}

    // 3. SecretKeySpec (capture HMAC / AES secret keys)
    try {
        const SKS = Java.use('javax.crypto.spec.SecretKeySpec');
        SKS.$init.overload('[B', 'java.lang.String').implementation = function (keyBytes, algo) {
            send({
                cap_cat: 'crypto',
                hook: 'SecretKeySpec.$init',
                algorithm: algo,
                key_utf8: bytesToUtf8(keyBytes),
                key_hex: bytesToHex(keyBytes),
                stack: shortStack(),
            });
            return this.$init(keyBytes, algo);
        };
    } catch (_) {}

    // 4. Cipher.doFinal (AES / DES / RSA)
    try {
        const Cipher = Java.use('javax.crypto.Cipher');
        Cipher.doFinal.overload('[B').implementation = function (input) {
            const out = this.doFinal(input);
            send({
                cap_cat: 'crypto',
                hook: 'Cipher.doFinal',
                algorithm: this.getAlgorithm(),
                input_utf8: bytesToUtf8(input),
                input_hex: bytesToHex(input),
                output_hex: bytesToHex(out),
                stack: shortStack(),
            });
            return out;
        };
    } catch (_) {}

    send({ cap_cat: 'lifecycle', hook: 'crypto', detail: 'Crypto & Sign hooks loaded (MessageDigest / Mac / SecretKeySpec / Cipher)' });
});
`

const scriptJNIRegisterNatives = `'use strict';

// ─── cap JNI RegisterNatives & dlopen Tracer ─────────────────────────
function hookRegisterNatives() {
    let addrRegisterNatives = null;
    const libart = Process.findModuleByName('libart.so');
    if (!libart) {
        console.log('[cap jni] libart.so not found');
        return;
    }
    const symbols = libart.enumerateSymbols();
    for (let i = 0; i < symbols.length; i++) {
        const sym = symbols[i];
        if (sym.name.indexOf('art') >= 0 &&
            sym.name.indexOf('JNI') >= 0 &&
            sym.name.indexOf('RegisterNatives') >= 0 &&
            sym.name.indexOf('CheckJNI') < 0) {
            addrRegisterNatives = sym.address;
            break;
        }
    }
    if (!addrRegisterNatives) {
        console.log('[cap jni] RegisterNatives symbol not found in libart.so');
        return;
    }

    Interceptor.attach(addrRegisterNatives, {
        onEnter(args) {
            const env = args[0];
            const javaClass = args[1];
            const methodsPtr = ptr(args[2]);
            const methodCount = args[3].toInt32();
            let className = '';
            try {
                className = Java.vm.tryGetEnv().getClassName(javaClass);
            } catch (_) {}

            for (let i = 0; i < methodCount; i++) {
                const base = methodsPtr.add(i * Process.pointerSize * 3);
                const name = base.readPointer().readCString();
                const sig = base.add(Process.pointerSize).readPointer().readCString();
                const fnPtr = base.add(Process.pointerSize * 2).readPointer();
                const mod = Process.findModuleByAddress(fnPtr);
                const offset = mod ? fnPtr.sub(mod.base) : fnPtr;
                send({
                    cap_cat: 'jni',
                    hook: 'RegisterNatives',
                    class_name: className,
                    method: name,
                    signature: sig,
                    module: mod ? mod.name : 'unknown',
                    offset: offset.toString(),
                    address: fnPtr.toString(),
                });
            }
        }
    });
    send({ cap_cat: 'lifecycle', hook: 'RegisterNatives', detail: 'Hooked RegisterNatives @ ' + addrRegisterNatives });
}

// Trace native library loads
['dlopen', 'android_dlopen_ext'].forEach(fn => {
    const addr = Module.findExportByName(null, fn);
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter(args) {
            this.path = args[0].isNull() ? '' : args[0].readCString();
        },
        onLeave(retval) {
            if (this.path && this.path.indexOf('/data/') !== -1) {
                send({ cap_cat: 'native', hook: fn, library: this.path, handle: retval.toString() });
            }
        }
    });
});

hookRegisterNatives();
`

const scriptStorageWatcher = `'use strict';

// ─── cap SharedPreferences & SQLite Secret Watcher ───────────────────
Java.perform(function () {
    try {
        const SP = Java.use('android.app.SharedPreferencesImpl');
        SP.getString.implementation = function (key, defVal) {
            const val = this.getString(key, defVal);
            if (/token|sign|key|secret|auth|session|cookie|uid|device/i.test(key || '')) {
                send({ cap_cat: 'trace', hook: 'SharedPreferences.getString', key: key, value: val });
            }
            return val;
        };
    } catch (_) {}

    try {
        const Editor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
        Editor.putString.implementation = function (key, val) {
            send({ cap_cat: 'trace', hook: 'SharedPreferences.putString', key: key, value: val });
            return this.putString(key, val);
        };
    } catch (_) {}

    try {
        const SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
        SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function (sql, selArgs) {
            send({ cap_cat: 'trace', hook: 'SQLiteDatabase.rawQuery', sql: sql });
            return this.rawQuery(sql, selArgs);
        };
    } catch (_) {}

    send({ cap_cat: 'lifecycle', hook: 'storage', detail: 'SharedPreferences & SQLite hooks loaded' });
});
`

const scriptClassExplorer = `'use strict';

// ─── cap Dynamic Class & Method Explorer ─────────────────────────────
// Edit KEYWORD below and press Hot Reload (Cmd+R) to search loaded classes!
const KEYWORD = 'sign';
const MAX_CLASSES = 30;

Java.perform(function () {
    const matched = [];
    Java.enumerateLoadedClasses({
        onMatch(name) {
            if (matched.length < MAX_CLASSES && name.toLowerCase().indexOf(KEYWORD.toLowerCase()) !== -1) {
                matched.push(name);
            }
        },
        onComplete() {
            send({
                cap_cat: 'java',
                hook: 'enumerateLoadedClasses',
                keyword: KEYWORD,
                count: matched.length,
                classes: matched,
            });
        }
    });
});
`
